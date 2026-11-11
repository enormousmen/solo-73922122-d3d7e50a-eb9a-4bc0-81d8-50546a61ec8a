"""Subprocess-backed diagnosis runner with a bounded compute pool.

Concurrency contract (deliberately strict):

* The web service runs a **single process / single event loop**.
* At most :data:`MAX_CONCURRENT_COMPUTATIONS` diagnoses may compute at once.
  There is **no waiting queue**: when every slot is taken the request is
  refused immediately with HTTP 503.
* A diagnosis that has not finished :data:`COMPUTE_TIMEOUT_SECONDS` after
  acquiring its slot is aborted and reported as HTTP 504.
* If the client disconnects, its computation is aborted as well -- cancelling
  the awaiting coroutine alone is not enough, the child process is terminated.
* On timeout, disconnect or abnormal child exit the process is reaped and its
  pipes are closed, and the compute slot is released only *after* the process
  has actually exited.

The CPU-bound PEM parsing and chain analysis live in :mod:`app.worker`, which
runs as an independent subprocess; this module only performs non-blocking IO
and bookkeeping on the event loop.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import sys
from pathlib import Path
from typing import Awaitable, Callable, Optional

MAX_CONCURRENT_COMPUTATIONS = 2
COMPUTE_TIMEOUT_SECONDS = 3.0

# Project root (the package parent) used as the child's working directory; the
# worker is launched by absolute path with ``-I`` so it is cwd-independent.
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)


class ComputeCapacityError(Exception):
    """All compute slots are occupied. Maps to HTTP 503."""


class ComputeTimeoutError(Exception):
    """The worker did not finish within the compute deadline. Maps to 504."""


class ComputeAbortedError(Exception):
    """The client went away while the computation was running."""


class WorkerFailureError(Exception):
    """The worker process exited abnormally or produced no usable answer."""


class ComputeSlotPool:
    """Semaphore-like pool that refuses instead of queuing."""

    def __init__(self, capacity: int = MAX_CONCURRENT_COMPUTATIONS) -> None:
        self._capacity = capacity
        self._in_use = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def in_use(self) -> int:
        return self._in_use

    @property
    def available(self) -> int:
        return self._capacity - self._in_use

    def try_acquire(self) -> bool:
        """Take a slot immediately. Returns ``False`` when saturated."""
        if self._in_use >= self._capacity:
            return False
        self._in_use += 1
        return True

    def release(self) -> None:
        if self._in_use <= 0:  # pragma: no cover - defensive bookkeeping
            raise RuntimeError("compute slot released without being held")
        self._in_use -= 1

    @contextlib.asynccontextmanager
    async def slot(self):
        if not self.try_acquire():
            raise ComputeCapacityError("computing capacity exhausted")
        try:
            yield
        finally:
            self.release()


# Shared pool for the whole web process.
pool = ComputeSlotPool()


def _worker_command() -> list[str]:
    # ``-I`` (isolated) keeps the child free of PYTHONPATH/user-site leakage;
    # worker.py re-adds its own package directory defensively.
    return [sys.executable, "-I", str(Path(__file__).resolve().parent / "worker.py")]


async def _spawn_worker() -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        *_worker_command(),
        cwd=_PROJECT_ROOT,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )


async def _terminate_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Stop the worker and block until it has actually exited.

    A well-behaved one-shot worker exits on its own after answering, in which
    case we only wait for it. Otherwise we first close its stdin (cooperative
    shutdown: the worker treats EOF as "cancel and exit") and then send
    SIGTERM, escalating to SIGKILL when the process ignores the signal. On
    hardened runtimes where signals to child processes are denied the
    permission error is swallowed while we keep waiting on the process
    object. The slot is released by the caller only after this returns.
    """
    if proc.returncode is None:
        if proc.stdin is not None and not proc.stdin.is_closing():
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            try:
                proc.terminate()
            except (PermissionError, ProcessLookupError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    proc.kill()
                with contextlib.suppress(asyncio.TimeoutError):
                    await proc.wait()
        except ProcessLookupError:
            pass
    if proc.stdin is not None and not proc.stdin.is_closing():
        proc.stdin.close()


async def _read_worker_response(
    proc: asyncio.subprocess.Process,
) -> dict:
    assert proc.stdout is not None
    raw = await proc.stdout.readline()
    if proc.returncode is not None and not raw:
        raise WorkerFailureError(f"诊断进程异常退出（退出码 {proc.returncode}）")
    if not raw:
        raise WorkerFailureError("诊断进程关闭了输出且未返回结果")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerFailureError(f"诊断进程返回了无法解析的结果：{exc}") from exc


def _build_request(
    leaf_bytes: bytes,
    intermediates_bytes: bytes,
    root_bytes: bytes,
    validation_time_iso: str,
) -> bytes:
    payload = {
        "leaf": base64.b64encode(leaf_bytes).decode("ascii"),
        "intermediates": base64.b64encode(intermediates_bytes).decode("ascii"),
        "root": base64.b64encode(root_bytes).decode("ascii"),
        "validation_time": validation_time_iso,
    }
    return (json.dumps(payload) + "\n").encode("utf-8")


async def run_diagnosis(
    leaf_bytes: bytes,
    intermediates_bytes: bytes,
    root_bytes: bytes,
    validation_time_iso: str,
    *,
    is_disconnected: Optional[Callable[[], Awaitable[bool]]] = None,
    timeout: Optional[float] = None,
) -> dict:
    """Run one diagnosis in a dedicated worker subprocess.

    Returns the serialised :class:`~app.diagnostics.DiagnosticResult` dict.

    Raises:
        ComputeCapacityError: no slot available right now (HTTP 503).
        ComputeTimeoutError: slot held longer than ``timeout`` (HTTP 504).
        ComputeAbortedError: the client disconnected mid-computation.
        WorkerFailureError: the child died or returned garbage (HTTP 502).
        ValueError: user input rejected by the worker (HTTP 400).
    """
    if not pool.try_acquire():
        raise ComputeCapacityError(
            f"已有 {pool.capacity} 份证书包正在计算，请稍后重试。"
        )

    # Resolve the deadline inside the body so operational/tests overrides of
    # runner.COMPUTE_TIMEOUT_SECONDS take effect without touching call sites.
    if timeout is None:
        timeout = COMPUTE_TIMEOUT_SECONDS

    proc: Optional[asyncio.subprocess.Process] = None
    try:
        try:
            proc = await _spawn_worker()
        except OSError as exc:
            raise WorkerFailureError(f"无法启动诊断子进程：{exc}") from exc
        assert proc.stdin is not None and proc.stdout is not None
        try:
            proc.stdin.write(
                _build_request(
                    leaf_bytes, intermediates_bytes, root_bytes, validation_time_iso
                )
            )
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise WorkerFailureError("诊断进程在接收请求前已退出。") from exc
        # Keep stdin open while the worker computes. Closing it is reserved
        # for the reap path (timeout / disconnect / crash), where EOF acts as
        # a cooperative cancellation signal in addition to OS signals.

        read_task = asyncio.create_task(_read_worker_response(proc))
        timeout_task = asyncio.create_task(asyncio.sleep(timeout))
        watcher_task = None
        if is_disconnected is not None:
            watcher_task = asyncio.create_task(
                _wait_for_disconnect(is_disconnected)
            )

        pending = {read_task, timeout_task}
        if watcher_task is not None:
            pending.add(watcher_task)
        try:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
        except asyncio.CancelledError:
            # The surrounding request task was cancelled (e.g. server shutdown
            # or client drop propagated by the framework): treat as abort.
            for task in pending:
                task.cancel()
            await _terminate_and_reap(proc)
            raise

        for task in pending:
            task.cancel()
        # Drain cancellations so no "task was destroyed pending" warnings and
        # no half-finished IO lingers.
        await asyncio.gather(*pending, return_exceptions=True)

        if read_task in done:
            response = read_task.result()  # may raise WorkerFailureError
        elif timeout_task in done:
            await _terminate_and_reap(proc)
            proc = None
            raise ComputeTimeoutError(
                f"诊断超过 {timeout:g} 秒未完成，已终止计算进程。"
            )
        else:  # disconnect watcher fired
            await _terminate_and_reap(proc)
            proc = None
            raise ComputeAbortedError("客户端已断开，诊断计算已停止。")
    finally:
        # Normal completion path: make sure the one-shot worker has exited and
        # close its pipes before handing the slot back. On abort paths the
        # process was already reaped and ``proc`` was set to None.
        if proc is not None:
            await _terminate_and_reap(proc)
        pool.release()

    if not response.get("ok"):
        message = response.get("error") or "诊断进程返回了未知错误"
        if response.get("input_error"):
            raise ValueError(message)
        raise WorkerFailureError(message)
    return response["result"]


async def _wait_for_disconnect(
    is_disconnected: Callable[[], Awaitable[bool]],
) -> None:
    """Resolve once the supplied predicate reports a dropped client.

    Polled far more often than the compute deadline so a disconnect aborts
    the worker promptly instead of waiting for the 3-second timeout.
    """
    while True:
        if await is_disconnected():
            return
        await asyncio.sleep(0.02)
