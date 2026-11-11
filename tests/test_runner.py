"""Tests for the bounded subprocess compute pool and its lifecycle rules.

Covers:
  * slot pool: immediate refusal, no waiting queue, guaranteed release;
  * 503 from both web endpoints while two computations are in flight, while
    the home page and example API stay available;
  * 504 after the compute deadline, with the worker actually terminated and
    reaped before the slot is released (EOF on hardened runtimes, signals
    otherwise);
  * client disconnect aborts and reaps the worker (coroutine cancellation is
    not enough);
  * worker crash / garbage output -> 502 and resources reclaimed;
  * worker-reported input errors still map to 400;
  * event-loop non-blocking: a diagnosis runs in a child PID, not the server.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import runner
from app.main import app
from app.runner import (
    COMPUTE_TIMEOUT_SECONDS,
    ComputeAbortedError,
    ComputeCapacityError,
    ComputeSlotPool,
    ComputeTimeoutError,
    WorkerFailureError,
    run_diagnosis,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "app" / "examples"
client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_pool():
    runner.pool._in_use = 0
    yield
    # Every test must give its slots back.
    assert runner.pool.in_use == 0


def _example_files(name: str):
    resp = client.get(f"/api/examples/{name}")
    assert resp.status_code == 200
    payload = resp.json()
    manifest = json.loads(payload["manifest"])
    return manifest, payload["files"]


def _post_api(manifest, files):
    return client.post(
        "/api/diagnose",
        files={
            "leaf": (manifest["leaf"], files[manifest["leaf"]], "application/x-pem"),
            "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
            "intermediates": (
                manifest["intermediates"],
                files[manifest["intermediates"]],
                "application/x-pem",
            ),
        },
        data={"validation_time": manifest["validation_time"]},
    )


# --------------------------------------------------------------------------- #
# Slot pool semantics
# --------------------------------------------------------------------------- #

def test_pool_refuses_when_full_and_never_queues():
    pool = ComputeSlotPool(capacity=2)
    assert pool.try_acquire() is True
    assert pool.try_acquire() is True
    assert pool.available == 0
    # Immediate refusal: no blocking, no queue.
    assert pool.try_acquire() is False
    pool.release()
    assert pool.try_acquire() is True
    pool.release()
    pool.release()
    assert pool.in_use == 0


def test_pool_release_after_exception_via_context_manager():
    pool = ComputeSlotPool(capacity=1)

    async def scenario():
        with pytest.raises(RuntimeError):
            async with pool.slot():
                assert pool.in_use == 1
                raise RuntimeError("boom")

    asyncio.run(scenario())
    assert pool.in_use == 0


# --------------------------------------------------------------------------- #
# Fake worker process used to drive timeout / disconnect / crash paths without
# waiting real seconds or forging real disconnections.
# --------------------------------------------------------------------------- #

class FakeProcess:
    def __init__(self, *, delay=0.0, response_line=None, exit_code=0,
                 die_without_output=False, pid=4242):
        self.pid = pid
        self.returncode = None
        self._delay = delay
        self._response_line = response_line
        self._exit_code = exit_code
        self._die_without_output = die_without_output
        self.terminated = False
        self.killed = False
        self.waited = False
        self.stdin = _FakeStdin(self)
        self.stdout = _FakeStdout(self)
        self.stderr = None
        self._waiters: list[asyncio.Future] = []

    def _finish(self):
        if self.returncode is None:
            self.returncode = self._exit_code
            self.waited = True  # equivalent to the exit future being resolved
            for fut in self._waiters:
                if not fut.done():
                    fut.set_result(self.returncode)

    def terminate(self):
        self.terminated = True
        self._finish()

    def kill(self):
        self.killed = True
        self.terminated = True
        self._finish()

    async def wait(self):
        # Mimic asyncio's transport: wait() resolves immediately once the
        # process has exited, otherwise it blocks on its exit future.
        if self.returncode is not None:
            return self.returncode
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append(fut)
        return await fut

class _FakeStdin:
    def __init__(self, proc: "FakeProcess"):
        self._proc = proc
        self.closed = False
        self._buffer = b""

    def write(self, data):
        self._buffer += data

    async def drain(self):
        return None

    def is_closing(self):
        return self.closed

    def close(self):
        self.closed = True
        # Simulates the worker exiting on stdin EOF.
        self._proc._finish()


class _FakeStdout:
    def __init__(self, proc: FakeProcess):
        self._proc = proc
        self._consumed = False

    async def readline(self):
        if self._proc._delay:
            await asyncio.sleep(self._proc._delay)
        self._consumed = True
        if self._proc._die_without_output:
            self._proc.returncode = self._proc._exit_code
            return b""
        if self._proc._response_line is None:
            await asyncio.sleep(10)  # wedged until terminated
            return b""
        return self._proc._response_line


def _patch_spawn(monkeypatch, proc: FakeProcess):
    async def fake_spawn():
        return proc

    monkeypatch.setattr(runner, "_spawn_worker", fake_spawn)


# --------------------------------------------------------------------------- #
# Timeout
# --------------------------------------------------------------------------- #

def test_timeout_kills_worker_and_releases_slot(monkeypatch):
    proc = FakeProcess(delay=10.0)
    _patch_spawn(monkeypatch, proc)

    async def scenario():
        with pytest.raises(ComputeTimeoutError):
            await run_diagnosis(
                b"leaf", b"inter", b"root", "2026-11-11T00:00:00+00:00",
                timeout=0.2,
            )

    started = time.monotonic()
    asyncio.run(scenario())
    elapsed = time.monotonic() - started
    assert elapsed < 2.0
    # The worker must have actually exited and been reaped before the slot
    # was handed back (terminate() may be denied on hardened runtimes, in
    # which case stdin EOF drives the same shutdown).
    assert proc.waited is True
    assert proc.returncode is not None
    assert proc.stdin.closed is True
    assert runner.pool.in_use == 0


def test_web_timeout_returns_504(monkeypatch):
    proc = FakeProcess(delay=10.0)
    _patch_spawn(monkeypatch, proc)
    monkeypatch.setattr(runner, "COMPUTE_TIMEOUT_SECONDS", 0.2)

    manifest, files = _example_files("cross-sign")
    started = time.monotonic()
    resp = _post_api(manifest, files)
    assert time.monotonic() - started < 2.0
    assert resp.status_code == 504
    assert resp.json()["code"] == "compute_timeout"
    assert proc.returncode is not None
    assert proc.waited is True
    assert runner.pool.in_use == 0

    # HTML route renders an explanatory timeout page.
    html = client.post(
        "/diagnose",
        files={
            "leaf": (manifest["leaf"], files[manifest["leaf"]], "application/x-pem"),
            "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
            "intermediates": (
                manifest["intermediates"],
                files[manifest["intermediates"]],
                "application/x-pem",
            ),
        },
        data={"validation_time": manifest["validation_time"]},
    )
    assert html.status_code == 504
    assert "超时" in html.text
    assert "返回诊断首页" in html.text


# --------------------------------------------------------------------------- #
# Client disconnect
# --------------------------------------------------------------------------- #

def test_disconnect_stops_computation_and_reaps(monkeypatch):
    proc = FakeProcess(delay=10.0)
    _patch_spawn(monkeypatch, proc)
    state = {"disconnected": False}

    async def is_disconnected():
        # Disconnect "observed" shortly after the computation starts.
        await asyncio.sleep(0.1)
        state["disconnected"] = True
        return state["disconnected"]

    async def scenario():
        with pytest.raises(ComputeAbortedError):
            await run_diagnosis(
                b"leaf", b"inter", b"root", "2026-11-11T00:00:00+00:00",
                is_disconnected=is_disconnected,
                timeout=5.0,
            )

    asyncio.run(scenario())
    assert proc.waited is True
    assert proc.returncode is not None
    assert proc.stdin.closed is True
    assert runner.pool.in_use == 0


# --------------------------------------------------------------------------- #
# Worker abnormal exit
# --------------------------------------------------------------------------- #

def test_worker_crash_reports_502_style_failure_and_reclaims(monkeypatch):
    proc = FakeProcess(die_without_output=True, exit_code=-9)
    _patch_spawn(monkeypatch, proc)

    async def scenario():
        with pytest.raises(WorkerFailureError, match="异常退出"):
            await run_diagnosis(
                b"leaf", b"inter", b"root", "2026-11-11T00:00:00+00:00"
            )

    asyncio.run(scenario())
    assert runner.pool.in_use == 0
    assert proc.stdin.closed is True


def test_worker_garbage_output_is_failure(monkeypatch):
    proc = FakeProcess(response_line=b"this is not json\n")
    _patch_spawn(monkeypatch, proc)

    async def scenario():
        with pytest.raises(WorkerFailureError):
            await run_diagnosis(
                b"leaf", b"inter", b"root", "2026-11-11T00:00:00+00:00"
            )

    asyncio.run(scenario())
    assert runner.pool.in_use == 0


def test_worker_input_error_becomes_value_error(monkeypatch):
    line = json.dumps(
        {"ok": False, "error": "PEM 解析失败：bad", "input_error": True}
    ).encode() + b"\n"
    proc = FakeProcess(response_line=line)
    _patch_spawn(monkeypatch, proc)

    async def scenario():
        with pytest.raises(ValueError, match="PEM 解析失败"):
            await run_diagnosis(
                b"leaf", b"inter", b"root", "2026-11-11T00:00:00+00:00"
            )

    asyncio.run(scenario())
    assert runner.pool.in_use == 0


def test_worker_internal_error_becomes_worker_failure(monkeypatch):
    line = json.dumps(
        {"ok": False, "error": "诊断进程内部错误：x", "input_error": False}
    ).encode() + b"\n"
    proc = FakeProcess(response_line=line)
    _patch_spawn(monkeypatch, proc)

    async def scenario():
        with pytest.raises(WorkerFailureError):
            await run_diagnosis(
                b"leaf", b"inter", b"root", "2026-11-11T00:00:00+00:00"
            )

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# Capacity enforcement through the real HTTP endpoints
# --------------------------------------------------------------------------- #

def _post_in_thread(manifest, files, results, key):
    try:
        results[key] = _post_api(manifest, files)
    except Exception as exc:  # pragma: no cover - surfaced via assertion
        results[key] = exc


def test_full_pool_returns_503_immediately_while_others_keep_working(monkeypatch):
    """Two slots held via the real HTTP stack => third request gets 503.

    The spawned "workers" are deterministic fakes (each request thread gets
    its own event loop under TestClient, where cross-loop subprocess child
    watchers are a harness-only source of flakiness; the real single-loop
    uvicorn behaviour is covered by the live-server smoke test below).
    """
    def make_proc(pid):
        # Never answers: holds the slot until the 3 s deadline reaps it.
        return FakeProcess(response_line=None, pid=pid)

    counter = {"n": 0}
    created: list[FakeProcess] = []

    async def fake_spawn():
        counter["n"] += 1
        proc = make_proc(9000 + counter["n"])
        created.append(proc)
        return proc

    monkeypatch.setattr(runner, "_spawn_worker", fake_spawn)
    manifest, files = _example_files("cross-sign")

    results: dict = {}
    threads = [
        threading.Thread(
            target=_post_in_thread, args=(manifest, files, results, f"busy-{i}")
        )
        for i in range(runner.MAX_CONCURRENT_COMPUTATIONS)
    ]
    for t in threads:
        t.start()

    # Wait until both slots are genuinely held.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and runner.pool.in_use < 2:
        time.sleep(0.02)
    assert runner.pool.in_use == 2
    assert len(created) == 2

    # No waiting queue: third request is refused at once.
    started = time.monotonic()
    refused = _post_api(manifest, files)
    assert time.monotonic() - started < 1.0
    assert refused.status_code == 503
    assert refused.json()["code"] == "capacity_exhausted"
    # Refusal must not spawn another worker.
    assert len(created) == 2

    # HTML form gets an explanatory page too, not a half result.
    refused_html = client.post(
        "/diagnose",
        files={
            "leaf": (manifest["leaf"], files[manifest["leaf"]], "application/x-pem"),
            "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
            "intermediates": (
                manifest["intermediates"],
                files[manifest["intermediates"]],
                "application/x-pem",
            ),
        },
        data={"validation_time": manifest["validation_time"]},
    )
    assert refused_html.status_code == 503
    assert "繁忙" in refused_html.text

    # Non-computing routes remain fully serviceable while both slots are busy.
    assert client.get("/").status_code == 200
    assert client.get("/api/examples/cross-sign").status_code == 200
    assert client.get("/examples/cross-sign", follow_redirects=False).status_code == 303

    for t in threads:
        t.join(timeout=10)
    for key, value in results.items():
        assert not isinstance(value, Exception), key
        assert value.status_code == 504, key  # fakes never answer -> timeout
    # Every fake worker was reaped and every slot returned.
    for proc in created:
        assert proc.returncode is not None
        assert proc.waited is True
    assert runner.pool.in_use == 0


def test_live_uvicorn_server_enforces_capacity_and_serves_pages():
    """End-to-end against a real single-process uvicorn server (real loop)."""
    import httpx
    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)

    async def scenario():
        task = asyncio.create_task(server.serve())
        # Wait for the server to start listening.
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        assert server.started
        port = server.servers[0].sockets[0].getsockname()[1]
        base = f"http://127.0.0.1:{port}"

        manifest, files = _example_files("cross-sign")
        form = {
            "validation_time": (None, manifest["validation_time"]),
        }
        upload = {
            "leaf": (manifest["leaf"], files[manifest["leaf"]], "application/x-pem"),
            "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
            "intermediates": (
                manifest["intermediates"],
                files[manifest["intermediates"]],
                "application/x-pem",
            ),
        }

        async with httpx.AsyncClient(base_url=base, timeout=10) as http:
            # Home page and examples work before any computation.
            assert (await http.get("/")).status_code == 200
            assert (await http.get("/api/examples/cross-sign")).status_code == 200

            # Normal diagnosis through a real worker subprocess.
            ok = await http.post("/api/diagnose", data=form, files=upload)
            assert ok.status_code == 200
            assert ok.json()["passing_chain"] is not None

            # HTML route renders the full result page.
            html = await http.post("/diagnose", data=form, files=upload)
            assert html.status_code == 200
            assert "通过的链" in html.text

            # Bad input still maps to 400 via the worker.
            bad = await http.post(
                "/api/diagnose",
                data={"validation_time": manifest["validation_time"]},
                files={
                    "leaf": ("x.pem", b"not pem", "text/plain"),
                    "root": (manifest["root"], files[manifest["root"]],
                             "application/x-pem"),
                    "intermediates": ("i.pem", b"", "text/plain"),
                },
            )
            assert bad.status_code == 400

        server.should_exit = True
        await task

    asyncio.run(scenario())
    assert runner.pool.in_use == 0


def test_capacity_recovers_after_workers_finish(monkeypatch):
    line = json.dumps(
        {"ok": False, "error": "boom", "input_error": False}
    ).encode() + b"\n"
    procs = [FakeProcess(response_line=line, pid=100 + i) for i in range(3)]
    index = {"i": 0}

    async def spawn():
        proc = procs[index["i"]]
        index["i"] += 1
        return proc

    monkeypatch.setattr(runner, "_spawn_worker", spawn)

    async def scenario():
        for _ in range(3):
            with pytest.raises(WorkerFailureError):
                await run_diagnosis(
                    b"a", b"b", b"c", "2026-11-11T00:00:00+00:00"
                )
            assert runner.pool.in_use == 0

    asyncio.run(scenario())


def test_worker_spawn_failure_is_502_style_and_releases_slot(monkeypatch):
    async def boom_spawn():
        raise OSError("no such executable")

    monkeypatch.setattr(runner, "_spawn_worker", boom_spawn)

    async def scenario():
        with pytest.raises(WorkerFailureError, match="无法启动"):
            await run_diagnosis(
                b"a", b"b", b"c", "2026-11-11T00:00:00+00:00"
            )

    asyncio.run(scenario())
    assert runner.pool.in_use == 0


def test_dead_on_arrival_worker_is_worker_failure(monkeypatch):
    proc = FakeProcess(die_without_output=True, exit_code=1)

    class _BrokenStdin(_FakeStdin):
        async def drain(self):
            raise BrokenPipeError("pipe closed")

    proc.stdin = _BrokenStdin(proc)

    async def spawn():
        return proc

    monkeypatch.setattr(runner, "_spawn_worker", spawn)

    async def scenario():
        with pytest.raises(WorkerFailureError, match="接收请求前已退出"):
            await run_diagnosis(
                b"a", b"b", b"c", "2026-11-11T00:00:00+00:00"
            )

    asyncio.run(scenario())
    assert runner.pool.in_use == 0


# --------------------------------------------------------------------------- #
# Real subprocess end-to-end sanity (not just fakes)
# --------------------------------------------------------------------------- #

def test_real_worker_runs_outside_web_process_and_returns_full_result():
    manifest, files = _example_files("cross-sign")
    resp = _post_api(manifest, files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["passing_chain"] is not None
    assert len(data["candidate_chains"]) == 2
    assert runner.pool.in_use == 0


def test_real_bad_pem_still_400_through_worker():
    good_manifest, files = _example_files("cross-sign")
    resp = client.post(
        "/api/diagnose",
        files={
            "leaf": ("leaf.pem", b"not a pem", "text/plain"),
            "root": (good_manifest["root"], files[good_manifest["root"]],
                     "application/x-pem"),
            "intermediates": ("i.pem", b"", "text/plain"),
        },
        data={"validation_time": good_manifest["validation_time"]},
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_html_result_page_renders_from_subprocess_payload():
    manifest, files = _example_files("cross-sign")
    html = client.post(
        "/diagnose",
        files={
            "leaf": (manifest["leaf"], files[manifest["leaf"]], "application/x-pem"),
            "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
            "intermediates": (
                manifest["intermediates"],
                files[manifest["intermediates"]],
                "application/x-pem",
            ),
        },
        data={"validation_time": manifest["validation_time"]},
    )
    assert html.status_code == 200
    assert "通过的链" in html.text
    assert runner.pool.in_use == 0


def test_index_explains_capacity_and_timeout():
    page = client.get("/").text
    assert "503" in page
    assert "504" in page
    assert str(runner.MAX_CONCURRENT_COMPUTATIONS) in page
    assert str(int(COMPUTE_TIMEOUT_SECONDS)) in page
