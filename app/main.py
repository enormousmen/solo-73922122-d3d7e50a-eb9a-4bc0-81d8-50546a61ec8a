"""FastAPI web entry point for the offline mTLS chain doctor.

The web process never performs the CPU-heavy PEM parsing or chain analysis
itself. Every diagnosis is delegated to an independent one-shot worker
subprocess via :mod:`app.runner`, behind a two-slot compute pool:

* saturated pool  -> 503 immediately (no waiting queue);
* > 3 s compute   -> 504, the worker is killed and reaped;
* client disconnect -> the worker is terminated as well;
* worker crash    -> 502, resources reclaimed before the slot is released.

Home page and example loading remain available while both slots are busy.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .diagnostics import ALLOWED_SIGNATURE_LABEL
from .result_adapter import wrap_result
from .runner import (
    COMPUTE_TIMEOUT_SECONDS,
    MAX_CONCURRENT_COMPUTATIONS,
    ComputeAbortedError,
    ComputeCapacityError,
    ComputeTimeoutError,
    WorkerFailureError,
    run_diagnosis,
)

BASE_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = BASE_DIR / "examples"

app = FastAPI(
    title="mTLS 证书链离线诊断",
    description="内网 mTLS 客户端证书链排障：区分中间证书缺失与交叉签发选链错误",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
# Datetimes cross the worker boundary as ISO strings; give templates a filter
# that renders just the calendar date for both datetimes and ISO strings.
templates.env.filters["date_only"] = lambda value: str(value)[:10]


def _read_upload(f: UploadFile | None) -> bytes:
    if f is None:
        return b""
    return f.file.read()


def _list_examples() -> list[str]:
    return sorted(
        p.name
        for p in EXAMPLES_DIR.iterdir()
        if p.is_dir() and (p / "manifest.json").exists()
    )


def _parse_when(raw: str) -> dt.datetime:
    text = raw.strip()
    if not text:
        return dt.datetime.now(dt.timezone.utc)
    when = dt.datetime.fromisoformat(text)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.astimezone(dt.timezone.utc)


async def _is_disconnected(request: Request) -> bool:
    return await request.is_disconnected()


def _display_seconds(value: float) -> str:
    """Render whole-second timeouts without a trailing ``.0``."""
    return str(int(value)) if float(value).is_integer() else str(value)


def _error_page(
    request: Request,
    *,
    status_code: int,
    title: str,
    heading: str,
    message: str,
    hint: str,
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "title": title,
            "heading": heading,
            "message": message,
            "hint": hint,
            "capacity": MAX_CONCURRENT_COMPUTATIONS,
            "timeout_seconds": _display_seconds(COMPUTE_TIMEOUT_SECONDS),
        },
        status_code=status_code,
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "examples": _list_examples(),
            "default_time": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            "sig_policy": ALLOWED_SIGNATURE_LABEL,
            "capacity": MAX_CONCURRENT_COMPUTATIONS,
            "timeout_seconds": _display_seconds(COMPUTE_TIMEOUT_SECONDS),
        },
    )


def _index_with_error(request: Request, message: str, validation_time: str):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "error": message,
            "examples": _list_examples(),
            "default_time": validation_time,
            "sig_policy": ALLOWED_SIGNATURE_LABEL,
            "capacity": MAX_CONCURRENT_COMPUTATIONS,
            "timeout_seconds": _display_seconds(COMPUTE_TIMEOUT_SECONDS),
        },
        status_code=400,
    )


def _collect_inputs(leaf, intermediates, root, validation_time):
    """Read uploads and normalise the validation time.

    The file reads are synchronous (SpooledTemporaryFile), so callers run
    this in a worker thread to keep the event loop free for other requests.
    """
    when = _parse_when(validation_time)
    return (
        _read_upload(leaf),
        _read_upload(intermediates),
        _read_upload(root),
        when.isoformat(),
    )


@app.post("/diagnose", response_class=HTMLResponse)
async def diagnose_html(
    request: Request,
    leaf: UploadFile | None = File(default=None),
    intermediates: UploadFile | None = File(default=None),
    root: UploadFile | None = File(default=None),
    validation_time: str = Form(default=""),
):
    try:
        leaf_b, inter_b, root_b, when_iso = await run_in_threadpool(
            _collect_inputs, leaf, intermediates, root, validation_time
        )
    except ValueError as exc:
        return _index_with_error(request, str(exc), validation_time)

    try:
        result = await run_diagnosis(
            leaf_b,
            inter_b,
            root_b,
            when_iso,
            is_disconnected=lambda: _is_disconnected(request),
        )
    except ValueError as exc:  # worker rejected the user input -> 400
        return _index_with_error(request, str(exc), validation_time)
    except ComputeCapacityError as exc:
        return _error_page(
            request,
            status_code=503,
            title="服务繁忙",
            heading="计算名额已满（503）",
            message=str(exc),
            hint="本服务只允许最多 2 份证书包同时计算，且不设置等待队列。"
            "请稍后重新提交；首页与示例载入不受影响。",
        )
    except ComputeTimeoutError as exc:
        return _error_page(
            request,
            status_code=504,
            title="计算超时",
            heading="诊断计算超时（504）",
            message=str(exc),
            hint="计算进程已被终止并回收。请简化证书包后重试，或稍后再提交。",
        )
    except ComputeAbortedError as exc:
        # Browser already left; a response body is unlikely to be delivered but
        # the status documents the outcome for proxies and logs.
        return _error_page(
            request,
            status_code=504,
            title="计算已中止",
            heading="客户端断开，计算已停止",
            message=str(exc),
            hint="对应的诊断子进程已终止，名额已回收。",
        )
    except WorkerFailureError as exc:
        return _error_page(
            request,
            status_code=502,
            title="诊断进程异常",
            heading="计算进程异常退出（502）",
            message=str(exc),
            hint="进程与通信资源已回收，未产生任何诊断结论；请稍后重试。",
        )

    wrapped = wrap_result(result)
    return templates.TemplateResponse(
        request,
        "result.html",
        {"r": wrapped, "r_dict": result},
    )


@app.post("/api/diagnose")
async def diagnose_api(
    request: Request,
    leaf: UploadFile | None = File(default=None),
    intermediates: UploadFile | None = File(default=None),
    root: UploadFile | None = File(default=None),
    validation_time: str = Form(default=""),
):
    try:
        leaf_b, inter_b, root_b, when_iso = await run_in_threadpool(
            _collect_inputs, leaf, intermediates, root, validation_time
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    try:
        result = await run_diagnosis(
            leaf_b,
            inter_b,
            root_b,
            when_iso,
            is_disconnected=lambda: _is_disconnected(request),
        )
    except ValueError as exc:  # input error reported by the worker
        return JSONResponse({"error": str(exc)}, status_code=400)
    except ComputeCapacityError as exc:
        return JSONResponse(
            {"error": str(exc), "code": "capacity_exhausted"}, status_code=503
        )
    except ComputeTimeoutError as exc:
        return JSONResponse(
            {"error": str(exc), "code": "compute_timeout"}, status_code=504
        )
    except ComputeAbortedError as exc:
        return JSONResponse(
            {"error": str(exc), "code": "client_disconnected"}, status_code=504
        )
    except WorkerFailureError as exc:
        return JSONResponse(
            {"error": str(exc), "code": "worker_failure"}, status_code=502
        )
    return JSONResponse(result)


@app.get("/examples/{name}")
def load_example(name: str):
    """Redirect the browser to a prefilled upload form for a built-in demo."""
    safe = Path(name).name  # strip any path components
    manifest = EXAMPLES_DIR / safe / "manifest.json"
    if not manifest.exists():
        return JSONResponse({"error": f"示例 {name} 不存在"}, status_code=404)
    return RedirectResponse(url=f"/?example={safe}", status_code=303)


@app.get("/api/examples/{name}")
def example_payload(name: str):
    safe = Path(name).name
    directory = EXAMPLES_DIR / safe
    manifest = directory / "manifest.json"
    if not manifest.exists():
        return JSONResponse({"error": f"示例 {name} 不存在"}, status_code=404)
    payload = {"manifest": manifest.read_text(encoding="utf-8"), "files": {}}
    for pem in sorted(directory.glob("*.pem")):
        payload["files"][pem.name] = pem.read_text(encoding="utf-8")
    return JSONResponse(payload)
