"""FastAPI web entry point for the offline mTLS chain doctor."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .diagnostics import (
    ALLOWED_SIGNATURE_LABEL,
    DiagnosticInputError,
    diagnose,
    parse_pem_bundle,
)

BASE_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = BASE_DIR / "examples"

app = FastAPI(
    title="mTLS 证书链离线诊断",
    description="内网 mTLS 客户端证书链排障：区分中间证书缺失与交叉签发选链错误",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def _read_upload(f: UploadFile | None) -> bytes:
    if f is None:
        return b""
    return f.file.read()


def _run_diagnosis(
    leaf_bytes: bytes,
    intermediates_bytes: bytes,
    root_bytes: bytes,
    when: dt.datetime,
):
    leaf_certs = parse_pem_bundle(leaf_bytes)
    root_certs = parse_pem_bundle(root_bytes)
    intermediates = (
        parse_pem_bundle(intermediates_bytes) if intermediates_bytes.strip() else []
    )
    return diagnose(leaf_certs, intermediates, root_certs, when)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    examples = sorted(
        p.name
        for p in EXAMPLES_DIR.iterdir()
        if p.is_dir() and (p / "manifest.json").exists()
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "examples": examples,
            "default_time": dt.datetime.now(dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            "sig_policy": ALLOWED_SIGNATURE_LABEL,
        },
    )


def _parse_when(raw: str) -> dt.datetime:
    text = raw.strip()
    if not text:
        return dt.datetime.now(dt.timezone.utc)
    when = dt.datetime.fromisoformat(text)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.astimezone(dt.timezone.utc)


@app.post("/diagnose", response_class=HTMLResponse)
async def diagnose_html(
    request: Request,
    leaf: UploadFile | None = File(default=None),
    intermediates: UploadFile | None = File(default=None),
    root: UploadFile | None = File(default=None),
    validation_time: str = Form(default=""),
):
    try:
        when = _parse_when(validation_time)
        result = _run_diagnosis(
            _read_upload(leaf),
            _read_upload(intermediates),
            _read_upload(root),
            when,
        )
    except (DiagnosticInputError, ValueError) as exc:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "error": str(exc),
                "examples": sorted(
                    p.name
                    for p in EXAMPLES_DIR.iterdir()
                    if p.is_dir() and (p / "manifest.json").exists()
                ),
                "default_time": validation_time,
                "sig_policy": ALLOWED_SIGNATURE_LABEL,
            },
            status_code=400,
        )
    return templates.TemplateResponse(
        request,
        "result.html",
        {"r": result, "r_dict": result.to_dict()},
    )


@app.post("/api/diagnose")
async def diagnose_api(
    leaf: UploadFile | None = File(default=None),
    intermediates: UploadFile | None = File(default=None),
    root: UploadFile | None = File(default=None),
    validation_time: str = Form(default=""),
):
    try:
        when = _parse_when(validation_time)
        result = _run_diagnosis(
            _read_upload(leaf),
            _read_upload(intermediates),
            _read_upload(root),
            when,
        )
    except (DiagnosticInputError, ValueError) as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(result.to_dict())


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
