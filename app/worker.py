"""One-shot diagnostic worker.

This module is executed as an *independent subprocess* by the web service
(``python -I app/worker.py``). All CPU-bound work -- PEM parsing, graph
construction, signature verification and path enumeration -- happens here so
the web event loop is never blocked by a diagnosis.

Line-delimited JSON protocol on stdin/stdout::

    request  (one JSON object + "\\n"):
        {"leaf": "<base64 pem>", "intermediates": "<base64 pem>",
         "root": "<base64 pem>", "validation_time": "<iso8601>"}
    response (one JSON object + "\\n"):
        {"ok": true,  "result": <DiagnosticResult.to_dict()>}
        {"ok": false, "error": "<message>", "input_error": true|false}

The worker exits after answering exactly one request; the parent reaps it and
only then releases the compute slot.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # executed as ``python -I app/worker.py``
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from diagnostics import DiagnosticInputError, diagnose, parse_pem_bundle
else:  # normal package import (tests, tooling)
    from .diagnostics import DiagnosticInputError, diagnose, parse_pem_bundle


def _b64_decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def handle_request(payload: dict) -> dict:
    """Run one diagnosis. Never raises -- failures become an ``ok=false`` row."""
    try:
        leaf_bytes = _b64_decode(payload["leaf"])
        root_bytes = _b64_decode(payload["root"])
        intermediates_bytes = _b64_decode(payload.get("intermediates", ""))
        when = dt.datetime.fromisoformat(payload["validation_time"])
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        when = when.astimezone(dt.timezone.utc)

        leaf_certs = parse_pem_bundle(leaf_bytes)
        root_certs = parse_pem_bundle(root_bytes)
        intermediates = (
            parse_pem_bundle(intermediates_bytes)
            if intermediates_bytes.strip()
            else []
        )
        result = diagnose(leaf_certs, intermediates, root_certs, when)
        return {"ok": True, "result": result.to_dict()}
    except (DiagnosticInputError, ValueError) as exc:
        # Bad user input maps to HTTP 400 in the parent.
        return {"ok": False, "error": str(exc), "input_error": True}
    except Exception as exc:  # noqa: BLE001 - worker must report, not crash silently
        return {"ok": False, "error": f"诊断进程内部错误：{exc}", "input_error": False}


def main() -> int:
    # A single line on stdin; framing is done by the parent process.
    raw = sys.stdin.buffer.readline()
    if not raw:
        return 1
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        response = {
            "ok": False,
            "error": f"诊断进程收到无法解析的请求：{exc}",
            "input_error": False,
        }
    else:
        response = handle_request(payload)
    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
