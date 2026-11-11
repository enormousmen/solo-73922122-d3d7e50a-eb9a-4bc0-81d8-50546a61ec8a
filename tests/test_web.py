"""Web/API integration tests using FastAPI's TestClient."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

EXAMPLES = Path(__file__).resolve().parent.parent / "app" / "examples"
client = TestClient(app)


def _load_example(name: str):
    resp = client.get(f"/api/examples/{name}")
    assert resp.status_code == 200
    payload = resp.json()
    manifest = json.loads(payload["manifest"])
    return manifest, payload["files"]


def _post(manifest, files):
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


def test_index_renders():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "mTLS" in resp.text
    assert "cross-sign" in resp.text


def test_cross_sign_example_end_to_end():
    manifest, files = _load_example("cross-sign")
    resp = _post(manifest, files)
    assert resp.status_code == 200
    data = resp.json()
    assert data["passing_chain"] is not None
    assert len(data["candidate_chains"]) == 2
    # One branch fails for trust reasons, enumeration was not aborted.
    assert sum(1 for c in data["candidate_chains"] if c["valid"]) == 1
    # Same-DN disambiguation surfaced.
    assert data["ambiguous_names"]
    # HTML route works too.
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


def test_all_fail_example_lists_each_failure():
    manifest, files = _load_example("all-fail")
    resp = _post(manifest, files)
    data = resp.json()
    assert data["passing_chain"] is None
    codes = {
        f["code"] for c in data["candidate_chains"] for f in c["failures"]
    }
    assert "path_len_violated" in codes
    # Orphan CA is self-signed with an untrusted issuer DN (its own).
    assert data["missing_issuers"]


def test_alt_leaves_isolate_failure_modes():
    manifest, files = _load_example("all-fail")
    for leaf_name, expected_code in [
        ("alt-leaf-expired-issuer.pem", "expired"),
        ("alt-leaf-no-keycertsign.pem", "key_usage_no_key_cert_sign"),
        ("alt-leaf-missing-issuer.pem", "untrusted_terminus"),
    ]:
        resp = client.post(
            "/api/diagnose",
            files={
                "leaf": (leaf_name, files[leaf_name], "application/x-pem"),
                "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
                "intermediates": (
                    manifest["intermediates"],
                    files[manifest["intermediates"]],
                    "application/x-pem",
                ),
            },
            data={"validation_time": manifest["validation_time"]},
        )
        data = resp.json()
        codes = {
            f["code"] for c in data["candidate_chains"] for f in c["failures"]
        }
        assert expected_code in codes, (leaf_name, codes)


def test_bad_pem_returns_400():
    good_manifest, files = _load_example("cross-sign")
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


def test_example_redirect_and_unknown_example():
    assert client.get("/examples/cross-sign", follow_redirects=False).status_code == 303
    assert client.get("/api/examples/nope").status_code == 404


def test_naive_validation_time_accepted_as_utc():
    manifest, files = _load_example("cross-sign")
    resp = client.post(
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
        data={"validation_time": "2026-11-11T00:00:00"},
    )
    assert resp.status_code == 200
    assert resp.json()["passing_chain"] is not None


def test_empty_validation_time_defaults_to_now_and_bad_format_400():
    manifest, files = _load_example("cross-sign")
    resp = client.post(
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
        data={"validation_time": ""},
    )
    assert resp.status_code == 200
    resp_bad = client.post(
        "/api/diagnose",
        files={
            "leaf": (manifest["leaf"], files[manifest["leaf"]], "application/x-pem"),
            "root": (manifest["root"], files[manifest["root"]], "application/x-pem"),
            "intermediates": ("i.pem", b"", "text/plain"),
        },
        data={"validation_time": "not-a-time"},
    )
    assert resp_bad.status_code == 400
    assert "error" in resp_bad.json()
