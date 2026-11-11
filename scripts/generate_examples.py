#!/usr/bin/env python3
"""Generate built-in offline cross-sign examples.

Run from repo root:  python3 scripts/generate_examples.py

Outputs PEM files under app/examples/<name>/ plus a manifest.json consumed
by the web UI. All keys are throwaway RSA-2048 keys generated on the spot;
everything is signed with RSA PKCS#1 v1.5 / SHA-256 only.

Two scenarios:
  cross-sign/   - two roots, one CA cross-signed by both; one branch dead-ends
                  (missing/untrusted issuer), the other reaches the trusted
                  root; a same-DN stale intermediate proves signature-based
                  disambiguation.
  all-fail/     - every candidate chain fails, for different reasons:
                  missing intermediate, expired same-DN candidate,
                  pathLen violation, keyCertSign missing.
"""

from __future__ import annotations

import json
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VAL_TIME = dt.datetime(2026, 11, 11, tzinfo=dt.timezone.utc)
OUT = Path(__file__).resolve().parent.parent / "app" / "examples"


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def dn(cn: str, o: str = "Example Internal CA") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _ku(key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def ca_cert(subject_cn, issuer_cn, subject_key, issuer_key, *,
            days, path_len, self_signed=False, key_cert_sign=True,
            serial=None):
    now = VAL_TIME
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(dn(subject_cn) if self_signed else dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=30))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True
        )
        .add_extension(_ku(key_cert_sign), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
    )
    signer = subject_key if self_signed else issuer_key
    return builder.sign(signer, hashes.SHA256())


def leaf_cert(subject_cn, issuer_cn, subject_key, issuer_key, *, days=365):
    now = VAL_TIME
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn, o="Example Internal Services"))
        .issuer_name(dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=10))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()
            ),
            critical=False,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


def write_pem(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def expired_ca_cert(subject_cn, issuer_cn, subject_key, issuer_key, *,
                    path_len, serial):
    """A CA cert whose whole validity window is in 2020 (expired at VAL_TIME)."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial)
        .not_valid_before(dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2020, 6, 1, tzinfo=dt.timezone.utc))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True
        )
        .add_extension(_ku(True), critical=True)
    )
    return builder.sign(issuer_key, hashes.SHA256())


def build_cross_sign(base: Path) -> None:
    d = base / "cross-sign"
    d.mkdir(parents=True, exist_ok=True)

    root_a_k, root_b_k = key(), key()
    shared_k = key()        # ONE intermediate key, cross-signed by both roots
    stale_k, leaf_k = key(), key()

    root_a = ca_cert("Root A", "Root A", root_a_k, root_a_k,
                     days=3650, path_len=None, self_signed=True)
    root_b = ca_cert("Root B", "Root B", root_b_k, root_b_k,
                     days=3650, path_len=None, self_signed=True)

    # Cross-sign: identical subject DN and public key, two issuers.
    ia = ca_cert("Intermediate CA X", "Root A", shared_k, root_a_k,
                 days=1825, path_len=0)
    ib = ca_cert("Intermediate CA X", "Root B", shared_k, root_b_k,
                 days=1825, path_len=0)
    # Same-DN stale intermediate, another key: DN equality is not enough.
    stale = ca_cert("Intermediate CA X", "Root A", stale_k, root_a_k,
                    days=900, path_len=0)

    leaf = leaf_cert("mtls-client.service.example", "Intermediate CA X",
                     leaf_k, shared_k)

    # Deliberately unordered bundle; stale/untrusted-root PEMs included so
    # the tool has to disambiguate rather than rely on file order.
    write_pem(d / "02-intermediates.pem", ib)
    with (d / "02-intermediates.pem").open("ab") as f:
        f.write(stale.public_bytes(serialization.Encoding.PEM))
        f.write(ia.public_bytes(serialization.Encoding.PEM))
        f.write(root_b.public_bytes(serialization.Encoding.PEM))
    write_pem(d / "01-client-leaf.pem", leaf)
    write_pem(d / "03-trusted-root.pem", root_a)

    (d / "README.md").write_text(
        "# cross-sign 示例\n\n"
        "- 受信根：Root A（独立指定）。Root B 故意放进中间包，模拟交叉签发的另一侧。\n"
        "- `Intermediate CA X` 的同一把公钥被 Root A、Root B 分别签发（真正的交叉签发），"
        "另有一张同 DN、不同密钥的陈旧证书；后者验签必然失败，必须按签名区分。\n"
        "- 期望：枚举出两条候选路径，只有 leaf→I(Root A 签)→Root A 通过；"
        "leaf→I(Root B 签) 因 Root B 不受信而失败，Root B 上方作为缺失/不受信签发者单独指出。\n"
        f"- 校验时间：{VAL_TIME.isoformat()}\n",
        encoding="utf-8",
    )
    (d / "manifest.json").write_text(
        json.dumps(
            {
                "title": "交叉签发选链（一条通过 / 一条不受信）",
                "leaf": "01-client-leaf.pem",
                "intermediates": "02-intermediates.pem",
                "root": "03-trusted-root.pem",
                "validation_time": VAL_TIME.isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def build_all_fail(base: Path) -> None:
    d = base / "all-fail"
    d.mkdir(parents=True, exist_ok=True)

    root_k = key()
    tight_k = key()          # pathLen=0 CA
    good_issuer_k = key()    # same DN as expired one, valid key
    old_issuer_k = key()     # same DN, expired cert
    no_ku_k = key()          # CA without keyCertSign
    orphan_k = key()         # its issuer is not in the bundle
    leaf1_k, leaf2_k = key(), key()
    leaf3_k, leaf4_k = key(), key()

    root = ca_cert("Strict Root", "Strict Root", root_k, root_k,
                   days=3650, path_len=1, self_signed=True)
    tight = ca_cert("Tight pathLen CA", "Strict Root", tight_k, root_k,
                    days=1825, path_len=0)

    same_dn = "Renewed Issuing CA"
    good_issuer = ca_cert(same_dn, "Tight pathLen CA", good_issuer_k, tight_k,
                          days=730, path_len=None, serial=0x1111)
    expired_issuer = expired_ca_cert(
        same_dn, "Tight pathLen CA", old_issuer_k, tight_k,
        path_len=None, serial=0x2222,
    )

    no_ku = ca_cert("No keyCertSign CA", "Tight pathLen CA", no_ku_k, tight_k,
                    days=730, path_len=None, key_cert_sign=False)

    orphan = ca_cert("Orphan CA", "Missing External Root", orphan_k, orphan_k,
                     days=730, path_len=None, self_signed=True)

    leaf1 = leaf_cert("client.pathlen.example", same_dn, leaf1_k, good_issuer_k)
    leaf2 = leaf_cert("client.expired-issuer.example", same_dn, leaf2_k, old_issuer_k)
    leaf3 = leaf_cert("client.no-keycertsign.example", "No keyCertSign CA",
                      leaf3_k, no_ku_k)
    leaf4 = leaf_cert("client.missing-issuer.example", "Orphan CA",
                      leaf4_k, orphan_k)

    write_pem(d / "01-client-leaf.pem", leaf1)
    with (d / "02-intermediates.pem").open("wb") as f:
        for c in (orphan, no_ku, expired_issuer, good_issuer, tight):
            f.write(c.public_bytes(serialization.Encoding.PEM))
    # Extra leaf probes kept aside: swap them into the leaf slot to see
    # each failure mode in isolation.
    write_pem(d / "alt-leaf-expired-issuer.pem", leaf2)
    write_pem(d / "alt-leaf-no-keycertsign.pem", leaf3)
    write_pem(d / "alt-leaf-missing-issuer.pem", leaf4)
    write_pem(d / "03-trusted-root.pem", root)

    (d / "README.md").write_text(
        "# all-fail 示例\n\n"
        "默认叶子 `client.pathlen`：根 pathLen=1、Tight pathLen CA pathLen=0，"
        "其下方又有一级签发 CA → pathLen 违规。\n\n"
        "替换叶子可分别复现：\n"
        "- alt-leaf-expired-issuer：同 DN 候选一张有效、一张 2020 年过期；过期链单独失败。\n"
        "- alt-leaf-no-keycertsign：签发 CA 的 KeyUsage 未置位 keyCertSign。\n"
        "- alt-leaf-missing-issuer：Orphan CA 的签发者 Missing External Root 未提供。\n"
        f"- 校验时间：{VAL_TIME.isoformat()}\n",
        encoding="utf-8",
    )
    (d / "manifest.json").write_text(
        json.dumps(
            {
                "title": "全链失败演示（pathLen/过期/KeyUsage/缺失签发者）",
                "leaf": "01-client-leaf.pem",
                "intermediates": "02-intermediates.pem",
                "root": "03-trusted-root.pem",
                "validation_time": VAL_TIME.isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    build_cross_sign(OUT)
    build_all_fail(OUT)
    print(f"examples written under {OUT}")


if __name__ == "__main__":
    main()
