"""Shared certificate factory helpers for tests (RSA, offline)."""

from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VAL = dt.datetime(2026, 11, 11, tzinfo=dt.timezone.utc)


def gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def make_ca(subject_cn, issuer_cn, subject_key, issuer_key, *,
            path_len=None, self_signed=False, key_cert_sign=True,
            not_before=None, not_after=None, hash_alg=hashes.SHA256(),
            serial=None):
    nb = not_before or (VAL - dt.timedelta(days=30))
    na = not_after or (VAL + dt.timedelta(days=365))
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject_cn))
        .issuer_name(name(subject_cn) if self_signed else name(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=path_len), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    signer = subject_key if self_signed else issuer_key
    return builder.sign(signer, hash_alg)


def make_leaf(subject_cn, issuer_cn, subject_key, issuer_key, *,
              not_before=None, not_after=None, hash_alg=hashes.SHA256(),
              subject_org="Test Svc"):
    nb = not_before or (VAL - dt.timedelta(days=10))
    na = not_after or (VAL + dt.timedelta(days=365))
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_org),
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                ]
            )
        )
        .issuer_name(name(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
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
    )
    return builder.sign(issuer_key, hash_alg)


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)
