"""Core offline chain-building and validation logic.

Scope (by design):
  * RSA PKCS#1 v1.5 / SHA-256 signatures only (OID 1.2.840.113549.1.1.11).
  * No revocation checking (CRL/OCSP) and no extended-key-usage checking.
  * The trusted root is supplied independently by the operator; trust is
    never derived from a bundle's self-signed certificate.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID

# RSA PKCS#1 v1.5 / SHA-256
ALLOWED_SIGNATURE_OID = "1.2.840.113549.1.1.11"
ALLOWED_SIGNATURE_LABEL = "RSA PKCS#1 v1.5 / SHA-256"

MAX_CERTIFICATES = 12
MAX_CANDIDATE_PATHS = 2000  # guard rail; 12 certs can otherwise explode


class DiagnosticInputError(ValueError):
    """Raised for malformed user input (bad PEM, too many certs, ...)."""


@dataclass
class CertInfo:
    index: int
    cert: x509.Certificate
    fingerprint: str
    subject: str
    issuer: str
    serial: str
    not_before: dt.datetime
    not_after: dt.datetime
    is_self_issued: bool
    is_self_signed: bool
    is_ca: bool
    path_len: Optional[int]
    key_usage_present: bool
    key_cert_sign: bool
    sig_oid: str
    sig_allowed: bool
    public_key_rsa: bool
    sig_label: str
    roles: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d.pop("cert")
        d["roles"] = sorted(self.roles)
        d["not_before"] = self.not_before.isoformat()
        d["not_after"] = self.not_after.isoformat()
        return d


@dataclass
class IssuerMatch:
    """A bundle/root certificate whose subject DN equals an issuer DN."""

    candidate: CertInfo
    signature_ok: bool
    failure: Optional[str] = None  # why verification failed / unsupported


@dataclass
class MissingIssuer:
    subject_cert: CertInfo
    issuer_dn: str
    same_name_mismatches: list[IssuerMatch]


@dataclass
class ChainFailure:
    position: int  # index in the chain list (0 == leaf)
    certificate_subject: str
    code: str
    reason: str


@dataclass
class CandidateChain:
    chain: list[CertInfo]
    reaches_root: bool
    valid: bool
    failures: list[ChainFailure] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "chain": [c.to_dict() for c in self.chain],
            "reaches_root": self.reaches_root,
            "valid": self.valid,
            "failures": [dataclasses.asdict(f) for f in self.failures],
        }


@dataclass
class DiagnosticResult:
    certificates: list[CertInfo]
    candidate_chains: list[CandidateChain]
    passing_chain: Optional[CandidateChain]
    missing_issuers: list[MissingIssuer]
    ambiguous_names: list[IssuerMatch]
    global_notes: list[str]
    leaf_fingerprint: str
    root_fingerprint: str
    validation_time: dt.datetime
    truncated: bool
    signature_policy: str = ALLOWED_SIGNATURE_LABEL

    def to_dict(self) -> dict:
        return {
            "certificates": [c.to_dict() for c in self.certificates],
            "candidate_chains": [c.to_dict() for c in self.candidate_chains],
            "passing_chain": (
                self.passing_chain.to_dict()
                if self.passing_chain is not None
                else None
            ),
            "missing_issuers": [
                {
                    "subject_cert": m.subject_cert.to_dict(),
                    "issuer_dn": m.issuer_dn,
                    "same_name_mismatches": [
                        {
                            "candidate": x.candidate.to_dict(),
                            "signature_ok": x.signature_ok,
                            "failure": x.failure,
                        }
                        for x in m.same_name_mismatches
                    ],
                }
                for m in self.missing_issuers
            ],
            "ambiguous_names": [
                {
                    "subject_cert": m.subject_cert.to_dict(),
                    "issuer_dn": m.issuer_dn,
                    "same_name_mismatches": [
                        {
                            "candidate": x.candidate.to_dict(),
                            "signature_ok": x.signature_ok,
                            "failure": x.failure,
                        }
                        for x in m.same_name_mismatches
                    ],
                }
                for m in self.ambiguous_names
            ],
            "global_notes": self.global_notes,
            "leaf_fingerprint": self.leaf_fingerprint,
            "root_fingerprint": self.root_fingerprint,
            "validation_time": self.validation_time.isoformat(),
            "truncated": self.truncated,
            "signature_policy": self.signature_policy,
        }


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

def _name_to_str(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # pragma: no cover - extremely defensive
        return str(name)


def parse_pem_bundle(data: bytes) -> list[x509.Certificate]:
    """Parse every PEM certificate in a byte string.

    Raises DiagnosticInputError when the payload contains no certificate or
    a PEM block that cannot be decoded.
    """
    if not data or not data.strip():
        raise DiagnosticInputError("上传内容为空，无法解析 PEM 证书。")
    certs: list[x509.Certificate] = []
    try:
        # load_pem_certs tolerates surrounding text and multiple blocks.
        loaded = x509.load_pem_x509_certificates(data)
    except ValueError as exc:
        raise DiagnosticInputError(f"PEM 解析失败：{exc}") from exc
    certs.extend(loaded)
    if not certs:
        raise DiagnosticInputError("未在上传内容中找到任何 PEM 证书。")
    return certs


def _is_rsa_public_key(cert: x509.Certificate) -> bool:
    return isinstance(cert.public_key(), rsa.RSAPublicKey)


def _basic_constraints(cert: x509.Certificate) -> tuple[bool, Optional[int]]:
    try:
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        return bool(bc.ca), bc.path_length
    except x509.ExtensionNotFound:
        return False, None
    except Exception:  # pragma: no cover
        return False, None


def _key_usage(cert: x509.Certificate) -> tuple[bool, bool]:
    try:
        ku = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        return True, bool(ku.key_cert_sign)
    except x509.ExtensionNotFound:
        return False, False
    except Exception:  # pragma: no cover
        return False, False


def build_cert_info(index: int, cert: x509.Certificate) -> CertInfo:
    sig_oid = cert.signature_algorithm_oid.dotted_string
    try:
        sig_hash = cert.signature_hash_algorithm
        sig_name = (
            f"{cert.signature_algorithm_oid._name} "  # type: ignore[attr-defined]
            f"({sig_hash.name if sig_hash else 'unknown hash'})"
        )
    except Exception:
        sig_name = cert.signature_algorithm_oid.dotted_string

    is_ca, path_len = _basic_constraints(cert)
    ku_present, key_cert_sign = _key_usage(cert)
    subject = _name_to_str(cert.subject)
    issuer = _name_to_str(cert.issuer)
    try:
        fp = cert.fingerprint(hashes.SHA256()).hex(":")
    except Exception:  # pragma: no cover
        fp = ""

    return CertInfo(
        index=index,
        cert=cert,
        fingerprint=fp,
        subject=subject,
        issuer=issuer,
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        is_self_issued=subject == issuer,
        is_self_signed=False,  # filled in after signature verification
        is_ca=is_ca,
        path_len=path_len,
        key_usage_present=ku_present,
        key_cert_sign=key_cert_sign,
        sig_oid=sig_oid,
        sig_allowed=sig_oid == ALLOWED_SIGNATURE_OID,
        public_key_rsa=_is_rsa_public_key(cert),
        sig_label=sig_name,
    )


# --------------------------------------------------------------------------- #
# Signature verification
# --------------------------------------------------------------------------- #

def verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> tuple[bool, Optional[str]]:
    """Verify `child` against `issuer`'s public key under the fixed policy.

    Returns (ok, failure_reason). Same-DN candidates that fail here must be
    distinguished rather than treated as valid issuers.
    """
    if child.signature_algorithm_oid.dotted_string != ALLOWED_SIGNATURE_OID:
        return False, (
            f"子证书签名算法 {child.signature_algorithm_oid.dotted_string} "
            f"不受支持（仅允许 {ALLOWED_SIGNATURE_LABEL}）"
        )
    issuer_pub = issuer.public_key()
    if not isinstance(issuer_pub, rsa.RSAPublicKey):
        return False, "候选签发者公钥不是 RSA，无法按策略验签"
    try:
        issuer_pub.verify(
            child.signature,
            child.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False, "签名验证失败：同名签发者持有不同密钥（交叉/冒名证书须按签名区分）"
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"签名验证异常：{exc}"
    return True, None


# --------------------------------------------------------------------------- #
# Graph construction & path search
# --------------------------------------------------------------------------- #

def _find_issuer_matches(
    info: CertInfo, pool: list[CertInfo]
) -> list[IssuerMatch]:
    """Same-DN candidates, signature-tested. Deterministic order."""
    matches: list[IssuerMatch] = []
    for cand in pool:
        if cand.subject != info.issuer:
            continue
        if cand.fingerprint == info.fingerprint and not info.is_self_issued:
            continue
        ok, fail = verify_signature(info.cert, cand.cert)
        matches.append(IssuerMatch(candidate=cand, signature_ok=ok, failure=fail))
    matches.sort(key=lambda m: (not m.signature_ok, m.candidate.index))
    return matches


def diagnose(
    leaf_certs: list[x509.Certificate],
    intermediate_certs: list[x509.Certificate],
    root_certs: list[x509.Certificate],
    validation_time: dt.datetime,
) -> DiagnosticResult:
    if len(leaf_certs) != 1:
        raise DiagnosticInputError("必须且只能上传 1 张客户端证书。")
    if len(root_certs) != 1:
        raise DiagnosticInputError("必须且只能独立指定 1 张受信根 PEM。")

    # De-duplicate identical certs (same DER) across the three inputs.
    seen: dict[bytes, x509.Certificate] = {}
    order: list[x509.Certificate] = []
    for c in [*leaf_certs, *intermediate_certs, *root_certs]:
        der = c.public_bytes(Encoding.DER)
        if der not in seen:
            seen[der] = c
            order.append(c)
    if len(order) > MAX_CERTIFICATES:
        raise DiagnosticInputError(
            f"去重后共 {len(order)} 张证书，超过上限 {MAX_CERTIFICATES} 张。"
        )

    infos = [build_cert_info(i, c) for i, c in enumerate(order)]
    leaf = next(i for i in infos if i.cert is leaf_certs[0])
    root = next(i for i in infos if i.cert is root_certs[0])
    leaf.roles.add("leaf")
    root.roles.add("root")
    for info in infos:
        if info is not leaf and info is not root:
            info.roles.add("intermediate")

    global_notes: list[str] = []

    # Policy check on every uploaded certificate's own signature algorithm.
    for info in infos:
        if not info.sig_allowed:
            global_notes.append(
                f"证书「{info.subject}」(序列号 {info.serial}) 的签名算法 OID "
                f"{info.sig_oid} 不在允许范围（{ALLOWED_SIGNATURE_LABEL}），"
                "其相关签名字段不参与有效路径构建。"
            )

    # Root must be self-signed and verify under itself.
    if root.subject != root.issuer:
        global_notes.append("指定的受信根不是自颁发证书（subject 与 issuer 不一致）。")
    root_ok, root_fail = verify_signature(root.cert, root.cert)
    root.is_self_signed = root_ok
    if not root_ok:
        global_notes.append(f"受信根自签名验证未通过：{root_fail}")

    # Mark self-signed status for any other self-issued certs.
    for info in infos:
        if info is root:
            continue
        if info.is_self_issued:
            ok, _ = verify_signature(info.cert, info.cert)
            info.is_self_signed = ok

    # Build edges: child -> same-DN candidates that verify cryptographically.
    # Candidates with an unsupported signature policy are still linked so
    # that per-chain validation can report the *policy* failure (instead of
    # masquerading as a missing issuer).
    edges: dict[str, list[IssuerMatch]] = {}
    same_name_mismatch_map: dict[str, list[IssuerMatch]] = {}
    for info in infos:
        matches = _find_issuer_matches(info, infos)
        edges[info.fingerprint] = [
            m for m in matches if m.signature_ok or not info.sig_allowed
        ]
        same_name_mismatch_map[info.fingerprint] = [
            m for m in matches if not m.signature_ok
        ]

    # DFS: enumerate every acyclic candidate path starting at the leaf.
    # A self-signed certificate (self-loop edge) terminates a path: the
    # trail recorded so far is the candidate chain.
    paths: list[list[CertInfo]] = []
    truncated = False

    def dfs(current: CertInfo, trail: list[CertInfo], visited: set[str]) -> None:
        nonlocal truncated
        if len(paths) >= MAX_CANDIDATE_PATHS:
            truncated = True
            return
        if current.is_self_signed:
            paths.append(list(trail))
            return
        nxt = [
            m for m in edges.get(current.fingerprint, [])
            if m.candidate.fingerprint != current.fingerprint
        ]
        if not nxt:
            paths.append(list(trail))  # dead end: missing/untrusted issuer
            return
        for match in nxt:
            cand = match.candidate
            if cand.fingerprint in visited:
                # Cycle: record the acyclic trail ending here, do not loop.
                paths.append(list(trail))
                if len(paths) >= MAX_CANDIDATE_PATHS:
                    truncated = True
                    return
                continue
            visited.add(cand.fingerprint)
            trail.append(cand)
            dfs(cand, trail, visited)
            trail.pop()
            visited.remove(cand.fingerprint)
            if len(paths) >= MAX_CANDIDATE_PATHS:
                truncated = True
                return

    dfs(leaf, [leaf], {leaf.fingerprint})

    # Missing issuers: certificates with no cryptographically verified
    # outgoing edge, except the trusted root. A self-signed orphan still
    # gets reported (its self-signature does not make the trusted root its
    # issuer). Policy-unsupported certs are handled by per-chain checks.
    missing: list[MissingIssuer] = []
    for info in infos:
        if info.fingerprint == root.fingerprint:
            continue
        # A self-loop (self-signed cert) does not count as an issuer path
        # toward the trusted root: only *other* verified certs qualify.
        verified_parents = [
            m for m in edges.get(info.fingerprint, [])
            if m.signature_ok
            and m.candidate.fingerprint != info.fingerprint
        ]
        if verified_parents:
            continue
        missing.append(
            MissingIssuer(
                subject_cert=info,
                issuer_dn=info.issuer,
                same_name_mismatches=same_name_mismatch_map.get(info.fingerprint, []),
            )
        )
    missing.sort(key=lambda m: m.subject_cert.index)

    # Same-DN ambiguity: certs that DO have a verified issuer but where
    # other same-DN candidates failed verification. This is the fingerprint
    # of cross-sign / stale-cert confusion operators must distinguish.
    ambiguous: list[MissingIssuer] = []
    for info in infos:
        if info.fingerprint == root.fingerprint:
            continue
        verified_parents = [
            m for m in edges.get(info.fingerprint, [])
            if m.signature_ok
            and m.candidate.fingerprint != info.fingerprint
        ]
        mismatches = same_name_mismatch_map.get(info.fingerprint, [])
        if verified_parents and mismatches:
            ambiguous.append(
                MissingIssuer(
                    subject_cert=info,
                    issuer_dn=info.issuer,
                    same_name_mismatches=mismatches,
                )
            )
    ambiguous.sort(key=lambda m: m.subject_cert.index)

    # Validate each candidate chain independently; one bad chain never
    # short-circuits evaluation of the others.
    candidates: list[CandidateChain] = []
    passing: Optional[CandidateChain] = None
    for path in paths:
        cand = _validate_chain(path, root, validation_time)
        candidates.append(cand)
        if cand.valid and passing is None:
            passing = cand

    return DiagnosticResult(
        certificates=infos,
        candidate_chains=candidates,
        passing_chain=passing,
        missing_issuers=missing,
        ambiguous_names=ambiguous,
        global_notes=global_notes,
        leaf_fingerprint=leaf.fingerprint,
        root_fingerprint=root.fingerprint,
        validation_time=validation_time,
        truncated=truncated,
    )


# --------------------------------------------------------------------------- #
# Per-chain validation
# --------------------------------------------------------------------------- #

def _validate_chain(
    chain: list[CertInfo],
    trusted_root: CertInfo,
    when: dt.datetime,
) -> CandidateChain:
    failures: list[ChainFailure] = []
    reaches_root = chain[-1].fingerprint == trusted_root.fingerprint

    def add(pos: int, code: str, reason: str) -> None:
        failures.append(
            ChainFailure(
                position=pos,
                certificate_subject=chain[pos].subject,
                code=code,
                reason=reason,
            )
        )

    # 1. Every link's signature must verify (edges guarantee this, re-check
    #    defensively, including the policy OID).
    for pos in range(1, len(chain)):
        child, issuer = chain[pos - 1], chain[pos]
        if not child.sig_allowed:
            add(
                pos - 1,
                "unsupported_signature",
                f"签名算法 OID {child.sig_oid} 不受支持（仅允许 {ALLOWED_SIGNATURE_LABEL}）",
            )
            continue
        ok, fail = verify_signature(child.cert, issuer.cert)
        if not ok:
            add(pos - 1, "signature_mismatch", fail or "签名验证失败")

    # 2. Validity window for every certificate, at the supplied time.
    for pos, info in enumerate(chain):
        if when < info.not_before:
            add(
                pos,
                "not_yet_valid",
                f"校验时间 {when.isoformat()} 早于 notBefore {info.not_before.isoformat()}",
            )
        elif when >= info.not_after:
            add(
                pos,
                "expired",
                f"校验时间 {when.isoformat()} 不早于 notAfter {info.not_after.isoformat()}",
            )

    # 3. Every issuer (positions 1..n) must be a CA.
    for pos in range(1, len(chain)):
        issuer = chain[pos]
        if not issuer.is_ca:
            add(
                pos,
                "not_a_ca",
                "BasicConstraints 缺失或 cA=FALSE，该证书不能签发下级证书",
            )

    # 4. KeyUsage: when present on an issuer, keyCertSign must be asserted.
    for pos in range(1, len(chain)):
        issuer = chain[pos]
        if issuer.key_usage_present and not issuer.key_cert_sign:
            add(
                pos,
                "key_usage_no_key_cert_sign",
                "KeyUsage 扩展存在但未置位 keyCertSign",
            )

    # 5. pathLenConstraint on every issuer CA (RFC 5280 §4.2.1.9).
    #    Gives the maximum number of non-self-issued *intermediate CA*
    #    certificates that may follow this certificate; the end-entity leaf
    #    is not an intermediate and does not consume the budget, neither do
    #    self-issued intermediate certificates.
    for pos in range(1, len(chain)):
        issuer = chain[pos]
        if issuer.path_len is None:
            continue
        intermediates_below = [
            c
            for c in chain[1:pos]  # exclude the leaf at position 0
            if c.is_ca and not c.is_self_issued
        ]
        if len(intermediates_below) > issuer.path_len:
            add(
                pos,
                "path_len_violated",
                f"pathLenConstraint={issuer.path_len}，"
                f"但其下方有 {len(intermediates_below)} 张非自颁发中间 CA"
                "（终端实体与自颁发中间证书不计入）",
            )

    # 6. The chain must terminate at the independently supplied trusted root.
    if not reaches_root:
        add(
            len(chain) - 1,
            "untrusted_terminus",
            (
                "链终止于非受信根证书；未找到通向指定受信根 "
                f"「{trusted_root.subject}」的已验证签发关系"
            ),
        )
    else:
        if not trusted_root.is_self_signed:
            add(
                len(chain) - 1,
                "root_self_signature_bad",
                "受信根自签名验证未通过",
            )

    return CandidateChain(
        chain=list(chain),
        reaches_root=reaches_root,
        valid=not failures,
        failures=failures,
    )
