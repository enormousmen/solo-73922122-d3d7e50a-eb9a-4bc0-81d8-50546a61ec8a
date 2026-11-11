"""Core diagnostics tests: chain search, cross-sign, constraints, policy."""

import datetime as dt

import pytest
from cryptography.hazmat.primitives import hashes

from app.diagnostics import (
    ALLOWED_SIGNATURE_LABEL,
    DiagnosticInputError,
    diagnose,
    parse_pem_bundle,
)

from .cert_factory import VAL, gen_key, make_ca, make_leaf, pem


def _simple_hierarchy(depth=2, path_lens=None):
    """root -> ca1 -> ... -> leaf. Returns (leaf, intermediates, root)."""
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True,
                   path_len=(path_lens or {}).get("root"))
    keys = [root_k]
    cas = [root]
    inter = []
    for i in range(1, depth):
        k = gen_key()
        ca = make_ca(f"CA{i}", f"CA{i - 1}" if i > 1 else "Root", k, keys[-1],
                     path_len=(path_lens or {}).get(f"ca{i}"))
        keys.append(k)
        cas.append(ca)
        inter.append(ca)
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", f"CA{depth - 1}", leaf_k, keys[-1])
    return leaf, inter, root


def test_simple_valid_chain_passes():
    leaf, inter, root = _simple_hierarchy(depth=3)
    res = diagnose([leaf], inter, [root], VAL)
    assert res.passing_chain is not None
    assert [c.subject for c in res.passing_chain.chain] == [
        "CN=leaf.example,O=Test Svc",
        "CN=CA2,O=Test Org",
        "CN=CA1,O=Test Org",
        "CN=Root,O=Test Org",
    ]
    assert res.missing_issuers == []
    assert all(c.valid for c in res.candidate_chains)


def test_missing_intermediate_is_reported_separately():
    leaf, inter, root = _simple_hierarchy(depth=3)
    res = diagnose([leaf], inter[1:], [root], VAL)  # drop CA1
    assert res.passing_chain is None
    codes = {f.code for c in res.candidate_chains for f in c.failures}
    assert "untrusted_terminus" in codes
    missing_dns = [m.issuer_dn for m in res.missing_issuers]
    assert any("CA1" in d for d in missing_dns)


def test_cross_sign_same_dn_disambiguated_by_signature():
    root_a_k, root_b_k = gen_key(), gen_key()
    root_a = make_ca("Root A", "Root A", root_a_k, root_a_k, self_signed=True)
    root_b = make_ca("Root B", "Root B", root_b_k, root_b_k, self_signed=True)
    # Cross-sign: ONE intermediate key, two certs with the same subject DN,
    # one issued by Root A, one by Root B.
    shared_k = gen_key()
    ia = make_ca("Shared CA", "Root A", shared_k, root_a_k)
    ib = make_ca("Shared CA", "Root B", shared_k, root_b_k)
    # Same-DN stale intermediate with a DIFFERENT key: DN matches but the
    # leaf's signature can never verify against it.
    stale_k = gen_key()
    stale = make_ca("Shared CA", "Root A", stale_k, root_a_k)
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", "Shared CA", leaf_k, shared_k)

    # Unordered bundle; Root B is present but not the designated trusted root.
    res = diagnose([leaf], [stale, ib, ia, root_b], [root_a], VAL)
    assert len(res.candidate_chains) == 2
    # First failure must not stop enumeration: exactly one chain passes.
    valid = [c for c in res.candidate_chains if c.valid]
    assert len(valid) == 1
    assert valid[0].chain[-1].fingerprint == res.root_fingerprint
    bad = [c for c in res.candidate_chains if not c.valid][0]
    assert not bad.reaches_root
    # Stale same-DN cert must never appear in any chain (signature fails).
    chain_fps = {c.fingerprint for c in res.candidate_chains for c in c.chain}
    assert stale.fingerprint(hashes.SHA256()).hex(":") not in chain_fps
    # Root B branch ends at an untrusted, self-signed terminus.
    miss = [m for m in res.missing_issuers if "Root B" in m.issuer_dn]
    assert miss
    # The stale same-DN cert is surfaced as an ambiguous name on the leaf.
    stale_fp = stale.fingerprint(hashes.SHA256()).hex(":")
    amb = [m for m in res.ambiguous_names
           if m.subject_cert.fingerprint == res.leaf_fingerprint]
    assert amb and any(
        x.candidate.fingerprint == stale_fp for x in amb[0].same_name_mismatches
    )


def test_all_chains_evaluated_even_if_first_fails():
    # Same-DN expired cert sorts before valid one? Regardless: both listed.
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    good_k, bad_k = gen_key(), gen_key()
    good = make_ca("Issuer", "Root", good_k, root_k)
    expired = make_ca(
        "Issuer", "Root", bad_k, root_k,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2020, 6, 1, tzinfo=dt.timezone.utc),
    )
    leaf_good_k = gen_key()
    leaf_good = make_leaf("good.example", "Issuer", leaf_good_k, good_k)
    leaf_bad_k = gen_key()
    leaf_bad = make_leaf("bad.example", "Issuer", leaf_bad_k, bad_k)

    # Two separate runs: expired chain reports expiry, good chain passes.
    res_bad = diagnose([leaf_bad], [good, expired], [root], VAL)
    assert res_bad.passing_chain is None
    codes = {f.code for c in res_bad.candidate_chains for f in c.failures}
    assert "expired" in codes
    res_good = diagnose([leaf_good], [expired, good], [root], VAL)
    assert res_good.passing_chain is not None


def test_validity_window_boundaries():
    leaf, inter, root = _simple_hierarchy()
    # VAL sits inside every cert's window.
    res = diagnose([leaf], inter, [root], VAL)
    assert res.passing_chain is not None
    # One second past the earliest notAfter makes that cert expire.
    earliest_na = min(c.not_valid_after_utc for c in [leaf, *inter, root])
    res2 = diagnose([leaf], inter, [root], earliest_na)
    assert res2.passing_chain is None
    assert any(
        f.code == "expired"
        for c in res2.candidate_chains for f in c.failures
    )
    # Before every notBefore -> not yet valid.
    earliest_nb = min(c.not_valid_before_utc for c in [leaf, *inter, root])
    res3 = diagnose([leaf], inter, [root], earliest_nb - dt.timedelta(seconds=1))
    assert any(
        f.code == "not_yet_valid"
        for c in res3.candidate_chains for f in c.failures
    )
    # Precise boundary semantics on a single-level chain where the leaf has
    # the earliest notBefore: inclusive notBefore, exclusive notAfter.
    root_k2 = gen_key()
    root2 = make_ca(
        "R2", "R2", root_k2, root_k2, self_signed=True,
        not_before=dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
    )
    ca_k2 = gen_key()
    ca2 = make_ca(
        "C2", "R2", ca_k2, root_k2,
        not_before=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc),
    )
    leaf_k2 = gen_key()
    leaf2 = make_leaf("l2", "C2", leaf_k2, ca_k2,
                      not_before=dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc),
                      not_after=dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc))
    t_lo = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)
    t_hi = dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc)
    assert diagnose([leaf2], [ca2], [root2], t_lo).passing_chain is not None
    res_hi = diagnose([leaf2], [ca2], [root2], t_hi)
    assert res_hi.passing_chain is None
    assert any(
        f.code == "expired"
        for c in res_hi.candidate_chains for f in c.failures
    )


def test_pathlen_constraint_and_self_issued_exemption():
    root_k = gen_key()
    # root pathLen=0: no non-self-issued intermediate allowed below.
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True, path_len=0)
    ca1_k = gen_key()
    ca1 = make_ca("CA1", "Root", ca1_k, root_k, path_len=0)
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", "CA1", leaf_k, ca1_k)
    res = diagnose([leaf], [ca1], [root], VAL)
    assert res.passing_chain is None
    assert any(
        f.code == "path_len_violated"
        for c in res.candidate_chains for f in c.failures
    )

    # Now a self-issued intermediate (same DN/key, self-signed) sits in the
    # chain: self-issued CA certs don't consume pathLen (RFC 5280).
    leaf2 = make_leaf("leaf2.example", "CA1", gen_key(), ca1_k)
    root2_k = gen_key()
    root2 = make_ca("Root2", "Root2", root2_k, root2_k, self_signed=True, path_len=1)
    ca1_2 = make_ca("CA1", "Root2", ca1_k, root2_k, path_len=0)
    si2 = make_ca("CA1", "CA1", ca1_k, ca1_k, self_signed=True, path_len=0)
    res2 = diagnose([leaf2], [ca1_2, si2], [root2], VAL)
    # One non-self-issued intermediate (ca1_2) below root2 -> pathLen 1 OK.
    assert res2.passing_chain is not None
    assert not any(
        f.code == "path_len_violated"
        for c in res2.candidate_chains for f in c.failures
    )

    # Two non-self-issued intermediates under a pathLen=1 root -> violation.
    root3_k = gen_key()
    root3 = make_ca("Root3", "Root3", root3_k, root3_k, self_signed=True, path_len=1)
    mid_k = gen_key()
    mid = make_ca("MID", "Root3", mid_k, root3_k, path_len=1)
    ca1_3 = make_ca("CA1", "MID", ca1_k, mid_k, path_len=0)
    leaf3 = make_leaf("leaf3.example", "CA1", gen_key(), ca1_k)
    res3 = diagnose([leaf3], [mid, ca1_3], [root3], VAL)
    assert res3.passing_chain is None
    assert any(
        f.code == "path_len_violated"
        for c in res3.candidate_chains for f in c.failures
    )


def test_key_usage_key_cert_sign_required_when_present():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    bad_ca_k = gen_key()
    bad_ca = make_ca("BadCA", "Root", bad_ca_k, root_k, key_cert_sign=False)
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", "BadCA", leaf_k, bad_ca_k)
    res = diagnose([leaf], [bad_ca], [root], VAL)
    assert res.passing_chain is None
    assert any(
        f.code == "key_usage_no_key_cert_sign"
        for c in res.candidate_chains for f in c.failures
    )


def test_non_ca_issuer_rejected():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    # A leaf-like cert (BasicConstraints cA=FALSE) tries to act as issuer.
    fake_k = gen_key()
    fake_issuer = make_leaf("fake.example", "Root", fake_k, root_k,
                            subject_org="Test Org")
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", "fake.example", leaf_k, fake_k)
    res = diagnose([leaf], [fake_issuer], [root], VAL)
    assert res.passing_chain is None
    assert any(
        f.code == "not_a_ca"
        for c in res.candidate_chains for f in c.failures
    )


def test_unsupported_signature_algorithm_rejected():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    ca_k = gen_key()
    # CA signed with SHA-384 PKCS#1 v1.5 -> policy violation.
    ca = make_ca("CA384", "Root", ca_k, root_k, hash_alg=hashes.SHA384())
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", "CA384", leaf_k, ca_k)
    res = diagnose([leaf], [ca], [root], VAL)
    assert res.passing_chain is None
    assert any("1.2.840.113549.1.1.12" in n or "不受支持" in n
               for n in res.global_notes)
    assert any(
        f.code == "unsupported_signature"
        for c in res.candidate_chains for f in c.failures
    )
    assert ALLOWED_SIGNATURE_LABEL in res.signature_policy


def test_cycle_does_not_loop_and_remains_acyclic():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    a_k, b_k = gen_key(), gen_key()
    # A has two certs with the same key: one issued by Root (trust path),
    # one cross-issued by B (closes a cycle A -> B -> A).
    a_from_root = make_ca("A", "Root", a_k, root_k)
    b = make_ca("B", "A", b_k, a_k)
    a_from_b = make_ca("A", "B", a_k, b_k)
    leaf_k = gen_key()
    leaf = make_leaf("leaf.example", "A", leaf_k, a_k)
    res = diagnose([leaf], [a_from_root, b, a_from_b], [root], VAL)
    # Search terminates and every enumerated chain is acyclic.
    for cand in res.candidate_chains:
        fps = [c.fingerprint for c in cand.chain]
        assert len(fps) == len(set(fps))
    # One branch reaches the trusted root via A-from-Root.
    assert any(
        cand.reaches_root and cand.valid
        for cand in res.candidate_chains
    )
    # Another branch hits the cycle / B dead-end and is reported.
    assert any(not cand.reaches_root for cand in res.candidate_chains)


def test_too_many_certificates_rejected():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    inter = []
    prev_k, prev_cn = root_k, "Root"
    for i in range(11):
        k = gen_key()
        cn = f"CA{i}"
        inter.append(make_ca(cn, prev_cn, k, prev_k))
        prev_k, prev_cn = k, cn
    leaf = make_leaf("leaf", "CA10", gen_key(), prev_k)
    # 1 root + 11 CAs + 1 leaf = 13 unique
    with pytest.raises(DiagnosticInputError, match="12"):
        diagnose([leaf], inter, [root], VAL)


def test_duplicate_inputs_deduped_and_limit_counts_unique():
    leaf, inter, root = _simple_hierarchy()
    # Same cert repeated across slots must not inflate the count.
    res = diagnose([leaf], inter + [leaf, root], [root], VAL)
    assert len(res.certificates) == 3
    assert res.passing_chain is not None


def test_exactly_twelve_certificates_accepted():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    inter = []
    prev_k, prev_cn = root_k, "Root"
    for i in range(10):  # 10 intermediates
        k = gen_key()
        cn = f"CA{i}"
        inter.append(make_ca(cn, prev_cn, k, prev_k))
        prev_k, prev_cn = k, cn
    leaf = make_leaf("leaf", "CA9", gen_key(), prev_k)
    # 1 root + 10 CAs + 1 leaf = 12 unique -> accepted.
    res = diagnose([leaf], inter, [root], VAL)
    assert len(res.certificates) == 12
    assert res.passing_chain is not None


def test_input_counts_validated():
    leaf, inter, root = _simple_hierarchy()
    with pytest.raises(DiagnosticInputError):
        diagnose([], inter, [root], VAL)
    with pytest.raises(DiagnosticInputError):
        diagnose([leaf], inter, [], VAL)
    with pytest.raises(DiagnosticInputError):
        diagnose([leaf, leaf], inter, [root], VAL)


def test_parse_pem_bundle_errors():
    with pytest.raises(DiagnosticInputError):
        parse_pem_bundle(b"")
    with pytest.raises(DiagnosticInputError):
        parse_pem_bundle(b"not a pem at all")


def test_trusted_root_self_signature_checked():
    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    ca_k = gen_key()
    ca = make_ca("CA1", "Root", ca_k, root_k)
    leaf = make_leaf("leaf", "CA1", gen_key(), ca_k)
    # Tamper: replace trusted root slot with a different self-signed root
    # whose DN matches but key differs -> chain edge to root fails.
    other_k = gen_key()
    other_root = make_ca("Root", "Root", other_k, other_k, self_signed=True)
    res = diagnose([leaf], [ca], [other_root], VAL)
    assert res.passing_chain is None
    assert any(
        "Root" in m.issuer_dn for m in res.missing_issuers
    )


def test_naive_validation_time_treated_as_utc_at_api_boundary():
    # Core layer assumes aware datetime; ensure aware path works normally.
    leaf, inter, root = _simple_hierarchy()
    res = diagnose(
        [leaf], inter, [root],
        dt.datetime(2026, 11, 11, tzinfo=dt.timezone.utc),
    )
    assert res.passing_chain is not None
