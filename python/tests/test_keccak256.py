# SPDX-License-Identifier: UNLICENSED
"""Cut V5-C — the stdlib Keccak-256 the on-chain bindings need.

Two values in a V5 receipt are computed with Ethereum's ``keccak256``: the signed
``transitionHash`` and the epoch ``entropyCommitment``. A validator must be able to check both
with nothing but the stdlib, so the primitive is proven here against PUBLISHED vectors before
anything is built on it.
"""
from __future__ import annotations

import hashlib

import pytest

import eval_artifact as ea
import frontier as fr
import keccak256 as kc


def test_published_known_answer_vectors():
    for data, expected in kc.KNOWN_ANSWERS:
        assert kc.keccak256_hex(data) == expected


def test_multi_block_regression_vectors():
    """Inputs at and beyond the 136-byte rate absorb two blocks."""
    for data, expected in kc.REGRESSION_ANSWERS:
        assert len(data) >= kc.RATE_BYTES
        assert kc.keccak256_hex(data) == expected


def test_self_test_runs_every_vector():
    assert kc.self_test() is True


def test_keccak256_is_not_sha3_256():
    """The padding byte differs (0x01 vs 0x06), so the two disagree on EVERY input. Confusing
    them would silently produce a transitionHash no contract would ever accept."""
    for data, _ in kc.KNOWN_ANSWERS:
        assert kc.keccak256_hex(data) != hashlib.sha3_256(data).hexdigest()


def test_digest_is_bare_lowercase_hex():
    assert fr.check_root(kc.keccak256_hex(b"anything"), "digest")


def test_non_bytes_input_is_refused():
    with pytest.raises(TypeError):
        kc.keccak256("a string")                       # type: ignore[arg-type]


def test_transition_hash_uses_the_contract_domain_label():
    """``keccak256(abi.encodePacked(TRANSITION_HASH_DOMAIN_LABEL, transitionBytes))``."""
    payload = fr.transition_bytes(
        target_profile="doc.tool.v1", expected_prior_release_root="b" * 64,
        new_release_root="d" * 64, resulting_composition_root="4" * 64)
    assert ea.transition_hash_keccak256(payload) == kc.keccak256_hex(
        b"coretex-memory-transition-hash-v1" + payload)


def test_transition_hash_is_not_the_v5a_transition_id():
    """Different algorithm, different preimage, different purpose — never interchangeable."""
    transition = fr.make_transition(
        target_profile="doc.tool.v1", expected_prior_release_root="b" * 64,
        new_release_root="d" * 64, resulting_composition_root="4" * 64)
    payload = fr.canonical_bytes(transition)
    assert ea.transition_hash_keccak256(payload) != fr.transition_hash(transition)
    assert fr.transition_hash(transition) == fr.sha256_hex(payload)


def test_transition_hash_refuses_an_oversized_payload():
    """The 384-byte bound is the V5-A decoder bound AND both V5-B contracts' bound."""
    assert fr.MAX_TRANSITION_BYTES == 384
    with pytest.raises(fr.TransitionSizeError):
        ea.transition_hash_keccak256(b"x" * (fr.MAX_TRANSITION_BYTES + 1))


def test_entropy_commitment_opens_the_chain_commitment():
    """``epochCommit = keccak256(abi.encodePacked(bytes32 secret))`` — checkable offline."""
    secret = "7" * 64
    assert ea.entropy_commitment_of(secret) == kc.keccak256_hex(bytes.fromhex(secret))
    assert ea.entropy_commitment_of(secret) != ea.entropy_commitment_of("8" * 64)


def test_entropy_commitment_rejects_a_malformed_secret():
    with pytest.raises(fr.FrontierValueError):
        ea.entropy_commitment_of("0x" + "7" * 62)
    with pytest.raises(fr.FrontierValueError):
        ea.entropy_commitment_of("A" * 64)
