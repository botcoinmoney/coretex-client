# SPDX-License-Identifier: Apache-2.0
"""Coordinator-shaped signed-receipt hash semantics (distinct eval vs candidate roots)."""
from __future__ import annotations

import pytest

from coretex_validator import replay


EVAL = "e" * 64
RELEASE = "a" * 64


def test_production_shaped_receipt_binds_two_distinct_roots(monkeypatch):
    monkeypatch.setattr(replay.evaluation, "eval_report_hash", lambda _artifact: EVAL)
    artifact = {"candidate": {"release_root": RELEASE}}
    receipt = {"evalReportHash": "0x" + EVAL, "artifactHash": "0x" + RELEASE}
    replay.check_signed_evaluation_addresses(receipt, artifact, chain_eval_report_hash=EVAL)


def test_identical_eval_hashes_fail_when_candidate_root_differs(monkeypatch):
    monkeypatch.setattr(replay.evaluation, "eval_report_hash", lambda _artifact: EVAL)
    artifact = {"candidate": {"release_root": RELEASE}}
    receipt = {"evalReportHash": EVAL, "artifactHash": EVAL}
    with pytest.raises(replay.ReplayError, match="EVALUATION_ADDRESS_MISMATCH"):
        replay.check_signed_evaluation_addresses(receipt, artifact)


def test_eval_report_hash_must_address_the_evaluation_artifact(monkeypatch):
    monkeypatch.setattr(replay.evaluation, "eval_report_hash", lambda _artifact: EVAL)
    artifact = {"candidate": {"release_root": RELEASE}}
    receipt = {"evalReportHash": "b" * 64, "artifactHash": RELEASE}
    with pytest.raises(replay.ReplayError, match="EVALUATION_ADDRESS_MISMATCH"):
        replay.check_signed_evaluation_addresses(receipt, artifact)


def test_chain_eval_report_hash_must_match_the_artifact(monkeypatch):
    monkeypatch.setattr(replay.evaluation, "eval_report_hash", lambda _artifact: EVAL)
    artifact = {"candidate": {"release_root": RELEASE}}
    receipt = {"evalReportHash": EVAL, "artifactHash": RELEASE}
    with pytest.raises(replay.ReplayError, match="EVALUATION_ADDRESS_MISMATCH"):
        replay.check_signed_evaluation_addresses(
            receipt, artifact, chain_eval_report_hash="c" * 64)


def test_receipt_binding_for_signing_uses_candidate_release(monkeypatch):
    from coretex_validator import eval_artifact as ea
    artifact = {
        "candidate": {"release_root": RELEASE},
        "receipt": {"eval_report_root": "b" * 64},
        "verdict": {"admit": True},
    }
    monkeypatch.setattr(ea, "validate_artifact", lambda _artifact: None)
    monkeypatch.setattr(ea, "artifact_law", lambda _artifact: None)
    monkeypatch.setattr(ea, "eval_report_hash", lambda _artifact: EVAL)
    binding = ea.receipt_binding_for_signing(artifact)
    assert binding["evalReportHash"] == EVAL
    assert binding["artifactHash"] == RELEASE
    assert binding["evalReportHash"] != binding["artifactHash"]
