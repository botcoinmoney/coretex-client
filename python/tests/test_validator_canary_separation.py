# SPDX-License-Identifier: UNLICENSED
"""Cut V5-E — HAIKU / EXTERNAL-MODEL EVIDENCE IS REPORTED SEPARATELY.

§17.236, binding: the deterministic Benchmark-v2 result is the SOLE mining admission and
state-advance law; the external-model canary is AUXILIARY coordinator sanity evidence
(``external_model_attestation: true``, ``consensus_critical: false``), it "creates no promotion
eligibility and MUST NOT silently deny a deterministically earned promotion".

The property under test is therefore an INDEPENDENCE property, and the only honest way to test it
is to vary the canary across its whole range — absent, passing, failing, unfetchable, wrongly
bound, sealed under a foreign scorer — and assert the deterministic verdict, outcome, code and
check list are the SAME every time. A test that only checked "the flags say false" would pass on
an implementation that reads the canary anyway.
"""
from __future__ import annotations

import copy

import pytest

import eval_artifact as ea
import publication as pub
from validator import backlog as bl
from validator import replay as rp

from conftest import make_sealed_transcript
from validator_fixtures import Scenario


def scenario_with_canary(verdict="PASS", **overrides):
    """A scenario whose artifact carries a sealed canary block with ``verdict``."""
    base = Scenario()
    sealed = make_sealed_transcript(base.artifact, verdict=verdict, **overrides)
    block = ea.build_canary_block(sealed)
    withc = Scenario(canary=block)
    sealed = make_sealed_transcript(withc.artifact, verdict=verdict, **overrides)
    block = ea.build_canary_block(sealed)
    final = Scenario(canary=block)
    sealed = make_sealed_transcript(final.artifact, verdict=verdict, **overrides)
    pub.publish_and_read_back(sealed, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=final.store)
    return final, sealed


@pytest.fixture()
def plain():
    return Scenario()


# --------------------------------------------------------------------------- #
# the invariant
# --------------------------------------------------------------------------- #
def test_a_passing_canary_does_not_change_the_verdict(plain):
    withc, _sealed = scenario_with_canary("PASS")
    a, b = plain.replay(), withc.replay()
    assert a.outcome is b.outcome is bl.PASS
    assert a.verdict_fingerprint() == b.verdict_fingerprint()


def test_a_failing_canary_does_not_deny_a_deterministically_earned_promotion(plain):
    withc, _sealed = scenario_with_canary("FAIL")
    a, b = plain.replay(), withc.replay()
    assert b.outcome is bl.PASS
    assert a.verdict_fingerprint() == b.verdict_fingerprint()
    assert b.auxiliary["ok"] is False
    assert b.auxiliary["code"] == "canary_failed"
    assert "never an opaque candidate-specific consensus gate" in b.auxiliary["authority"]


def test_an_absent_canary_yields_the_identical_verdict(plain):
    withc, _sealed = scenario_with_canary("PASS")
    a, b = plain.replay(), withc.replay()
    assert a.verdict_fingerprint() == b.verdict_fingerprint()
    assert a.auxiliary["present"] is False and b.auxiliary["present"] is True
    assert a.auxiliary["ok"] is True and a.auxiliary["code"] == "no_canary"


def test_an_unfetchable_transcript_does_not_change_the_verdict():
    withc, sealed = scenario_with_canary("PASS")
    root = ea.canary_transcript_root(sealed)
    withc.store._objects.pop(root)                     # the transcript is simply not there
    result = withc.replay()
    assert result.outcome is bl.PASS
    assert result.auxiliary["ok"] is False
    assert result.auxiliary["code"] == "transcript_unavailable"


def test_a_transcript_sealed_under_a_foreign_scorer_does_not_change_the_verdict():
    withc, _sealed = scenario_with_canary("PASS")
    result = withc.replay(expected_canary_code_identity={
        "format": "benchmark-v2/canary/code-identity/v1",
        "scorer_version": "canary-scorer.v4",          # the corrected build: a DISTINCT identity
        "scoring.py_sha256": "50" * 32, "questions.py_sha256": "51" * 32})
    assert result.outcome is bl.PASS
    assert result.auxiliary["ok"] is False
    assert result.auxiliary["code"] == "code_identity_foreign"
    assert result.auxiliary["differences"]


def test_the_verdict_fingerprint_ignores_the_auxiliary_block(plain):
    a = plain.replay()
    b = plain.replay()
    b.auxiliary = {"anything": "at all"}
    assert a.verdict_fingerprint() == b.verdict_fingerprint()


def test_a_canary_adds_exactly_one_evidence_step_and_no_decision(plain):
    """The ONLY thing a canary changes about the deterministic record: V5-C runs its
    canary-isolation assertion, which is evidence that separation held."""
    withc, _sealed = scenario_with_canary("FAIL")
    a, b = plain.replay(), withc.replay()
    assert set(b.checks) - set(a.checks) == {"artifact:canary_isolation"}
    assert set(a.checks) - set(b.checks) == set()
    assert a.verdict_fingerprint() == b.verdict_fingerprint()


@pytest.mark.parametrize("verdict", ["PASS", "FAIL", "DEGRADED", "UNKNOWN"])
def test_every_canary_verdict_yields_one_deterministic_verdict(verdict, plain):
    withc, _sealed = scenario_with_canary(verdict)
    assert withc.replay().verdict_fingerprint() == plain.replay().verdict_fingerprint()


# --------------------------------------------------------------------------- #
# the auxiliary block's own shape
# --------------------------------------------------------------------------- #
def test_the_auxiliary_block_declares_itself_non_consensus(plain):
    aux = plain.replay().auxiliary
    assert aux["consensus_critical"] is False
    assert aux["external_model_attestation"] is True
    assert aux["may_change_verdict"] is False


def test_the_auxiliary_block_verifies_the_transcript_hash_and_bindings():
    withc, _sealed = scenario_with_canary("PASS")
    aux = withc.replay().auxiliary
    assert aux["ok"] is True
    assert aux["canary_verdict"] == "PASS"
    assert aux["deterministic_verdict"]["verdict"] == "ADMIT"


def test_a_tampered_transcript_is_caught_by_its_own_root():
    withc, sealed = scenario_with_canary("PASS")
    root = ea.canary_transcript_root(sealed)
    tampered = copy.deepcopy(sealed)
    tampered["run_id"] = "someone-elses-run"
    withc.store._objects[root] = pub.benchmark_canonical_bytes(tampered)
    result = withc.replay()
    assert result.outcome is bl.PASS
    assert result.auxiliary["ok"] is False
    assert result.auxiliary["code"] in ("transcript_root_mismatch", "transcript_unavailable")


def test_a_canary_bound_to_another_candidate_is_reported_not_enforced():
    withc, sealed = scenario_with_canary("PASS")
    root = ea.canary_transcript_root(sealed)
    foreign = copy.deepcopy(sealed)
    foreign["candidate_hash"] = "b" * 64
    withc.store._objects[root] = pub.benchmark_canonical_bytes(foreign)
    result = withc.replay()
    assert result.outcome is bl.PASS
    assert result.auxiliary["ok"] is False


def test_a_canary_claiming_consensus_authority_is_refused_outright():
    # verify_artifact refuses the block before it is ever addressable, so such an artifact cannot
    # exist on the surface at all — the refusal is structural, not a downgrade.
    base = Scenario()
    sealed = make_sealed_transcript(base.artifact)
    block = dict(ea.build_canary_block(sealed), consensus_critical=True)
    with pytest.raises(ea.CanaryConsensusError):
        ea.validate_canary_block(block)


def test_the_canary_evidence_helper_never_raises_for_a_canary_failure():
    withc, sealed = scenario_with_canary("FAIL")
    aux = rp.canary_evidence(withc.artifact, store=withc.store, sealed_transcript=sealed)
    assert aux["ok"] is False and aux["consensus_critical"] is False


def test_canary_evidence_carries_the_canary_free_deterministic_verdict():
    withc, sealed = scenario_with_canary("FAIL")
    aux = rp.canary_evidence(withc.artifact, store=withc.store, sealed_transcript=sealed)
    assert aux["deterministic_verdict"] == ea.deterministic_verdict(
        ea.strip_canary(withc.artifact))


# --------------------------------------------------------------------------- #
# the canary cannot rescue a deterministic failure either
# --------------------------------------------------------------------------- #
def test_a_passing_canary_cannot_rescue_a_rejected_candidate():
    base = Scenario(admit=False)
    sealed = make_sealed_transcript(base.artifact, verdict="PASS")
    block = ea.build_canary_block(sealed)
    rejected = Scenario(admit=False, canary=block)
    sealed = make_sealed_transcript(rejected.artifact, verdict="PASS")
    final = Scenario(admit=False, canary=ea.build_canary_block(sealed))
    result = final.replay()
    assert result.outcome is bl.FAIL and result.code == "not_admitted"


def test_a_passing_canary_cannot_rescue_a_broken_binding(plain):
    withc, _sealed = scenario_with_canary("PASS")
    result = withc.replay(pins=withc.resolver(entropy_commitment="0" * 63 + "9"))
    assert result.outcome is bl.FAIL


# --------------------------------------------------------------------------- #
# separation is asserted, not assumed
# --------------------------------------------------------------------------- #
def test_replay_asserts_the_separation_defensively(monkeypatch, plain):
    """If a future edit ever let the canary reach a deterministic check, replay must blow up."""
    calls = {"n": 0}
    real = ea.deterministic_verdict

    def drifting(artifact):
        calls["n"] += 1
        out = real(artifact)
        if calls["n"] > 1:                             # the post-auxiliary re-derivation
            return dict(out, verdict="SOMETHING ELSE")
        return out

    monkeypatch.setattr(ea, "deterministic_verdict", drifting)
    with pytest.raises(ea.CanaryInfluenceError, match="separation has been broken"):
        plain.replay()


def test_the_deterministic_stages_read_a_canary_free_artifact(plain):
    """Structural: the verdict the incumbent law reads is derived from strip_canary()."""
    withc, _sealed = scenario_with_canary("FAIL")
    result = withc.replay()
    assert result.detail["verdict"] == ea.deterministic_verdict(
        ea.strip_canary(withc.artifact))


def test_the_artifact_hash_differs_with_and_without_a_canary_but_the_verdict_does_not(plain):
    """The canary IS inside the artifact's canonical bytes — so it moves evalReportHash, and
    must still not move the verdict. Both halves matter."""
    withc, _sealed = scenario_with_canary("PASS")
    assert withc.eval_report_hash != plain.eval_report_hash
    assert withc.replay().detail["verdict"] == plain.replay().detail["verdict"]
