"""LAW §3A.3 parity: the client's artifact recompute over the ONE shared fixed-cap corpus.

``fixtures/coretex-fixed-cap-dominance-vectors.json`` is a byte copy of the coordinator corpus
(``coretex.fixed-cap-dominance-parity/v3``, 39 vectors) that the sealed benchmark-v2 engine, the
V5 evaluator, the TypeScript mirror and this client all consume.  The corpus states vector KINDS;
building the artifacts needs the sealed engine, which the standalone client intentionally does
not ship.  ``fixtures/coretex-fixed-cap-dominance-parity.materialized.json`` therefore carries the
exact artifacts the coordinator driver (``project_decisions``) produced from that corpus, keyed
to the corpus sha256 and the suite root, so this package stays self-contained while asserting
the identical verdict on every vector: ``verify_dominance_block`` must accept exactly the
artifacts the corpus calls valid, agree on the admit bit, and reject the rest fail-closed.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from coretex_validator import canonical_suite as cs
from coretex_validator import eval_artifact as ea


FIXTURES = Path(__file__).with_name("fixtures")
CORPUS = FIXTURES / "coretex-fixed-cap-dominance-vectors.json"
MATERIALIZED = FIXTURES / "coretex-fixed-cap-dominance-parity.materialized.json"
CORPUS_FORMAT = "coretex.fixed-cap-dominance-parity/v3"
MATERIALIZED_FORMAT = "coretex.fixed-cap-dominance-parity.materialized/v1"
CORPUS_VECTOR_COUNT = 39


def _load():
    corpus_raw = CORPUS.read_bytes()
    corpus = json.loads(corpus_raw)
    materialized = json.loads(MATERIALIZED.read_text(encoding="utf-8"))
    return corpus_raw, corpus, materialized


def test_materialized_fixture_is_bound_to_the_corpus_the_law_and_the_packaged_suite():
    corpus_raw, corpus, materialized = _load()
    assert corpus["format"] == CORPUS_FORMAT
    assert materialized["format"] == MATERIALIZED_FORMAT
    assert materialized["source"]["corpus_sha256"] == hashlib.sha256(corpus_raw).hexdigest()
    assert materialized["source"]["corpus_format"] == CORPUS_FORMAT
    assert materialized["law_id"] == ea.FIXED_SUITE_LAW_ID == cs.suite_law_id()
    assert materialized["engine"] == ea.DOMINANCE_ENGINE_ID
    assert materialized["trade_constants"] == {
        "QUALITY_DIP_TOLERANCE_MICRO": ea.QUALITY_DIP_TOLERANCE_MICRO,
        "QUALITY_DIP_PAYMENT_RATIO": ea.QUALITY_DIP_PAYMENT_RATIO,
    }
    # The artifacts were projected against the SAME suite bytes this wheel carries.
    assert materialized["suite_root"] == cs.suite_root()
    corpus_ids = [vector["id"] for vector in corpus["vectors"]]
    assert len(corpus_ids) == CORPUS_VECTOR_COUNT == len(set(corpus_ids))
    assert [item["id"] for item in materialized["vectors"]] == corpus_ids
    by_id = {vector["id"]: vector for vector in corpus["vectors"]}
    for item in materialized["vectors"]:
        source = by_id[item["id"]]
        assert item["expected"] == source["expected"], item["id"]
        assert item["profile_id"] == source["profile_id"], item["id"]
        artifact = item["artifact"]
        assert artifact["dominance"]["engine"] == ea.DOMINANCE_ENGINE_ID, item["id"]
        assert artifact["suite"]["law_id"] == ea.FIXED_SUITE_LAW_ID, item["id"]
        assert artifact["suite"]["suite_root"] == cs.suite_root(), item["id"]
        for label in ea.SELECTION_LABELS:
            assert artifact["genesis_floor"]["partitions"][label] \
                == cs.genesis_floor_vector(item["profile_id"], label), (item["id"], label)


def _verify_or_error(artifact: dict) -> dict:
    """The driver's ``verify_or_error`` seam: schema-validate both stored vectors, then
    recompute."""
    try:
        profile_id = artifact["candidate"]["target_profile"]
        for label in ea.SELECTION_LABELS:
            part = artifact["dominance"]["partitions"][label]
            ea._validate_vector(  # noqa: SLF001 - the independent schema seam under test
                part["candidate_vector"], f"dominance.{label}.candidate_vector", profile_id)
            ea._validate_vector(  # noqa: SLF001
                part["incumbent_vector"], f"dominance.{label}.incumbent_vector", profile_id)
        result = ea.verify_dominance_block(copy.deepcopy(artifact))
        return {"ok": True, "admit": bool(result["admit"])}
    except Exception as exc:  # noqa: BLE001 - fail-closed is the shared contract, not the class
        return {"ok": False, "error": type(exc).__name__, "message": str(exc)}


def _vectors():
    _raw, _corpus, materialized = _load()
    return [pytest.param(item, id=item["id"]) for item in materialized["vectors"]]


@pytest.mark.parametrize("item", _vectors())
def test_client_recompute_matches_the_corpus_verdict(item):
    expected = item["expected"]
    outcome = _verify_or_error(item["artifact"])
    assert outcome["ok"] is expected["artifact_valid"], (item["id"], outcome)
    if expected["artifact_valid"]:
        assert outcome["admit"] is expected["admit"], item["id"]
        block = item["artifact"]["dominance"]
        for label in ea.SELECTION_LABELS:
            part = block["partitions"][label]
            assert part["admit"] is expected[f"{label}_admit"], (item["id"], label)
            if expected[f"{label}_admit"]:
                assert part["progress_class"] == expected[f"{label}_class"], (item["id"], label)
                assert part["admission_gain_ppm"] \
                    == expected[f"{label}_admission_gain_ppm"], (item["id"], label)


def _flip_admit_bit(artifact: dict) -> dict:
    tampered = copy.deepcopy(artifact)
    block = tampered["dominance"]
    flipped = not block["admit"]
    block["admit"] = flipped
    for label in ea.SELECTION_LABELS:
        part = block["partitions"][label]
        part["admit"] = flipped
        if flipped:
            part.setdefault("progress_class", "quality")
            part.setdefault("admission_gain_ppm", 1)
        else:
            part.pop("progress_class", None)
            part.pop("admission_gain_ppm", None)
    tampered["admission_projection"] = (
        {"class": block["partitions"]["confirm"]["progress_class"],
         "score_after_ppm": block["partitions"]["confirm"]["admission_gain_ppm"],
         "score_before_ppm": 0}
        if flipped else {"score_before_ppm": 0})
    return tampered


@pytest.mark.parametrize("item", [
    param for param in _vectors() if param.values[0]["expected"]["artifact_valid"]])
def test_flipped_verdict_on_a_valid_corpus_artifact_is_refused(item):
    """The recompute is a verdict check, not a schema check: every valid artifact with its
    admit bit inverted (each partition + final projection) must be a VerdictMismatchError."""
    with pytest.raises(ea.VerdictMismatchError):
        ea.verify_dominance_block(_flip_admit_bit(item["artifact"]))


def test_bounded_trade_boundaries_are_present_in_the_corpus():
    """The corpus must exercise every rule-2 boundary the law names (SPEC parity list)."""
    _raw, corpus, _materialized = _load()
    kinds = {vector[label]["kind"] for vector in corpus["vectors"]
             for label in ea.SELECTION_LABELS}
    assert {
        "dip_at_tolerance_paid", "dip_over_tolerance_paid",
        "floor_minus_tolerance_paid", "floor_below_tolerance_paid",
        "trade_paid_exactly", "trade_underpaid_by_one",
        "two_dips_at_tolerance_paid", "efficiency_with_paid_dips",
        "quality_with_paid_dips_tie", "rounding_drop_with_paid_dips",
        "unpaid_dip_on_efficiency", "resource_uint64_max", "missing_objective",
    } <= kinds
