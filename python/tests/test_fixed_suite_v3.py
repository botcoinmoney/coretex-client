# SPDX-License-Identifier: Apache-2.0
"""The fixed-suite (v4) era, against a REAL minted artifact.

WHY THE FIXTURE IS A REAL ONE. Every check here could be made to pass on a synthesised artifact,
and several of them would then be checking the synthesiser. `v3-cas/` holds the objects a real
`eval.candidate.v2` job published — the artifact, the evaluation report it addresses, the parent
frontier manifest, the release and composition manifests, the counter-resource law and the
transition artifact — copied verbatim out of the evaluator's own content-addressed store. The one
object added beside them is the published bridge-vector document the artifact's determinism witness
names, which is what makes the stored parent vector provenance rather than a number.

The three suites the P9 checklist asks for are here: STRIPPED-SUITE REFUSAL, OFFLINE DETERMINISM
(two runs, identical hashes) and the era-aware `worldSeed` recomputation, plus the aggregate
resource non-regression the public law promised and the replayer did not enforce.
"""
from __future__ import annotations

import copy
import json
import os

import pytest

from coretex_validator import canonical_suite as cs
from coretex_validator import eval_artifact as ea
from coretex_validator import frontier as fr
from coretex_validator import publication as pub
from coretex_validator import replay as rp

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CAS = os.path.join(FIXTURES, "v3-cas")
BRIDGE = os.path.join(FIXTURES, "bridge-vector.event.schema.genesis.json")

ARTIFACT_ROOT = "b56b8d24307f3448d5c434e84d299e271aa694f5f43592f8481b9f73acb5f3c7"
REPORT_ROOT = "869feaf443d599b0c49be95645c6d3a1ae6eb14096db923b3a1486fb3e15d591"
WITNESS_SOURCE_ROOT = "60dc89e29888ef34de7f4eff617cb4edb8472a7469a34bf10cb2219b9aa2730b"
SUITE_ROOT = "dbb6582dca25d466c6eda4a0c5d30bf29437f74068531a7ee272b9a6462c410e"

#: The rehearsal opening the shadow run committed to. `world_seed` is a pure function of it, and
#: the fixture's signed value is what the coordinator's own derivation predicted independently.
REHEARSAL_SECRET = "7" * 64
EXPECTED_WORLD_SEED = 153161973798012115915136293741110411803


def _store():
    store = pub.InMemoryCAS()
    for name in sorted(os.listdir(CAS)):
        with open(os.path.join(CAS, name), "rb") as fh:
            store.put(name, fh.read())
    return store


def _publish_bridge(store):
    with open(BRIDGE, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    pub.publish_item(document, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    return document


@pytest.fixture()
def artifact():
    with open(os.path.join(CAS, ARTIFACT_ROOT), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _verify(artifact, store, **overrides):
    front = artifact["frontier"]
    cand = artifact["candidate"]
    kwargs = {
        "expected_parent_root": front["parent_frontier_root"],
        "expected_new_root": front["new_frontier_root"],
        "expected_release_root": cand["release_root"],
        "expected_composition_root": front["composition_root"],
        "expected_runtime_abi_root": front["runtime_abi_root"],
        "expected_benchmark_law_root": front["benchmark_law_root"],
        "expected_counter_resource_law_root": artifact["counter_resource_law_root"],
        "expected_entropy_commitment": None,
        "expected_epoch": artifact["epoch"],
        "expected_target_profile": cand["target_profile"],
        "store": store,
        "resolve_witness_source": True,
        # The parent is constructor genesis (epoch 0) and this advance re-pinned the law, so the
        # inherited parent carries the PRE-CUT pins. That is the re-anchored path, and supplying
        # the independently verified epoch pins is how a validator says so.
        "epoch_pins": {"benchmark_law_root": front["benchmark_law_root"],
                       "runtime_abi_root": front["runtime_abi_root"]},
    }
    kwargs.update(overrides)
    return ea.verify_artifact(artifact, **kwargs)


# --------------------------------------------------------------------------- #
# 1. the honest artifact verifies, end to end, from published bytes only
# --------------------------------------------------------------------------- #
def test_a_real_v3_artifact_verifies_from_clean_public_objects(artifact):
    store = _store()
    _publish_bridge(store)
    report = _verify(artifact, store)

    # the era-specific steps ran, by name — a v3 artifact that quietly took the walk-era path
    # would still "pass" and would have proved nothing about the suite
    for check in ("suite_membership", "genesis_floor", "dominance", "dominance_report_binding",
                  "determinism_witness", "fixed_round_identity", "decided_vectors_are_measured",
                  "determinism_witness_source"):
        assert check in report["checks"], check
    # and the walk-era steps did NOT
    assert "entropy_commitment" not in report["checks"]
    assert "selection_walk" not in report["checks"]

    assert report["witness_provenance"]["resolved"] is True
    assert report["witness_provenance"]["source_kind"] == "bridge"
    assert report["witness_provenance"]["source_root"] == WITNESS_SOURCE_ROOT
    assert ea.deterministic_verdict(artifact)["verdict"] == "ADMIT"


def test_the_artifact_rehashes_to_the_eval_report_hash_the_chain_names(artifact):
    assert ea.eval_report_hash(artifact) == ARTIFACT_ROOT
    assert artifact["suite"]["suite_root"] == SUITE_ROOT == cs.suite_root()


# --------------------------------------------------------------------------- #
# 2. OFFLINE DETERMINISM — two runs, identical hashes
# --------------------------------------------------------------------------- #
def test_two_independent_verifications_produce_identical_hashes_and_reports(artifact):
    """Nothing outside the bytes may influence the outcome — not the store instance, not the
    order objects were published in, not a second copy of the artifact."""
    first_store = _store()
    _publish_bridge(first_store)
    first = _verify(copy.deepcopy(artifact), first_store)

    second_store = _store()
    _publish_bridge(second_store)
    second = _verify(copy.deepcopy(artifact), second_store)

    assert first["checks"] == second["checks"]
    assert first["witness_provenance"] == second["witness_provenance"]
    assert fr.canonical_bytes(first) == fr.canonical_bytes(second)
    assert ea.eval_report_hash(artifact) == ARTIFACT_ROOT
    assert ea.witness_root(artifact["determinism_witness"]) \
        == artifact["determinism_witness"]["witness_root"]


def test_the_uint128_world_seed_survives_a_json_round_trip_exactly(artifact):
    """The trap that cost the integration gate a run: `world_seed` is a uint128, and a reader that
    widens it to a float loses it silently. Python's `int` is exact, and the canonical encoder
    REFUSES a float — so the round trip is byte-identical or it raises."""
    seed = artifact["rig_receipt"]["world_seed"]
    assert isinstance(seed, int) and not isinstance(seed, bool)
    assert seed > 2 ** 53                              # beyond exact IEEE-754 integer range
    reparsed = fr.parse_json(fr.canonical_bytes(artifact).decode("utf-8"))
    assert reparsed["rig_receipt"]["world_seed"] == seed
    assert fr.canonical_bytes(reparsed) == fr.canonical_bytes(artifact)

    widened = copy.deepcopy(artifact)
    widened["rig_receipt"]["world_seed"] = float(seed)
    with pytest.raises(fr.FrontierError):
        fr.canonical_bytes(widened)


# --------------------------------------------------------------------------- #
# 3. STRIPPED-SUITE REFUSAL
# --------------------------------------------------------------------------- #
def test_a_stripped_suite_partition_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["gate"] = doctored["suite"]["cases"]["gate"][:-1]
    with pytest.raises(ea.EvalArtifactError):
        ea.validate_artifact(doctored)


def test_a_stripped_suite_partition_whose_count_was_restated_is_still_refused(artifact):
    """The interesting one: make the artifact internally consistent about the theft. It is the
    LAW's counts that decide, so restating them does not buy a smaller exam."""
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["gate"] = doctored["suite"]["cases"]["gate"][:-1]
    doctored["suite"]["counts"]["gate"] = len(doctored["suite"]["cases"]["gate"])
    with pytest.raises(ea.SuiteMembershipError) as exc:
        ea.verify_suite_membership(doctored)
    assert "never" in str(exc.value) and "subsetted" in str(exc.value)


def test_a_substituted_suite_case_is_refused_even_at_the_right_length(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["confirm"][0]["seed"] += 1
    with pytest.raises(ea.SuiteMembershipError):
        ea.verify_suite_membership(doctored)


def test_a_case_scored_on_a_different_instance_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["confirm"][0]["instance_hash"] = "a" * 64
    with pytest.raises(ea.SuiteMembershipError) as exc:
        ea.verify_suite_membership(doctored)
    assert "not the case the law names" in str(exc.value)


def test_an_artifact_naming_another_suite_is_a_mismatch_not_a_variation(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["suite_root"] = "b" * 64
    with pytest.raises(ea.SuiteMembershipError) as exc:
        ea.verify_suite_membership(doctored)
    assert "NEW LAW" in str(exc.value)


def test_a_doctored_genesis_floor_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["genesis_floor"]["partitions"]["gate"]["composite_micro"] -= 1
    with pytest.raises(ea.BindingMismatchError):
        ea.verify_genesis_floor(doctored)


def test_a_restated_floor_provenance_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["genesis_floor"]["source"] = "measured by someone, somewhere"
    with pytest.raises(ea.BindingMismatchError) as exc:
        ea.verify_genesis_floor(doctored)
    assert "provenance of the floor is part of the floor" in str(exc.value)


def test_a_doctored_determinism_witness_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["determinism_witness"]["partitions"]["confirm"]["composite_micro"] += 1
    doctored["determinism_witness"]["witness_root"] = ea.witness_root(
        doctored["determinism_witness"])
    with pytest.raises(ea.DeterminismWitnessMismatchError):
        ea.validate_artifact(doctored)


# --------------------------------------------------------------------------- #
# 4. witness provenance — unpublished BACKLOGs, substituted MISMATCHes
# --------------------------------------------------------------------------- #
def test_an_unpublished_witness_source_is_unavailable_not_a_pass(artifact):
    store = _store()                                   # bridge deliberately NOT published
    with pytest.raises(ea.WitnessSourceUnavailableError):
        _verify(artifact, store)


def test_verification_without_a_resolver_reports_unresolved_rather_than_silence(artifact):
    store = _store()
    report = _verify(artifact, store, resolve_witness_source=False)
    provenance = report["witness_provenance"]
    assert provenance["resolved"] is False
    assert provenance["source_root"] == WITNESS_SOURCE_ROOT
    assert "not fetched" in provenance["reason"]
    assert "determinism_witness_source" not in report["checks"]


def test_a_different_valid_bridge_document_at_the_witness_address_is_a_mismatch(artifact):
    store = _store()
    document = _publish_bridge(store)
    hostile = copy.deepcopy(document)
    hostile["partitions"]["gate"]["composite_micro"] += 1
    # SERVED AT the honest address: the substitution a hostile publication surface would attempt.
    store.put(WITNESS_SOURCE_ROOT, pub.encode(hostile, pub.HASH_RULE_FRONTIER_JSON))
    with pytest.raises(ea.WitnessSourceMismatchError):
        _verify(artifact, store)


# --------------------------------------------------------------------------- #
# 5. ERA-AWARE worldSeed
# --------------------------------------------------------------------------- #
def test_the_signed_world_seed_recomputes_from_the_revealed_secret(artifact):
    result = ea.verify_world_seed(artifact, revealed_secret=REHEARSAL_SECRET)
    assert result == {"checked": True, "world_seed": EXPECTED_WORLD_SEED}
    assert artifact["rig_receipt"]["world_seed"] == EXPECTED_WORLD_SEED
    assert ea.derive_world_seed(
        revealed_secret=REHEARSAL_SECRET, epoch=artifact["epoch"],
        parent_frontier_root=artifact["frontier"]["parent_frontier_root"]) == EXPECTED_WORLD_SEED


def test_a_world_seed_that_is_not_the_committed_secrets_expansion_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["rig_receipt"]["world_seed"] += 1
    with pytest.raises(ea.WorldSeedMismatchError) as exc:
        ea.verify_world_seed(doctored, revealed_secret=REHEARSAL_SECRET)
    assert "function of the committed secret" in str(exc.value)


def test_a_different_epoch_secret_does_not_open_this_receipts_seed(artifact):
    with pytest.raises(ea.WorldSeedMismatchError):
        ea.verify_world_seed(artifact, revealed_secret="8" * 64)


def test_an_artifact_with_no_rig_receipt_reports_nothing_to_check(artifact):
    without = {k: v for k, v in artifact.items() if k != "rig_receipt"}
    assert ea.verify_world_seed(without, revealed_secret=REHEARSAL_SECRET)["checked"] is False


# --------------------------------------------------------------------------- #
# 6. AGGREGATE RESOURCE NON-REGRESSION — the rule the public law promised
# --------------------------------------------------------------------------- #
def _parent_identity(artifact):
    """The exact parent execution, taken from the artifact's own resolved incumbent block.

    `_beat_incumbent` re-resolves this from public bytes when it is given a store; these tests
    are about the ARITHMETIC that follows, so the identity is supplied and the resolution is
    covered where it belongs, in the replay tests.
    """
    incumbent = dict(artifact["replay_inputs"]["incumbent"])
    return {"exec": incumbent["exec"], "id": incumbent["id"],
            "candidate_hash": incumbent["candidate_hash"],
            "release_root": incumbent["release_root"],
            "module": {"sha256": incumbent["module_sha256"]}}


def _accounting(**overrides):
    block = {"branch": "confirm", "utility_before_ppm": 667762, "utility_after_ppm": 721537,
             "resource_before_ppm": 1_000_000, "resource_after_ppm": 948_520}
    block.update(overrides)
    return block


def test_the_replayer_refuses_an_advance_that_spends_more_to_score_more(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["resource_accounting"] = _accounting(resource_after_ppm=1_000_001)
    outcome = rp._beat_incumbent(
        doctored, doctored["replay_inputs"]["parent_manifest"],
        doctored["candidate"]["target_profile"], doctored["resource_accounting"],
        ea.deterministic_verdict(doctored),
        resolved_parent_execution=_parent_identity(doctored), store=None)
    assert outcome["code"] == "resource_regression"
    assert "no aggregate resource regression" in outcome["reason"]


def test_the_honest_accounting_passes_the_same_check(artifact):
    outcome = rp._beat_incumbent(
        artifact, artifact["replay_inputs"]["parent_manifest"],
        artifact["candidate"]["target_profile"], artifact["resource_accounting"],
        ea.deterministic_verdict(artifact),
        resolved_parent_execution=_parent_identity(artifact), store=None)
    assert outcome["code"] is None
    report = outcome["report"]
    assert report["resource_after_ppm"] <= report["resource_before_ppm"]
    # the v3 summary a reader needs to see WHY it admitted
    assert report["dominance"]["engine"] == ea.DOMINANCE_ENGINE_ID
    for label in ("gate", "confirm"):
        part = report["dominance"]["partitions"][label]
        assert part["admit"] is True
        assert part["regressed_objectives"] == []
        assert part["regressed_resource_axes"] == []
        assert part["floor_regressions"] == []
    assert report["genesis_floor"]["status"] == "resolved"


# --------------------------------------------------------------------------- #
# 7. the eras are not cross-satisfiable
# --------------------------------------------------------------------------- #
def test_a_v3_artifact_presented_as_v2_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["format"] = ea.ARTIFACT_FORMAT
    with pytest.raises(ea.EvalArtifactError):
        ea.validate_artifact(doctored)


def test_a_v3_artifact_that_grew_an_entropy_block_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["entropy"] = {"commitment": "a" * 64, "commitment_scheme": "x",
                           "derivation_domain": ea.ENTROPY_DOMAIN}
    with pytest.raises(ea.EvalArtifactError):
        ea.validate_artifact(doctored)


def test_a_v3_artifact_may_not_be_checked_against_an_entropy_commitment(artifact):
    store = _store()
    _publish_bridge(store)
    with pytest.raises(ea.EntropyMismatchError) as exc:
        _verify(artifact, store, expected_entropy_commitment="c" * 64)
    assert "binds no entropy" in str(exc.value)
