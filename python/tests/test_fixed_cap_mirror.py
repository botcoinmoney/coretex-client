from __future__ import annotations

import copy

import pytest

from coretex_validator import benchmark_replay
from coretex_validator import canonical_suite as cs
from coretex_validator import eval_artifact as ea


PROFILE = "doc.tool.v1"
PARENT_ROOT = "4" * 64
SOURCE_ROOT = "5" * 64


def _witness():
    return ea.build_determinism_witness(
        profile_id=PROFILE,
        release_root=PARENT_ROOT,
        source_kind="genesis",
        source_root=SOURCE_ROOT,
        partitions={label: cs.genesis_floor_vector(PROFILE, label)
                    for label in ea.SELECTION_LABELS},
    )


def test_suite_declares_eighteen_explicit_product_caps_above_genesis_usage():
    observed = []
    for profile_id in sorted(cs.canonical_suite()["profiles"]):
        for label in ea.SELECTION_LABELS:
            vector = cs.genesis_floor_vector(profile_id, label)
            cap = cs.fixed_product_cap(profile_id, label)
            for axis, measured_key, cap_key in cs.PRODUCT_CAP_VECTOR_FIELDS:
                observed.append(cap[axis])
                assert cap[axis] == vector[cap_key]
                assert cap[axis] > vector[measured_key]
    assert len(observed) == 18


def _accounting_side(vector: dict) -> dict:
    return {
        "composite_micro": vector["composite_micro"],
        "rendered_cost_micro": vector["rendered_cost_micro"],
        "work_fuel": vector["work_fuel"],
        "logical_durable_storage_bytes": vector["logical_durable_storage_bytes"],
    }


def test_counter_accounting_is_fixed_cap_normalized_and_zero_safe():
    law = ea.load_counter_resource_law()
    assert law["resource_normalizer"] == ea.FIXED_CAP_RESOURCE_NORMALIZER
    parent = copy.deepcopy(cs.genesis_floor_vector(PROFILE, "confirm"))
    candidate = copy.deepcopy(parent)
    for _axis, measured_key, cap_key in cs.PRODUCT_CAP_VECTOR_FIELDS:
        parent[measured_key] = 0
        candidate[measured_key] = candidate[cap_key]
    accounting = ea.evaluate_counter_resource_law(
        law, _accounting_side(candidate), _accounting_side(parent), profile_id=PROFILE,
        candidate_vector=candidate, incumbent_vector=parent)
    assert accounting["resource_before_ppm"] == 0
    assert accounting["resource_after_ppm"] == ea.MICRO


def test_counter_accounting_rejects_legacy_law_and_forged_cap():
    law = ea.load_counter_resource_law()
    legacy = copy.deepcopy(law)
    legacy.pop("resource_normalizer")
    with pytest.raises(ea.ArtifactSchemaError, match="resource_normalizer"):
        ea.validate_counter_resource_law(legacy)

    parent = copy.deepcopy(cs.genesis_floor_vector(PROFILE, "confirm"))
    candidate = copy.deepcopy(parent)
    candidate["envelope_work_fuel"] += 1
    with pytest.raises(ea.ResourceAccountingError, match="canonical fixed product cap"):
        ea.evaluate_counter_resource_law(
            law, _accounting_side(candidate), _accounting_side(parent), profile_id=PROFILE,
            candidate_vector=candidate, incumbent_vector=parent)


@pytest.mark.parametrize("mutation, error, match", [
    (lambda value: value.pop("source_root"), ea.ArtifactSchemaError, "missing"),
    (lambda value: value.update(profile_id="conv.pref.v1"),
     ea.ArtifactSchemaError, "target profile"),
    (lambda value: value.update(release_root="6" * 64),
     ea.DeterminismWitnessMismatchError, "exact parent release"),
    (lambda value: value["partitions"]["gate"].pop("work_fuel"),
     ea.ArtifactSchemaError, "missing"),
])
def test_parent_stored_vector_is_complete_and_exactly_bound(mutation, error, match):
    witness = _witness()
    mutation(witness)
    if "witness_root" in witness:
        witness["witness_root"] = ea.witness_root(witness)
    with pytest.raises(error, match=match):
        ea.validate_parent_stored_vector(
            witness, expected_profile_id=PROFILE, expected_release_root=PARENT_ROOT)


def test_parent_stored_vector_must_self_address_and_carry_canonical_cap():
    witness = _witness()
    witness["partitions"]["confirm"]["work_fuel"] += 1
    with pytest.raises(ea.ArtifactSchemaError, match="canonical body"):
        ea.validate_parent_stored_vector(
            witness, expected_profile_id=PROFILE, expected_release_root=PARENT_ROOT)

    witness = _witness()
    witness["partitions"]["confirm"]["envelope_work_fuel"] += 1
    witness["witness_root"] = ea.witness_root(witness)
    with pytest.raises(ea.ArtifactSchemaError, match="fixed product cap"):
        ea.validate_parent_stored_vector(
            witness, expected_profile_id=PROFILE, expected_release_root=PARENT_ROOT)


def _partition(label: str, *, admit: bool, spend: bool = False) -> dict:
    incumbent = cs.genesis_floor_vector(PROFILE, label)
    candidate = copy.deepcopy(incumbent)
    if admit:
        candidate["composite_micro"] += 100  # exactly one existing rounded ppm
    if spend:
        candidate["work_fuel"] += 1
        assert candidate["work_fuel"] <= candidate["envelope_work_fuel"]
    before = incumbent["composite_micro"] // 100
    after = candidate["composite_micro"] // 100
    result = {
        "admit": admit,
        "candidate_vector": candidate,
        "composite_after_ppm": after,
        "composite_before_ppm": before,
        "composite_gain_ppm": after - before,
        "floor_regressions": [],
        "hard": {"validity": True},
        "hard_ok": True,
        "incumbent_vector": copy.deepcopy(incumbent),
        "regressed_objectives": [],
        "regressed_resource_axes": [],
    }
    if admit:
        result.update(admission_gain_ppm=after - before, progress_class="quality")
    return result


def _artifact(gate_admit: bool, confirm_admit: bool, *, spend: bool = False) -> dict:
    final_admit = gate_admit and confirm_admit
    parts = {
        "gate": _partition("gate", admit=gate_admit, spend=spend and gate_admit),
        "confirm": _partition("confirm", admit=confirm_admit,
                              spend=spend and confirm_admit),
    }
    projection = {"score_before_ppm": 0}
    if final_admit:
        projection = {
            "class": parts["confirm"]["progress_class"],
            "score_after_ppm": parts["confirm"]["admission_gain_ppm"],
            "score_before_ppm": 0,
        }
    return {
        "admission_projection": projection,
        "candidate": {"target_profile": PROFILE},
        "dominance": {
            "admit": final_admit,
            "engine": ea.DOMINANCE_ENGINE_ID,
            "partitions": parts,
        },
        "genesis_floor": {
            "partitions": {label: cs.genesis_floor_vector(PROFILE, label)
                           for label in ea.SELECTION_LABELS},
        },
    }


@pytest.mark.parametrize("gate_admit, confirm_admit", [
    (True, False), (False, True), (False, False), (True, True),
])
def test_final_projection_is_confirm_only_on_final_admit(gate_admit, confirm_admit):
    artifact = _artifact(gate_admit, confirm_admit)
    assert ea.verify_dominance_block(artifact)["admit"] is (gate_admit and confirm_admit)
    if not (gate_admit and confirm_admit):
        assert artifact["admission_projection"] == {"score_before_ppm": 0}


@pytest.mark.parametrize("projection", [
    {"score_before_ppm": 1},
    {"score_before_ppm": 0, "score_after_ppm": 1, "class": "quality"},
    {"score_before_ppm": 0, "class": "efficiency"},
])
def test_tampered_final_reject_projection_is_refused(projection):
    artifact = _artifact(True, False)
    artifact["admission_projection"] = projection
    with pytest.raises(ea.VerdictMismatchError, match="canonical reject"):
        ea.verify_dominance_block(artifact)


def test_quality_may_spend_parent_resources_inside_unchanged_cap():
    artifact = _artifact(True, True, spend=True)
    ea.verify_dominance_block(artifact)
    for label in ea.SELECTION_LABELS:
        part = artifact["dominance"]["partitions"][label]
        assert part["candidate_vector"]["work_fuel"] \
            > part["incumbent_vector"]["work_fuel"]
        assert part["candidate_vector"]["envelope_work_fuel"] \
            == part["incumbent_vector"]["envelope_work_fuel"]


@pytest.mark.parametrize("axis, measured_key, cap_key", cs.PRODUCT_CAP_VECTOR_FIELDS)
def test_quality_admits_at_each_exact_cap(axis, measured_key, cap_key):
    artifact = _artifact(True, True)
    for label in ea.SELECTION_LABELS:
        candidate = artifact["dominance"]["partitions"][label]["candidate_vector"]
        candidate[measured_key] = candidate[cap_key]
    assert ea.verify_dominance_block(artifact)["admit"] is True


@pytest.mark.parametrize("axis, measured_key, cap_key", cs.PRODUCT_CAP_VECTOR_FIELDS)
def test_each_cap_plus_one_is_a_canonical_reject(axis, measured_key, cap_key):
    artifact = _artifact(True, True)
    gate = artifact["dominance"]["partitions"]["gate"]
    gate["candidate_vector"][measured_key] = gate["candidate_vector"][cap_key] + 1
    gate["regressed_resource_axes"] = [axis]
    gate["admit"] = False
    gate.pop("admission_gain_ppm")
    gate.pop("progress_class")
    artifact["dominance"]["admit"] = False
    artifact["admission_projection"] = {"score_before_ppm": 0}
    assert ea.verify_dominance_block(artifact)["admit"] is False


def test_same_quality_componentwise_resource_drop_is_efficiency():
    artifact = _artifact(True, True)
    for label in ea.SELECTION_LABELS:
        part = artifact["dominance"]["partitions"][label]
        part["candidate_vector"]["composite_micro"] = \
            part["incumbent_vector"]["composite_micro"]
        part["candidate_vector"]["work_fuel"] = part["incumbent_vector"]["work_fuel"] - 1
        part["composite_after_ppm"] = part["composite_before_ppm"]
        part["composite_gain_ppm"] = 0
        part["progress_class"] = "efficiency"
        part["admission_gain_ppm"] = 1
    artifact["admission_projection"] = {
        "class": "efficiency", "score_after_ppm": 1, "score_before_ppm": 0,
    }
    assert ea.verify_dominance_block(artifact)["admit"] is True


def test_quality_gain_cannot_hide_a_declared_objective_regression():
    artifact = _artifact(True, True)
    objective = sorted(
        artifact["dominance"]["partitions"]["gate"]["candidate_vector"]
        ["objectives_micro"])[0]
    gate = artifact["dominance"]["partitions"]["gate"]
    gate["incumbent_vector"]["objectives_micro"][objective] += 10
    gate["candidate_vector"]["objectives_micro"][objective] += 9
    gate["regressed_objectives"] = [objective]
    gate["admit"] = False
    gate.pop("admission_gain_ppm")
    gate.pop("progress_class")
    artifact["dominance"]["admit"] = False
    artifact["admission_projection"] = {"score_before_ppm": 0}
    assert ea.verify_dominance_block(artifact)["admit"] is False


@pytest.mark.parametrize("side", ["incumbent_vector", "candidate_vector"])
def test_forged_parent_or_candidate_envelope_is_refused(side):
    artifact = _artifact(True, True)
    artifact["dominance"]["partitions"]["gate"][side]["envelope_work_fuel"] += 1
    with pytest.raises(ea.VerdictMismatchError, match="fixed product cap"):
        ea.verify_dominance_block(artifact)


def test_benchmark_runner_refuses_bad_parent_before_starting_child(monkeypatch):
    runner = object.__new__(benchmark_replay.ReleaseBenchmarkRunner)
    monkeypatch.setattr(
        runner, "_run",
        lambda _payload: pytest.fail("malformed parent vector reached benchmark child"))
    with pytest.raises(benchmark_replay.BenchmarkReplayError, match="complete exact-parent"):
        runner.replay_report(
            {"profile_id": PROFILE}, expected_root="7" * 64,
            incumbent_execution={"release_root": PARENT_ROOT},
            parent_stored_vector={"partitions": {}},
        )


def test_final_reject_is_stopped_at_the_signing_boundary(monkeypatch):
    artifact = {"verdict": {"admit": False}}
    monkeypatch.setattr(ea, "validate_artifact", lambda _artifact: None)
    monkeypatch.setattr(ea, "artifact_law", lambda _artifact: ea.FIXED_SUITE_LAW_ID)
    with pytest.raises(ea.PreSignError, match="REJECT"):
        ea.receipt_binding_for_signing(artifact)
