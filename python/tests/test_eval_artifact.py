# SPDX-License-Identifier: UNLICENSED
"""Cut V5-C — the canonical deterministic evaluation artifact.

Everything a confirmed ``CoreTexMemoryFrontierAdvanced`` event points at, proven to be bound:
the semantic candidate and BOTH transition hashes, the parent and proposed frontier roots, the
release and composition roots, the three epoch pins, the entropy commitment and its expansion,
the fresh selection, the signed deterministic receipt, the EXACT consumer-visible rendered cost,
the fuel/storage/resource evidence, the verdict, and the raw replay inputs.

Every mismatch must RAISE. A verification that returned ``False`` could be read as a pass by a
caller that forgot to look — the same reason ``frontier.verify_transition`` raises.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os

import pytest

import eval_artifact as ea
import frontier as fr
import publication as pub
from conftest import (EPOCH, NEW_RELEASE_ROOT, V5_DIR, make_artifact, make_parts,
                      publish_required, verify_kwargs)


@pytest.fixture()
def built():
    artifact, parts, store = make_artifact()
    return artifact, parts, store


def _tampered(artifact, path, value):
    """A deep copy with one field replaced. ``path`` is a dotted key path."""
    out = copy.deepcopy(dict(artifact))
    node = out
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value
    return out


def _permute(obj):
    """Rebuild every dict with its keys in REVERSED insertion order (values unchanged)."""
    if isinstance(obj, dict):
        return {k: _permute(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [_permute(v) for v in obj]
    return obj


# --------------------------------------------------------------------------- #
# round trip + canonical hash
# --------------------------------------------------------------------------- #
def test_a_freshly_built_artifact_verifies(built):
    artifact, parts, _ = built
    report = ea.verify_artifact(artifact, **verify_kwargs(artifact, parts))
    assert report["ok"] is True
    assert report["eval_report_hash"] == ea.eval_report_hash(artifact)
    assert "receipt_bindings" in report["checks"] and "selection_walk" in report["checks"]


def test_artifact_round_trips_through_canonical_bytes(built):
    artifact, parts, _ = built
    blob = ea.artifact_canonical_bytes(artifact)
    reparsed = fr.parse_json(blob.decode("utf-8"))
    assert reparsed == artifact
    assert ea.eval_report_hash(reparsed) == ea.eval_report_hash(artifact)
    assert ea.verify_artifact(reparsed, **verify_kwargs(reparsed, parts))["ok"] is True


def test_eval_report_hash_is_sha256_over_the_canonical_bytes(built):
    artifact, _, _ = built
    assert ea.eval_report_hash(artifact) == fr.sha256_hex(ea.artifact_canonical_bytes(artifact))


def test_canonical_hash_is_stable_under_key_order_permutation(built):
    """Same rule as V5-A: key order is a serialization detail, never identity."""
    artifact, _, _ = built
    permuted = _permute(artifact)
    assert list(permuted) != list(artifact)
    assert ea.eval_report_hash(permuted) == ea.eval_report_hash(artifact)


def test_uppercase_hex_is_rejected_not_lowered(built):
    """Case variance is refused exactly as in V5-A §4.2: normalizing would let two byte strings
    address one root, and 'fetch by root, rehash, compare' would stop working."""
    artifact, _, _ = built
    upper = _tampered(artifact, "frontier.parent_frontier_root",
                      artifact["frontier"]["parent_frontier_root"].upper())
    with pytest.raises(fr.FrontierValueError):
        ea.eval_report_hash(upper)


def test_zero_x_prefixed_root_is_rejected(built):
    artifact, _, _ = built
    prefixed = _tampered(artifact, "candidate.release_root", "0x" + NEW_RELEASE_ROOT[2:])
    with pytest.raises(fr.FrontierValueError):
        ea.validate_artifact(prefixed)


def test_an_invalid_artifact_has_no_hash_at_all(built):
    artifact, _, _ = built
    broken = copy.deepcopy(dict(artifact))
    del broken["entropy"]
    with pytest.raises(ea.ArtifactSchemaError):
        ea.eval_report_hash(broken)


def test_the_schema_is_closed(built):
    artifact, _, _ = built
    with pytest.raises(ea.ArtifactSchemaError):
        ea.validate_artifact(dict(artifact, extra_evidence={"x": 1}))


def test_entropy_accepts_only_complete_open_or_closed_sealed_shapes(built):
    artifact, _, _ = built
    sealed = copy.deepcopy(artifact)
    sealed["entropy"] = {
        key: value for key, value in artifact["entropy"].items()
        if key in ea.ENTROPY_SEALED_FIELDS
    }
    assert ea.validate_artifact(sealed) is sealed
    assert ea.eval_report_hash(sealed) == fr.sha256_hex(ea.artifact_canonical_bytes(sealed))

    partial = copy.deepcopy(sealed)
    partial["entropy"]["revealed_secret"] = artifact["entropy"]["revealed_secret"]
    with pytest.raises(ea.ArtifactSchemaError, match="complete historical open shape"):
        ea.validate_artifact(partial)


def test_a_sealed_artifact_needs_an_external_opening_for_binding_verification(built):
    artifact, parts, _ = built
    sealed = copy.deepcopy(artifact)
    sealed["entropy"] = {
        key: value for key, value in artifact["entropy"].items()
        if key in ea.ENTROPY_SEALED_FIELDS
    }
    kwargs = verify_kwargs(sealed, parts)
    with pytest.raises(ea.EntropyOpeningUnavailableError):
        ea.verify_artifact(sealed, **kwargs)
    report = ea.verify_artifact(
        sealed, revealed_entropy_secret=parts["secret"], **kwargs)
    assert report["ok"] is True
    assert "entropy_commitment" in report["checks"]


def test_floats_cannot_enter_the_artifact(built):
    artifact, _, _ = built
    with pytest.raises(fr.CanonicalizationError):
        ea.artifact_canonical_bytes(_tampered(artifact, "epoch", 7.0))


def test_null_is_not_a_value(built):
    artifact, _, _ = built
    with pytest.raises(fr.FrontierError):
        ea.validate_artifact(_tampered(artifact, "counter_resource_law_root", None))


def test_duplicate_keys_in_serialized_form_are_refused(built):
    artifact, _, _ = built
    blob = ea.artifact_canonical_bytes(artifact).decode("utf-8")
    doubled = blob.replace('"epoch":7', '"epoch":7,"epoch":8', 1)
    with pytest.raises(fr.DuplicateKeyError):
        fr.parse_json(doubled)


# --------------------------------------------------------------------------- #
# binding mismatches — each one must RAISE its own typed error
# --------------------------------------------------------------------------- #
def test_wrong_parent_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_parent_root="9" * 64)
    with pytest.raises(ea.ParentRootMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_new_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_new_root="9" * 64)
    with pytest.raises(ea.NewRootMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_a_tampered_new_root_fails_the_frontier_replay(built):
    """Consistent-looking but wrong: the transition applied to the parent does not produce it."""
    artifact, parts, _ = built
    bogus = "a9" * 32
    tampered = _tampered(artifact, "frontier.new_frontier_root", bogus)
    kwargs = dict(verify_kwargs(tampered, parts), expected_new_root=bogus)
    with pytest.raises(fr.RootMismatchError):
        ea.verify_artifact(tampered, **kwargs)


def test_wrong_release_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_release_root="9" * 64)
    with pytest.raises(ea.ReleaseRootMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_composition_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_composition_root="9" * 64)
    with pytest.raises(ea.CompositionRootMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_runtime_abi_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_runtime_abi_root="9" * 64)
    with pytest.raises(ea.EpochPinMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_benchmark_law_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_benchmark_law_root="9" * 64)
    with pytest.raises(ea.EpochPinMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_counter_resource_law_root_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts),
                  expected_counter_resource_law_root="9" * 64)
    with pytest.raises(ea.EpochPinMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_a_counter_law_that_does_not_hash_to_the_bound_root_is_rejected(built):
    artifact, parts, _ = built
    other = dict(parts["law"], branch="gate")
    kwargs = dict(verify_kwargs(artifact, parts), counter_resource_law=other)
    with pytest.raises(ea.EpochPinMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_epoch_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_epoch=EPOCH + 1)
    with pytest.raises(ea.EpochPinMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_target_profile_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_target_profile="conv.pref.v1")
    with pytest.raises(ea.BindingMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_wrong_entropy_commitment_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts), expected_entropy_commitment="9" * 64)
    with pytest.raises(ea.EntropyMismatchError):
        ea.verify_artifact(artifact, **kwargs)


def test_an_entropy_secret_that_does_not_open_the_commitment_is_rejected(built):
    artifact, parts, _ = built
    swapped = _tampered(artifact, "entropy.revealed_secret", "8" * 64)
    with pytest.raises(ea.EntropyMismatchError):
        ea.verify_artifact(swapped, **verify_kwargs(swapped, parts))


def test_a_restated_gate_entropy_is_rejected(built):
    """The scored instances must come from the CHAIN-COMMITTED entropy, not a chosen value."""
    artifact, parts, _ = built
    tampered = _tampered(artifact, "entropy.gate_value", "5c" * 32)
    with pytest.raises(ea.EntropyMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_tampered_transition_keccak_hash_is_rejected(built):
    """The 22nd signed receipt field: without it the broadcast bytes are unsigned."""
    artifact, parts, _ = built
    tampered = _tampered(artifact, "frontier.transition_hash_keccak256", "cc" * 32)
    with pytest.raises(ea.TransitionHashMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_tampered_transition_sha256_id_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "frontier.transition_id_sha256", "cd" * 32)
    with pytest.raises(ea.TransitionHashMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_the_two_transition_hashes_are_bound_separately(built):
    artifact, _, _ = built
    front = artifact["frontier"]
    assert front["transition_hash_keccak256"] != front["transition_id_sha256"]
    payload = ea.transition_bytes_for(artifact)
    assert front["transition_id_sha256"] == fr.sha256_hex(payload)
    assert front["transition_hash_keccak256"] == ea.transition_hash_keccak256(payload)
    assert front["transition_bytes_len"] == len(payload) <= fr.MAX_TRANSITION_BYTES == 384


def test_a_transition_that_does_not_match_the_candidate_block_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "candidate.release_root", "9c" * 32)
    kwargs = dict(verify_kwargs(tampered, parts), expected_release_root="9c" * 32)
    with pytest.raises(ea.ReleaseRootMismatchError):
        ea.verify_artifact(tampered, **kwargs)


def test_a_parent_manifest_that_does_not_hash_to_the_bound_parent_root_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "replay_inputs.parent_manifest",
                         dict(artifact["replay_inputs"]["parent_manifest"],
                              default_composition_root="7c" * 32))
    with pytest.raises(ea.ParentRootMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_stale_prior_release_root_is_rejected(built):
    """Off-chain twin of the contract's parent-root CAS: a candidate built against a superseded
    frontier. The transition's own hashes are RECOMPUTED so the artifact is internally
    consistent — only its relationship to the parent frontier is wrong, which is exactly the
    case a mere self-consistency check would wave through."""
    artifact, parts, _ = built
    tampered = copy.deepcopy(dict(artifact))
    tampered["candidate"]["prior_release_root"] = "7a" * 32
    transition = tampered["frontier"]["transition"]
    transition["expected_prior_release_root"] = "7a" * 32
    payload = fr.canonical_bytes(transition)
    tampered["frontier"]["transition_bytes_len"] = len(payload)
    tampered["frontier"]["transition_id_sha256"] = fr.sha256_hex(payload)
    tampered["frontier"]["transition_hash_keccak256"] = ea.transition_hash_keccak256(payload)
    with pytest.raises(ea.ReleaseRootMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


# --------------------------------------------------------------------------- #
# the fresh selection
# --------------------------------------------------------------------------- #
def test_the_selection_re_derives_from_the_committed_entropy(built):
    artifact, _, _ = built
    ids = ea.verify_selection_walk(artifact["selection"], entropy=artifact["entropy"],
                                   candidate_hash=artifact["candidate"]["candidate_hash"])
    assert set(ids) == set(ea.SELECTION_LABELS)


def test_a_fabricated_selection_case_is_rejected(built):
    """A case that never sat at its claimed index of the walk fails offline, right here."""
    artifact, parts, _ = built
    tampered = copy.deepcopy(dict(artifact))
    case = tampered["selection"]["cases"]["gate"][0]
    case["seed"] = (case["seed"] + 1) % (2 ** 31)
    case["instance_id"] = ea.instance_id(case["profile_id"], case["seed"], case["scale"])
    with pytest.raises(ea.SelectionMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_restated_selection_base_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "selection.base_sha256",
                         dict(artifact["selection"]["base_sha256"], gate="3a" * 32))
    with pytest.raises(ea.SelectionMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_non_monotone_derivation_indices_are_rejected(built):
    artifact, parts, _ = built
    tampered = copy.deepcopy(dict(artifact))
    cases = tampered["selection"]["cases"]["gate"]
    cases[0], cases[1] = cases[1], cases[0]
    with pytest.raises(ea.SelectionMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_overlapping_gate_and_confirmation_selections_are_rejected(built):
    artifact, _, _ = built
    selection = copy.deepcopy(dict(artifact["selection"]))
    selection["cases"]["confirm"] = list(selection["cases"]["gate"])
    with pytest.raises(ea.SelectionMismatchError):
        ea.verify_selection_walk(selection, entropy=artifact["entropy"],
                                 candidate_hash=artifact["candidate"]["candidate_hash"])


def test_a_selection_count_that_disagrees_with_the_cases_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "selection.counts",
                         dict(artifact["selection"]["counts"], gate=99))
    with pytest.raises(ea.SelectionMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_gate_and_confirm_entropies_are_independent(built):
    artifact, _, _ = built
    assert artifact["entropy"]["gate_value"] != artifact["entropy"]["confirm_value"]
    assert artifact["selection"]["base_sha256"]["gate"] != \
        artifact["selection"]["base_sha256"]["confirm"]


# --------------------------------------------------------------------------- #
# the deterministic receipt
# --------------------------------------------------------------------------- #
def test_verification_without_a_receipt_or_a_store_fails_closed(built):
    artifact, parts, _ = built
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("receipt_wrapper")
    with pytest.raises(ea.ReceiptUnavailableError):
        ea.verify_artifact(artifact, **kwargs)


def test_the_receipt_can_be_fetched_from_the_publication_surface(built):
    artifact, parts, store = built
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("receipt_wrapper")
    kwargs.pop("counter_resource_law")
    assert ea.verify_artifact(artifact, store=store, **kwargs)["ok"] is True


def test_a_receipt_with_a_broken_self_hash_is_rejected(built):
    artifact, parts, _ = built
    kwargs = dict(verify_kwargs(artifact, parts),
                  receipt_wrapper=dict(parts["wrapper"], receipt_hash="1f" * 32))
    with pytest.raises(ea.ReceiptBindingError):
        ea.verify_artifact(artifact, **kwargs)


def test_a_substituted_receipt_is_rejected(built):
    """A different-but-valid receipt does not hash to the bound wrapper root."""
    artifact, parts, _ = built
    other = make_parts(admit=False)
    kwargs = dict(verify_kwargs(artifact, parts), receipt_wrapper=other["wrapper"])
    with pytest.raises(ea.ReceiptBindingError):
        ea.verify_artifact(artifact, **kwargs)


def test_a_tampered_code_root_is_rejected(built):
    """The exact bytes that executed are bound; a scorer edit must fail closed."""
    artifact, parts, _ = built
    tampered = _tampered(artifact, "receipt.code_roots",
                         dict(artifact["receipt"]["code_roots"], scoring="ff" * 32))
    with pytest.raises(ea.ReceiptBindingError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_tampered_outputs_hash_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "receipt.outputs_hash", "ef" * 32)
    with pytest.raises(ea.ReceiptBindingError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_signature_verifier_is_honoured_when_supplied(built):
    artifact, parts, _ = built
    ok = ea.verify_artifact(artifact, signature_verifier=lambda w: True,
                            **verify_kwargs(artifact, parts))
    assert "receipt_signature" in ok["checks"]
    with pytest.raises(ea.ReceiptBindingError):
        ea.verify_artifact(artifact, signature_verifier=lambda w: False,
                           **verify_kwargs(artifact, parts))


def test_the_receipt_hash_rule_matches_the_benchmark_one():
    """``receipt_body_hash`` is reproduced, not imported (the V5 lane stays stdlib-only) — so it
    is asserted byte-identical to ``benchmark-v2/frontier/_canon.py`` loaded BY PATH, which keeps
    the two same-named ``frontier`` packages off one sys.path."""
    canon_path = os.path.join(os.path.dirname(V5_DIR), "benchmark-v2", "frontier", "_canon.py")
    if not os.path.exists(canon_path):
        pytest.skip("benchmark-v2 tree not present in this checkout")
    spec = importlib.util.spec_from_file_location("v5_probe_canon", canon_path)
    canon = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(canon)
    body = {"b": 2, "a": {"z": [1, 2], "y": 1.5}, "u": "é"}
    assert pub.benchmark_canonical_bytes(body) == canon.canonical_json(body).encode("utf-8")
    assert ea.receipt_body_hash(body) == canon.hash_obj(body)


# --------------------------------------------------------------------------- #
# measurements, rendered cost, resource accounting
# --------------------------------------------------------------------------- #
def test_rendered_cost_is_bound_exactly(built):
    artifact, parts, _ = built
    scores = parts["wrapper"]["receipt"]["scores"]["confirm"]
    bound = artifact["measurements"]["branches"]["confirm"]["candidate"]["rendered_cost_micro"]
    assert bound == ea.to_micro(scores["candidate"]["rendered_cost"], "x")
    assert bound == 880250000                                   # 880.25 render_cost.v2 tokens


def test_a_tampered_rendered_cost_is_rejected(built):
    artifact, parts, _ = built
    tampered = copy.deepcopy(dict(artifact))
    tampered["measurements"]["branches"]["confirm"]["candidate"]["rendered_cost_micro"] -= 1
    with pytest.raises(ea.RenderedCostMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_tampered_fuel_or_storage_evidence_is_rejected(built):
    artifact, parts, _ = built
    for field in ("work_fuel", "storage_bytes", "events_scanned", "store_ops", "compute_micro"):
        tampered = copy.deepcopy(dict(artifact))
        tampered["measurements"]["branches"]["gate"]["candidate"][field] += 1
        with pytest.raises(ea.ReceiptBindingError):
            ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_micro_projection_is_exact_and_never_rounds():
    assert ea.to_micro(880.25, "x") == 880250000
    assert ea.to_micro(0.000001, "x") == 1
    assert ea.to_micro(3, "x") == 3000000
    with pytest.raises(ea.MeasurementPrecisionError):
        ea.to_micro(0.0000001, "x")
    with pytest.raises(ea.MeasurementPrecisionError):
        ea.to_micro(float("nan"), "x")
    with pytest.raises(ea.ArtifactTypeError):
        ea.to_micro(True, "x")


def test_hook_fuel_absent_projects_to_zero_never_to_absent(built):
    """The schema is closed, so 'absent' must not become a second way to say zero."""
    artifact, _, _ = built
    incumbent = artifact["measurements"]["branches"]["gate"]["incumbent"]
    candidate = artifact["measurements"]["branches"]["gate"]["candidate"]
    assert incumbent["hook_fuel"] == 0 and candidate["hook_fuel"] == 6000


def test_resource_accounting_recomputes_under_the_pinned_law(built):
    artifact, parts, _ = built
    branch = parts["law"]["branch"]
    recomputed = ea.evaluate_counter_resource_law(
        parts["law"], artifact["measurements"]["branches"][branch]["candidate"],
        artifact["measurements"]["branches"][branch]["incumbent"])
    assert {k: artifact["resource_accounting"][k] for k in recomputed} == recomputed
    assert artifact["resource_accounting"]["resource_before_ppm"] == 1_000_000


def test_tampered_resource_accounting_is_rejected(built):
    artifact, parts, _ = built
    for field in ("utility_after_ppm", "resource_after_ppm", "utility_before_ppm",
                  "resource_before_ppm"):
        tampered = copy.deepcopy(dict(artifact))
        tampered["resource_accounting"][field] += 1
        with pytest.raises(ea.ResourceAccountingError):
            ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_the_committed_counter_law_file_is_the_bound_root(built):
    artifact, _, _ = built
    law = ea.load_counter_resource_law()
    path = ea.COUNTER_RESOURCE_LAW_PATH
    with open(path, "rb") as fh:
        raw = fh.read()
    assert raw == fr.canonical_bytes(law)              # the file IS its canonical bytes
    assert fr.sha256_hex(raw) == ea.counter_resource_law_root(law)
    assert artifact["counter_resource_law_root"] == ea.counter_resource_law_root(law)


def test_counter_law_weights_must_sum_to_one_million():
    law = ea.load_counter_resource_law()
    broken = copy.deepcopy(law)
    broken["resource_axes"][0]["weight_ppm"] += 1
    with pytest.raises(ea.CounterResourceLawError):
        ea.validate_counter_resource_law(broken)


def test_candidate_reported_compute_is_diagnostic_not_admission_authority():
    law = ea.load_counter_resource_law()
    broken = copy.deepcopy(law)
    broken["resource_axes"][1]["source"] = "resource.hook_compute_fuel"
    with pytest.raises(ea.CounterResourceLawError, match="not an admission authority"):
        ea.validate_counter_resource_law(broken)

    broken = copy.deepcopy(law)
    broken["utility_axis"]["source"] = "compute_micro"
    with pytest.raises(ea.CounterResourceLawError, match="diagnostic"):
        ea.validate_counter_resource_law(broken)


def test_counter_law_refuses_a_zero_incumbent_baseline(built):
    artifact, parts, _ = built
    branch = parts["law"]["branch"]
    incumbent = dict(artifact["measurements"]["branches"][branch]["incumbent"], work_fuel=0)
    with pytest.raises(ea.CounterResourceLawError):
        ea.evaluate_counter_resource_law(
            parts["law"], artifact["measurements"]["branches"][branch]["candidate"], incumbent)


def test_the_incumbent_side_is_exactly_one_million_ppm_by_construction(built):
    artifact, parts, _ = built
    branch = parts["law"]["branch"]
    side = artifact["measurements"]["branches"][branch]["incumbent"]
    assert ea.evaluate_counter_resource_law(parts["law"], side, side)["resource_after_ppm"] == \
        1_000_000


# --------------------------------------------------------------------------- #
# the verdict
# --------------------------------------------------------------------------- #
def test_a_tampered_verdict_is_rejected(built):
    artifact, parts, _ = built
    flipped = copy.deepcopy(dict(artifact))
    flipped["verdict"]["admit"] = False
    flipped["verdict"]["verdict"] = "REJECT"
    with pytest.raises(ea.VerdictMismatchError):
        ea.verify_artifact(flipped, **verify_kwargs(flipped, parts))


def test_an_internally_inconsistent_verdict_is_rejected(built):
    artifact, _, _ = built
    with pytest.raises(ea.VerdictMismatchError):
        ea.validate_artifact(_tampered(artifact, "verdict",
                                       dict(artifact["verdict"], verdict="REJECT")))


def test_a_tampered_decision_hash_is_rejected(built):
    artifact, parts, _ = built
    tampered = _tampered(artifact, "verdict",
                         dict(artifact["verdict"], decision_hash="7f" * 32))
    with pytest.raises(ea.VerdictMismatchError):
        ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))


def test_a_reject_verdict_builds_and_verifies_too():
    artifact, parts, _ = make_artifact(admit=False)
    assert artifact["verdict"] == dict(artifact["verdict"], admit=False, verdict="REJECT")
    assert ea.verify_artifact(artifact, **verify_kwargs(artifact, parts))["ok"] is True


def test_the_verdict_must_declare_itself_consensus_critical(built):
    artifact, _, _ = built
    with pytest.raises(ea.ArtifactValueError):
        ea.validate_artifact(_tampered(artifact, "verdict",
                                       dict(artifact["verdict"], consensus_critical=False)))


def test_verify_artifact_never_returns_false(built):
    """Every failure path RAISES; there is no falsy return an inattentive caller could read as a
    pass (the ``frontier.verify_transition`` discipline)."""
    artifact, parts, _ = built
    for path, value in (("frontier.parent_frontier_root", "9" * 64),
                        ("candidate.candidate_hash", "9" * 64),
                        ("receipt.receipt_hash", "9" * 64),
                        ("selection.season_root", "9" * 64)):
        tampered = _tampered(artifact, path, value)
        with pytest.raises((ea.EvalArtifactError, fr.FrontierError)) as exc:
            result = ea.verify_artifact(tampered, **verify_kwargs(tampered, parts))
            assert result is not False                 # unreachable; documents the contract
        assert exc.value is not None


# --------------------------------------------------------------------------- #
# the PRE-SIGN availability gate
# --------------------------------------------------------------------------- #
def test_pre_sign_returns_the_broadcastable_receipt_fields(built):
    artifact, parts, store = built
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("expected_parent_root")
    kwargs.pop("expected_new_root")
    out = ea.prepare_broadcastable_receipt(
        artifact, store=store, expected_parent_root=parts["parent_root"],
        expected_new_root=parts["new_root"], **kwargs)
    assert out["broadcastable"] is True
    assert out["eval_report_hash"] == ea.eval_report_hash(artifact)
    assert out["transition_hash"] == artifact["frontier"]["transition_hash_keccak256"]
    assert set(out["available"]) == set(ea.REQUIRED_AVAILABILITY)
    # the artifact itself is now fetchable by its evalReportHash
    assert pub.fetch_json(out["eval_report_hash"], hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                          store=store) == artifact


def test_pre_sign_refuses_when_a_required_object_was_never_published():
    parts = make_parts()
    store = pub.InMemoryCAS()
    availability = publish_required(parts, store)
    availability.pop("candidate_bundle")
    artifact = ea.build_artifact(
        epoch=parts["epoch"], parent_manifest=parts["parent"], transition=parts["transition"],
        candidate_hash=parts["candidate_hash"], receipt_wrapper=parts["wrapper"],
        revealed_entropy_secret=parts["secret"], counter_resource_law=parts["law"],
        availability=availability)
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("expected_parent_root")
    kwargs.pop("expected_new_root")
    with pytest.raises(ea.PreSignError):
        ea.prepare_broadcastable_receipt(
            artifact, store=store, expected_parent_root=parts["parent_root"],
            expected_new_root=parts["new_root"], **kwargs)


def test_pre_sign_refuses_when_the_surface_loses_an_object(built):
    artifact, parts, store = built
    del store._objects[artifact["availability"]["receipt_wrapper"]["root"]]
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("expected_parent_root")
    kwargs.pop("expected_new_root")
    with pytest.raises(ea.PreSignError):
        ea.prepare_broadcastable_receipt(
            artifact, store=store, expected_parent_root=parts["parent_root"],
            expected_new_root=parts["new_root"], **kwargs)


def test_pre_sign_refuses_when_the_surface_serves_different_bytes(built):
    artifact, parts, store = built
    root = artifact["availability"]["parent_frontier_manifest"]["root"]
    store._objects[root] = fr.canonical_bytes({"tampered": True})
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("expected_parent_root")
    kwargs.pop("expected_new_root")
    with pytest.raises(ea.PreSignError):
        ea.prepare_broadcastable_receipt(
            artifact, store=store, expected_parent_root=parts["parent_root"],
            expected_new_root=parts["new_root"], **kwargs)


def test_pre_sign_refuses_a_deterministically_invalid_artifact(built):
    artifact, parts, store = built
    tampered = _tampered(artifact, "receipt.outputs_hash", "ee" * 32)
    kwargs = verify_kwargs(tampered, parts)
    kwargs.pop("expected_parent_root")
    kwargs.pop("expected_new_root")
    with pytest.raises(ea.ReceiptBindingError):
        ea.prepare_broadcastable_receipt(
            tampered, store=store, expected_parent_root=parts["parent_root"],
            expected_new_root=parts["new_root"], **kwargs)


def test_publish_artifact_reads_the_artifact_back(built):
    artifact, _, _ = built
    store = pub.InMemoryCAS()
    root = ea.publish_artifact(artifact, store=store)
    assert root == ea.eval_report_hash(artifact)
    assert pub.read_back(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                         store=store) == ea.artifact_canonical_bytes(artifact)


# --------------------------------------------------------------------------- #
# replay inputs
# --------------------------------------------------------------------------- #
def test_the_artifact_carries_every_raw_replay_input(built):
    """A validator gets the parent manifest inline, the transition inline, and a root for every
    object it must fetch — with no coordinator-private data anywhere."""
    artifact, parts, _ = built
    replay = artifact["replay_inputs"]
    assert fr.frontier_root(replay["parent_manifest"]) == parts["parent_root"]
    assert fr.validate_transition(artifact["frontier"]["transition"])
    assert set(ea.REQUIRED_AVAILABILITY) <= set(artifact["availability"])
    assert replay["incumbent"]["candidate_hash"] == ea.NO_CHAMPION      # reference incumbent
    assert replay["incumbent"]["exec"] == "reference"


def test_a_reference_incumbent_is_rendered_as_the_zero_sentinel_never_null(built):
    artifact, parts, _ = built
    assert parts["wrapper"]["receipt"]["incumbent"]["candidate_hash"] is None
    assert artifact["replay_inputs"]["incumbent"]["candidate_hash"] == "0" * 64
    fr.canonical_bytes(artifact)                        # would have raised on a null


def test_transition_bytes_for_matches_what_the_miner_broadcasts(built):
    artifact, _, _ = built
    payload = ea.transition_bytes_for(artifact)
    assert fr.parse_transition_bytes(payload) == artifact["frontier"]["transition"]


def test_artifact_json_is_never_the_addressed_form(built):
    artifact, _, _ = built
    pretty = ea.artifact_json(artifact, indent=1)
    assert json.loads(pretty) == artifact
    assert pretty.encode("utf-8") != ea.artifact_canonical_bytes(artifact)
