# SPDX-License-Identifier: Apache-2.0
"""Thin-client reconstruction of genesis -> efficiency -> prior_accept on the law-v2 fixtures.

``fixtures/law-v2-two-transition.json`` holds byte copies (base64) of the sealed final-cut
evidence, each with its source path and sha256: every CAS object the two evaluation artifacts
address, the genesis baseline the first determinism witness names, and the epoch context both
transitions were pinned to.  Nothing else is consulted — no release directory, no chain, no worker
result.  The
client fetches each object by its content address, verifies the efficiency artifact and then the
second-generation ``prior_accept`` artifact under the v2 fixed-suite law (``verify_dominance_block``
recomputes the componentwise verdict from the bound vectors; ``verify_artifact`` binds every field
to the chain-side roots), requires the second witness to resolve to the first artifact's stored
vector, and replays both transition artifacts from the genesis manifest to the two frontier roots.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from coretex_validator import dispatch
from coretex_validator import eval_artifact as ea
from coretex_validator import frontier
from coretex_validator import publication as pub
from coretex_validator import rig_events


FIXTURE = Path(__file__).with_name("fixtures") / "law-v2-two-transition.json"
FIXTURE_FORMAT = "coretex.law-v2-two-transition-fixture/v1"
LAW_V2 = "benchmark-v2-law/dominance-fixed-suite.v2"
ENGINE_V2 = "dominance.componentwise.v2"
PROFILE = "doc.tool.v1"
GENESIS_ROOT = "dd95d466ccc8dbfae3bf587c42a0584e04fe84511f142b7dacaa88335e82daf7"
GENESIS_BASELINE_ROOT = "aa1299b9ee629fdbe35501c12f5fba3a37a41fb4267db95890923a2c887820af"
EFFICIENCY_EVAL_ROOT = "3d20fcb0827b43996a70e2d03ffb7d6ffeef05bdd85ab783ce487944a0086368"
EFFICIENCY_FRONTIER_ROOT = "380adf083060b3deb6a0134e2ae1e8493c4d04e77b15c26a4bc1621770c00f8c"
PRIOR_ACCEPT_EVAL_ROOT = "2434c29502bf48e1f39c432f25f794028f36649c69007df914535f01d5b2c4a4"
PRIOR_ACCEPT_FRONTIER_ROOT = "e08c6386bfecc193f9eb5d645691f6affc75500a993740def2e29adb3495385f"
EPOCH_CONTEXT_ROOT = "9ec4339f938004304069c4f676e05a1f986298f6c534ef58609e7aad5b8691a4"
COMPATIBILITY_LOCK_ROOT = "6aa30482ab15128e643f82d7b283d0e0432a3b6840f48c6a78156321f3a85694"
EXPECTED_CHECKS = [
    "chain_roots", "transition_identity", "frontier_replay", "suite_membership", "genesis_floor",
    "dominance", "dominance_report_binding", "determinism_witness", "fixed_round_identity",
    "receipt_bindings", "measurements", "decided_vectors_are_measured", "counter_resource_law",
    "verdict", "rig_receipt_fields", "determinism_witness_source", "availability",
]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_fixture():
    """The closed inventory: every copied byte must still match its recorded digest."""
    index = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert index["format"] == FIXTURE_FORMAT
    store = pub.InMemoryCAS()
    for root, record in index["cas_objects"].items():
        raw = base64.b64decode(record["base64"], validate=True)
        assert len(raw) == record["bytes"] and _sha256(raw) == record["sha256"], root
        assert record["sources"], root
        store.put(root, raw)
    context_record = index["epoch_context"]
    context_raw = base64.b64decode(context_record["base64"], validate=True)
    assert len(context_raw) == context_record["bytes"]
    assert _sha256(context_raw) == context_record["sha256"]
    context = json.loads(context_raw)
    return index, store, context


def _fetch(store, item):
    return pub.fetch_json(item["root"], hash_rule=item["hash_rule"], store=store,
                          expected_bytes_len=item["bytes"])


def _epoch_pins(context):
    """Pin 3 recomputed from the fetched context bytes, never taken from an artifact."""
    root = dispatch.epoch_context_root(context)
    assert root == EPOCH_CONTEXT_ROOT
    return {
        "benchmark_law_root": context["benchmark_law_root"],
        "epoch": context["epoch"],
        "epoch_context_root": root,
        "runtime_abi_root": context["runtime_abi_root"],
    }


def _verify_and_replay(store, context, pins, current, eval_root):
    """Verify one artifact against the CURRENT frontier and replay its transition on top of it."""
    artifact = pub.fetch_json(eval_root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    assert ea.eval_report_hash(artifact) == eval_root
    assert ea.artifact_law(artifact) == LAW_V2
    assert artifact["suite"]["law_id"] == LAW_V2
    assert artifact["determinism_witness"]["law_id"] == LAW_V2
    assert artifact["dominance"]["engine"] == ENGINE_V2
    assert ea.verify_dominance_block(artifact) == {"engine": ENGINE_V2, "admit": True}
    assert artifact["verdict"]["admit"] is True
    assert artifact["candidate"]["target_profile"] == PROFILE

    availability = artifact["availability"]
    resulting = _fetch(store, availability["resulting_frontier_manifest"])
    parent_root = frontier.frontier_root(current)
    resulting_root = frontier.frontier_root(resulting)
    # The parent the artifact claims must be the frontier we actually arrived at.
    assert artifact["candidate"]["prior_release_root"] == current["profiles"][PROFILE]
    report = ea.verify_artifact(
        artifact,
        expected_parent_root=parent_root,
        expected_new_root=resulting_root,
        expected_release_root=resulting["profiles"][PROFILE],
        expected_composition_root=resulting["default_composition_root"],
        expected_runtime_abi_root=context["runtime_abi_root"],
        expected_benchmark_law_root=context["benchmark_law_root"],
        expected_counter_resource_law_root=context["counter_resource_law_root"],
        expected_epoch=context["epoch"],
        expected_target_profile=PROFILE,
        store=store,
        check_availability=True,
        require_rig_receipt=True,
        expected_epoch_context_root=pins["epoch_context_root"],
        expected_core_version_hash=COMPATIBILITY_LOCK_ROOT,
        resolve_witness_source=True,
    )
    assert report["ok"] is True
    assert report["law_id"] == LAW_V2
    assert report["checks"] == EXPECTED_CHECKS
    assert report["witness_provenance"]["resolved"] is True

    # The descriptor a receipt would carry, built from the addressed roots (no receipt is in the
    # fixture) and re-read by the same decoder the chain join uses.
    transition_item = availability["transition_artifact"]
    transition_raw = pub.read_back(
        transition_item["root"], hash_rule=transition_item["hash_rule"], store=store,
        expected_bytes_len=transition_item["bytes"])
    descriptor_bytes = dispatch.encode_transition_descriptor(
        patch_artifact_hash=transition_item["root"], parent_state_root=parent_root,
        new_state_root=resulting_root)
    descriptor = dispatch.decode_transition_descriptor(
        descriptor_bytes, parent_state_root=parent_root, new_state_root=resulting_root,
        expected_patch_hash=dispatch.transition_descriptor_hash(descriptor_bytes),
        transition_format_version=ea.RIG_TRANSITION_FORMAT_VERSION)
    projection = artifact["admission_projection"]
    transition = rig_events.verify_transition_artifact_bytes(
        transition_raw, descriptor=descriptor,
        score_delta_ppm=projection["score_after_ppm"] - projection["score_before_ppm"],
        epoch_context_root_=pins["epoch_context_root"])
    child = rig_events.replay_transition_artifact(current, transition, epoch_pins=pins)
    assert frontier.frontier_root(child) == resulting_root
    assert child == resulting
    assert child["parent_frontier_root"] == parent_root
    assert child["profiles"][PROFILE] == artifact["candidate"]["release_root"]
    return artifact, report, child


def test_two_transitions_reconstruct_from_genesis_under_law_v2():
    index, store, context = _load_fixture()
    pins = _epoch_pins(context)
    assert context["active_frontier_root"] == GENESIS_ROOT
    assert context["baseline_manifest_hash"] == GENESIS_BASELINE_ROOT

    genesis = pub.fetch_json(GENESIS_ROOT, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    frontier.validate_manifest(genesis)
    assert frontier.frontier_root(genesis) == GENESIS_ROOT
    assert genesis["epoch"] == 0 and genesis["parent_frontier_root"] == "0" * 64

    efficiency, efficiency_report, after_efficiency = _verify_and_replay(
        store, context, pins, genesis, EFFICIENCY_EVAL_ROOT)
    assert efficiency["admission_projection"]["class"] == "efficiency"
    assert efficiency_report["witness_provenance"]["source_kind"] == "genesis"
    assert efficiency_report["witness_provenance"]["source_root"] == GENESIS_BASELINE_ROOT
    assert frontier.frontier_root(after_efficiency) == EFFICIENCY_FRONTIER_ROOT

    prior_accept, prior_accept_report, after_prior_accept = _verify_and_replay(
        store, context, pins, after_efficiency, PRIOR_ACCEPT_EVAL_ROOT)
    assert prior_accept["admission_projection"]["class"] == "quality"
    witness = prior_accept["determinism_witness"]
    assert witness["source_kind"] == "prior_accept"
    assert witness["source_root"] == EFFICIENCY_EVAL_ROOT
    assert witness["release_root"] == efficiency["candidate"]["release_root"]
    provenance = prior_accept_report["witness_provenance"]
    assert provenance["source_kind"] == "prior_accept"
    assert provenance["source_root"] == EFFICIENCY_EVAL_ROOT
    assert provenance["source"]["candidate_hash"] == efficiency["candidate"]["candidate_hash"]
    assert frontier.frontier_root(after_prior_accept) == PRIOR_ACCEPT_FRONTIER_ROOT

    assert [step["frontier_root"] for step in index["chain"]] == [
        GENESIS_ROOT, EFFICIENCY_FRONTIER_ROOT, PRIOR_ACCEPT_FRONTIER_ROOT]
    assert after_prior_accept["parent_frontier_root"] == EFFICIENCY_FRONTIER_ROOT
    assert after_efficiency["parent_frontier_root"] == GENESIS_ROOT


def test_prior_accept_witness_refuses_a_predecessor_that_does_not_reproduce():
    _index, store, _context = _load_fixture()
    prior_accept = pub.fetch_json(
        PRIOR_ACCEPT_EVAL_ROOT, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    assert ea.resolve_determinism_witness_source(prior_accept, store=store)["resolved"] is True

    # An absent predecessor is unavailable, never presumed.
    without_predecessor = pub.InMemoryCAS()
    for root in (PRIOR_ACCEPT_EVAL_ROOT,):
        without_predecessor.put(root, store.get(root))
    with pytest.raises(ea.EvalArtifactError, match="no object published"):
        ea.resolve_determinism_witness_source(prior_accept, store=without_predecessor)

    # A witness that restates the predecessor's stored vector is refused against the object.
    tampered = copy.deepcopy(prior_accept)
    vector = tampered["determinism_witness"]["partitions"]["confirm"]
    vector["composite_micro"] += 1
    with pytest.raises(ea.WitnessSourceMismatchError, match="different 'confirm' stored vector"):
        ea.resolve_determinism_witness_source(tampered, store=store)


def test_dominance_block_is_recomputed_not_trusted_on_the_fixture_artifacts():
    _index, store, _context = _load_fixture()
    for eval_root in (EFFICIENCY_EVAL_ROOT, PRIOR_ACCEPT_EVAL_ROOT):
        artifact = pub.fetch_json(eval_root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
        forged = copy.deepcopy(artifact)
        forged["dominance"]["partitions"]["confirm"]["admission_gain_ppm"] += 1
        with pytest.raises(ea.VerdictMismatchError, match="admission_gain_ppm"):
            ea.verify_dominance_block(forged)
