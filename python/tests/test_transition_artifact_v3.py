# SPDX-License-Identifier: Apache-2.0
"""Descriptor-v3 transition-artifact replay and refusal controls.

The positive fixture is the exact accepted epoch-8 public artifact addressed by
``f01ef652...`` and its exact ``14fb22cd...`` parent.  Keeping the canonical bytes
in the test makes this proof independent of a coordinator checkout or network.
"""
from __future__ import annotations

import copy

import pytest

from coretex_validator import frontier as fr
from coretex_validator import rig_events as rig


ARTIFACT_ROOT = "f01ef652e00f1abc2387294c332b08c17348616da1fa51cf8eb4b61ff16d1ad2"
PARENT_ROOT = "14fb22cd67c13b811860dcb590931ebac4058f95aabfcfee5f2e8ea9a24c352f"
NEW_ROOT = "bc61b3b6042872ed6583ac3de1966f611e18f2a0d1a30307a2d651a8760a71ee"
EPOCH_CONTEXT_ROOT = "8e282d2a64f6a7fcee45f0abca7cb12242eed70db4fde2f939d4b635d494be44"
DESCRIPTOR_HEX = (
    "21f01ef652e00f1abc2387294c332b08c17348616da1fa51cf8eb4b61ff16d1ad2"
    "14fb22cd67c13b811860dcb590931ebac4058f95aabfcfee5f2e8ea9a24c352f"
    "bc61b3b6042872ed6583ac3de1966f611e18f2a0d1a30307a2d651a8760a71ee"
)

ARTIFACT_BYTES = b"""{"affected_profiles":["event.schema.v1"],"availability":{"candidate_bundle":{"bytes":1093,"hash_rule":"sha256-signed-manifest-body","root":"3fc7ff9db89f860ca30fd91ae5bd1df98932a6741bdf605bcb8555643d60143a"},"composition_manifest":{"bytes":2549,"hash_rule":"sha256-signed-manifest-body","root":"ee732028c073a2a25477c8ff90b4b51c12d63ed7d83993f65aab0111daa8bae1"},"counter_resource_law":{"bytes":629,"hash_rule":"sha256-frontier-canonical-json","root":"049fe98ec08a3a47e2bf4582afa70ad45506a465584f3cec1a53286617c7b207"},"eval_report":{"bytes":34026,"hash_rule":"sha256-benchmark-canonical-json","root":"6f2cf67d10122263d0733cf5e262819ccd7544abe14624be9257db168b08d565"},"parent_frontier_manifest":{"bytes":668,"hash_rule":"sha256-frontier-canonical-json","root":"14fb22cd67c13b811860dcb590931ebac4058f95aabfcfee5f2e8ea9a24c352f"}},"byte_length":2263,"derived_state":{},"epoch":8,"epoch_context_root":"8e282d2a64f6a7fcee45f0abca7cb12242eed70db4fde2f939d4b635d494be44","format":"coretex.transition-artifact/v3","new_state_root":"bc61b3b6042872ed6583ac3de1966f611e18f2a0d1a30307a2d651a8760a71ee","parent_state_root":"14fb22cd67c13b811860dcb590931ebac4058f95aabfcfee5f2e8ea9a24c352f","profile_releases":{"event.schema.v1":{"expected_prior_release_root":"c85857242b434cec35ae2cb0b67bd33f96d1f0f425bc6265fec3758321e98ce5","hooks":["m6_pack"],"new_release_root":"3fc7ff9db89f860ca30fd91ae5bd1df98932a6741bdf605bcb8555643d60143a"}},"resulting_composition_root":"ee732028c073a2a25477c8ff90b4b51c12d63ed7d83993f65aab0111daa8bae1","resulting_frontier_manifest":{"benchmark_law_root":"a9e7fc72744c4f91be13c943c71d5b48ef4d0e13a0b205bd76fbcf2d40bb4bdb","default_composition_root":"ee732028c073a2a25477c8ff90b4b51c12d63ed7d83993f65aab0111daa8bae1","epoch":8,"format":"coretex.memory-frontier.v1","parent_frontier_root":"14fb22cd67c13b811860dcb590931ebac4058f95aabfcfee5f2e8ea9a24c352f","profiles":{"conv.pref.v1":"86deac65e365619c3601655b6768b6ef1738943ab620f67d62368089d727919b","doc.tool.v1":"4e81744ee61fd58602c04b23210b8ac7dad66cc126986ac82db2af66200dbe9c","event.schema.v1":"3fc7ff9db89f860ca30fd91ae5bd1df98932a6741bdf605bcb8555643d60143a"},"runtime_abi_root":"8f17abc43f6dd14a9ab828b999d48f7adc967d7c68a14a8b21007ace47e9aa30"},"score_delta_ppm":31400,"shared_components":[]}"""

PARENT_BYTES = b"""{"benchmark_law_root":"a9e7fc72744c4f91be13c943c71d5b48ef4d0e13a0b205bd76fbcf2d40bb4bdb","default_composition_root":"159596b813dd262bca81d086cfddd06ed0fea943b8cd8d35d64765b945d2f9c7","epoch":0,"format":"coretex.memory-frontier.v1","parent_frontier_root":"0000000000000000000000000000000000000000000000000000000000000000","profiles":{"conv.pref.v1":"86deac65e365619c3601655b6768b6ef1738943ab620f67d62368089d727919b","doc.tool.v1":"4e81744ee61fd58602c04b23210b8ac7dad66cc126986ac82db2af66200dbe9c","event.schema.v1":"c85857242b434cec35ae2cb0b67bd33f96d1f0f425bc6265fec3758321e98ce5"},"runtime_abi_root":"8f17abc43f6dd14a9ab828b999d48f7adc967d7c68a14a8b21007ace47e9aa30"}"""

# Exact chain-current production genesis and epoch-179 runtime pin. The former is immutable chain
# history and deliberately carries the retired compatibility-lock copy; the latter is adopted
# only from a separately verified epoch context on the inherited first edge.
PRODUCTION_GENESIS_ROOT = "8f2455e5cbf49cd4bb5e1b148c1828a9c79aa7fd27d3db7035fe7fb5e0287788"
PRODUCTION_GENESIS_RUNTIME = "d83638ae0819f49eb447d730978949f66f0e1bc1e4cdacaa3ed8e7029ef9c82a"
PRODUCTION_COMPATIBILITY_LOCK = "684152133d6900e43eff7edd799f6d97710f55fe995304185edd15d83c9b1354"
EPOCH_179_RUNTIME = "b6cc91e115597e1059cda9b3c5a57ed9a0a7ee3f34feb35ec0301a69f35f78c0"


def _production_genesis():
    return {
        "benchmark_law_root":
            "a9e7fc72744c4f91be13c943c71d5b48ef4d0e13a0b205bd76fbcf2d40bb4bdb",
        "compatibility_lock_root": PRODUCTION_COMPATIBILITY_LOCK,
        "default_composition_root":
            "159596b813dd262bca81d086cfddd06ed0fea943b8cd8d35d64765b945d2f9c7",
        "epoch": 0,
        "format": fr.MANIFEST_FORMAT,
        "parent_frontier_root": fr.ZERO_ROOT,
        "profiles": {
            "conv.pref.v1":
                "86deac65e365619c3601655b6768b6ef1738943ab620f67d62368089d727919b",
            "doc.tool.v1":
                "4e81744ee61fd58602c04b23210b8ac7dad66cc126986ac82db2af66200dbe9c",
            "event.schema.v1":
                "c85857242b434cec35ae2cb0b67bd33f96d1f0f425bc6265fec3758321e98ce5",
        },
        "runtime_abi_root": PRODUCTION_GENESIS_RUNTIME,
    }


def _epoch_pins(*, epoch=179, context_root="91" * 32, runtime=EPOCH_179_RUNTIME):
    return {
        "epoch": epoch,
        "epoch_context_root": context_root,
        "benchmark_law_root":
            "a9e7fc72744c4f91be13c943c71d5b48ef4d0e13a0b205bd76fbcf2d40bb4bdb",
        "runtime_abi_root": runtime,
    }


def _first_advance_artifact(*, parent=None, epoch=179, pins=None):
    parent = copy.deepcopy(parent or _production_genesis())
    pins = dict(pins or _epoch_pins(epoch=epoch))
    prior = parent["profiles"]["event.schema.v1"]
    release = "92" * 32
    composition = "93" * 32
    transition = fr.make_transition(
        target_profile="event.schema.v1",
        expected_prior_release_root=prior,
        new_release_root=release,
        resulting_composition_root=composition)
    if epoch > parent["epoch"]:
        child = fr.apply_transition(parent, transition, epoch=epoch, epoch_pins=pins)
    else:
        # Manufacture the invalid claim without weakening the public constructor, which itself
        # refuses same-epoch pin adoption / compatibility-lock retirement.
        child = fr.apply_transition(parent, transition, epoch=epoch)
        for pin in fr.EPOCH_PINNED_MANIFEST_FIELDS:
            child[pin] = pins[pin]
        child.pop("compatibility_lock_root", None)
    artifact = {
        "affected_profiles": ["event.schema.v1"],
        "availability": {},
        "byte_length": 1,
        "derived_state": {},
        "epoch": epoch,
        "epoch_context_root": pins["epoch_context_root"],
        "format": rig.TRANSITION_ARTIFACT_FORMAT,
        "new_state_root": fr.frontier_root(child),
        "parent_state_root": fr.frontier_root(parent),
        "profile_releases": {
            "event.schema.v1": {
                "expected_prior_release_root": prior,
                "hooks": ["m6_pack"],
                "new_release_root": release,
            },
        },
        "resulting_composition_root": composition,
        "resulting_frontier_manifest": child,
        "score_delta_ppm": 1,
        "shared_components": [],
    }
    return rig.finalize_transition_artifact_byte_length(artifact), pins


def _artifact():
    return fr.parse_json(ARTIFACT_BYTES.decode("utf-8"))


def _parent():
    return fr.parse_json(PARENT_BYTES.decode("utf-8"))


def _assert_refusal(code, call):
    with pytest.raises(rig.TransitionArtifactError) as raised:
        call()
    assert raised.value.code == code


def test_exact_accepted_public_artifact_verifies_and_replays():
    descriptor = rig.decode_transition_descriptor(bytes.fromhex(DESCRIPTOR_HEX))

    assert len(ARTIFACT_BYTES) == 2263
    assert fr.sha256_hex(ARTIFACT_BYTES) == ARTIFACT_ROOT
    assert fr.sha256_hex(PARENT_BYTES) == PARENT_ROOT
    assert descriptor.patch_artifact_hash == ARTIFACT_ROOT
    assert descriptor.parent_state_root == PARENT_ROOT
    assert descriptor.new_state_root == NEW_ROOT

    document = rig.verify_transition_artifact_bytes(
        ARTIFACT_BYTES,
        descriptor=descriptor,
        score_delta_ppm=31400,
        epoch_context_root_=EPOCH_CONTEXT_ROOT,
    )
    replayed = rig.replay_transition_artifact(_parent(), document)

    assert replayed == document["resulting_frontier_manifest"]
    assert fr.frontier_root(replayed) == NEW_ROOT


def test_malformed_artifact_and_served_byte_length_are_refused():
    wrong_format = _artifact()
    wrong_format["format"] = "coretex.transition-artifact/v2"
    _assert_refusal(
        rig.TRANSITION_ARTIFACT_MALFORMED,
        lambda: rig.validate_transition_artifact(wrong_format),
    )

    wrong_length = _artifact()
    wrong_length["byte_length"] += 1
    served = rig.transition_artifact_bytes(wrong_length)
    descriptor = rig.decode_transition_descriptor(
        rig.encode_transition_descriptor(
            patch_artifact_hash=fr.sha256_hex(served),
            parent_state_root=PARENT_ROOT,
            new_state_root=NEW_ROOT,
        )
    )
    _assert_refusal(
        rig.TRANSITION_ARTIFACT_MALFORMED,
        lambda: rig.verify_transition_artifact_bytes(served, descriptor=descriptor),
    )


def test_wrong_parent_manifest_is_refused():
    wrong_parent = _parent()
    wrong_parent["default_composition_root"] = "1" * 64
    _assert_refusal(
        rig.TRANSITION_PARENT_MISMATCH,
        lambda: rig.replay_transition_artifact(wrong_parent, _artifact()),
    )


def test_non_reproducing_resulting_manifest_is_refused():
    artifact = _artifact()
    artifact["resulting_frontier_manifest"]["profiles"]["event.schema.v1"] = "2" * 64
    _assert_refusal(
        rig.TRANSITION_REPLAY_ROOT_MISMATCH,
        lambda: rig.check_transition_artifact_self_consistency(artifact),
    )


def test_wrong_epoch_context_is_refused():
    _assert_refusal(
        rig.TRANSITION_EPOCH_CONTEXT_MISMATCH,
        lambda: rig.check_transition_epoch_context(
            _artifact(), epoch_context_root_="3" * 64
        ),
    )


def test_dependency_closure_refusals_are_distinct_and_fail_closed():
    missing_declaration = _artifact()
    del missing_declaration["affected_profiles"]
    _assert_refusal(
        rig.TRANSITION_CLOSURE_MALFORMED,
        lambda: rig.validate_transition_artifact(missing_declaration),
    )

    underdeclared = _artifact()
    underdeclared["affected_profiles"] = []
    _assert_refusal(
        rig.TRANSITION_CLOSURE_UNDERDECLARED,
        lambda: rig.replay_transition_artifact(_parent(), underdeclared),
    )

    transitive_gap = _artifact()
    transitive_gap["shared_components"] = ["shared.runtime.v1"]
    _assert_refusal(
        rig.TRANSITION_CLOSURE_MISMATCH,
        lambda: rig.replay_transition_artifact(
            _parent(),
            transitive_gap,
            component_references={"shared.runtime.v1": ["conv.pref.v1"]},
        ),
    )

    unknown_component = copy.deepcopy(transitive_gap)
    _assert_refusal(
        rig.TRANSITION_CLOSURE_UNKNOWN_ID,
        lambda: rig.replay_transition_artifact(_parent(), unknown_component),
    )


def test_production_genesis_first_advance_adopts_only_verified_epoch_179_pins():
    parent = _production_genesis()
    artifact, pins = _first_advance_artifact(parent=parent)

    assert fr.frontier_root(parent) == PRODUCTION_GENESIS_ROOT
    assert parent["runtime_abi_root"] == PRODUCTION_GENESIS_RUNTIME
    replayed = rig.replay_transition_artifact(parent, artifact, epoch_pins=pins)

    assert replayed == artifact["resulting_frontier_manifest"]
    assert replayed["epoch"] == 179
    assert replayed["runtime_abi_root"] == EPOCH_179_RUNTIME
    assert replayed["benchmark_law_root"] == pins["benchmark_law_root"]
    assert "compatibility_lock_root" not in replayed
    assert fr.frontier_root(replayed) == artifact["new_state_root"]


def test_first_advance_reanchor_without_verified_context_is_refused():
    artifact, _pins = _first_advance_artifact()
    _assert_refusal(
        rig.TRANSITION_LAW_PIN_CHANGE,
        lambda: rig.replay_transition_artifact(_production_genesis(), artifact),
    )


def test_same_epoch_parent_cannot_use_context_to_change_a_law_pin():
    parent = _production_genesis()
    parent["epoch"] = 179
    artifact, pins = _first_advance_artifact(parent=parent, epoch=179)
    _assert_refusal(
        rig.TRANSITION_LAW_PIN_CHANGE,
        lambda: rig.replay_transition_artifact(parent, artifact, epoch_pins=pins),
    )


def test_artifact_cannot_choose_a_pin_that_differs_from_verified_context():
    artifact, pins = _first_advance_artifact()
    artifact["resulting_frontier_manifest"]["runtime_abi_root"] = "94" * 32
    artifact["new_state_root"] = fr.frontier_root(artifact["resulting_frontier_manifest"])
    artifact = rig.finalize_transition_artifact_byte_length(artifact)
    _assert_refusal(
        rig.TRANSITION_LAW_PIN_CHANGE,
        lambda: rig.replay_transition_artifact(
            _production_genesis(), artifact, epoch_pins=pins),
    )


@pytest.mark.parametrize("changed", ["epoch", "epoch_context_root"])
def test_verified_context_must_bind_the_artifact_epoch_and_context_root(changed):
    artifact, pins = _first_advance_artifact()
    wrong = dict(pins)
    wrong[changed] = 180 if changed == "epoch" else "95" * 32
    _assert_refusal(
        rig.TRANSITION_EPOCH_CONTEXT_MISMATCH,
        lambda: rig.replay_transition_artifact(
            _production_genesis(), artifact, epoch_pins=wrong),
    )


def test_pinned_child_cannot_retain_the_retired_compatibility_lock_copy():
    artifact, pins = _first_advance_artifact()
    artifact["resulting_frontier_manifest"][
        "compatibility_lock_root"] = PRODUCTION_COMPATIBILITY_LOCK
    artifact["new_state_root"] = fr.frontier_root(artifact["resulting_frontier_manifest"])
    artifact = rig.finalize_transition_artifact_byte_length(artifact)
    _assert_refusal(
        rig.TRANSITION_LAW_PIN_CHANGE,
        lambda: rig.replay_transition_artifact(
            _production_genesis(), artifact, epoch_pins=pins),
    )


def test_same_epoch_transition_cannot_retire_a_compatibility_lock_copy():
    parent = _production_genesis()
    parent["epoch"] = 179
    parent["runtime_abi_root"] = EPOCH_179_RUNTIME
    artifact, pins = _first_advance_artifact(parent=parent, epoch=179)
    _assert_refusal(
        rig.TRANSITION_LAW_PIN_CHANGE,
        lambda: rig.replay_transition_artifact(parent, artifact, epoch_pins=pins),
    )
