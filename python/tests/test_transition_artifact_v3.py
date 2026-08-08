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
