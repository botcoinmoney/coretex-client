# SPDX-License-Identifier: UNLICENSED
"""Cut V5-E — PROTOCOL AND DEPLOYMENT DISPATCH.

The property under test: a validator handed a mixed log feed routes every line to the RIGHT law,
and does so without ever being brittle about lines it does not know. Old epochs must keep
decoding under the V4 path exactly as ``coretex-registry.ts`` decodes them (§17.236: "old epochs
and old deployments stay immutable and replayable"), V5 epochs must route to the new topic0, and
an unknown topic0 must be ignored rather than fatal.
"""
from __future__ import annotations

import pytest

import frontier as fr
from keccak256 import keccak256_hex
from validator import dispatch as dp

from validator_fixtures import (DEPLOYMENTS, MINER, V4_REGISTRY, V5_REGISTRY, Scenario,
                                unknown_topic_log, v4_advance_log)


# --------------------------------------------------------------------------- #
# topic0 identity
# --------------------------------------------------------------------------- #
def test_v5_advance_topic0_is_the_committed_literal():
    assert dp.event_topic(dp.V5_FRONTIER_ADVANCED_SIG) == dp.V5_FRONTIER_ADVANCED_TOPIC0
    assert dp.V5_FRONTIER_ADVANCED_TOPIC0.startswith("b943265f")


def test_v4_advance_topic0_is_the_committed_literal():
    assert dp.event_topic(dp.V4_STATE_ADVANCED_SIG) == dp.V4_STATE_ADVANCED_TOPIC0
    assert dp.V4_STATE_ADVANCED_TOPIC0.startswith("2f0a8989")


def test_v4_and_v5_advance_topics_do_not_collide():
    assert dp.V4_STATE_ADVANCED_TOPIC0 != dp.V5_FRONTIER_ADVANCED_TOPIC0


def test_every_committed_topic_literal_recomputes_from_its_signature():
    # the import-time guard, asserted explicitly so the intent survives a refactor
    for topic, (_protocol, name, signature) in dp._SIGNATURES.items():
        assert dp.event_topic(signature) == topic, name


def test_profile_id_hashes_match_the_solidity_constants():
    # V5TestBase.sol: bytes32 PROFILE_DOC = keccak256("doc.tool.v1")
    assert dp.PROFILE_ID_HASHES["doc.tool.v1"] == keccak256_hex(b"doc.tool.v1")
    assert set(dp.PROFILE_ID_HASHES) == set(fr.PROFILE_IDS)
    assert dp.PROFILE_BY_ID_HASH[dp.PROFILE_ID_HASHES["conv.pref.v1"]] == "conv.pref.v1"


# --------------------------------------------------------------------------- #
# classification / routing
# --------------------------------------------------------------------------- #
def test_unknown_topic0_is_ignored_not_an_error():
    result = dp.classify(unknown_topic_log())
    assert result.recognised is False
    assert result.protocol is None
    assert "ignored" in result.reason


def test_unknown_topic0_survives_full_decode():
    route, decoded = dp.decode(unknown_topic_log(), DEPLOYMENTS)
    assert route.recognised is False and decoded is None


def test_a_log_with_no_topics_is_ignored():
    assert dp.classify({"topics": [], "data": "0x"}).recognised is False


def test_a_log_with_a_malformed_topic0_is_ignored():
    assert dp.classify({"topics": ["0xzz"], "data": "0x"}).recognised is False


def test_v5_topic_routes_to_v5(scenario):
    assert dp.classify(scenario.advance_log()).protocol == dp.PROTOCOL_V5


def test_v4_topic_routes_to_v4():
    assert dp.classify(v4_advance_log()).protocol == dp.PROTOCOL_V4


def test_v5_topic_from_a_v4_address_is_ignored_not_guessed(scenario):
    # epoch 5 IS inside the V4 deployment's window, so the address resolves — and the topic0 then
    # disagrees with the protocol that address speaks. That is a mismatch, not a near-miss.
    log = scenario.advance_log(address=V4_REGISTRY, epoch=5)
    result = dp.route(log, DEPLOYMENTS)
    assert result.recognised is False
    assert "speaks" in result.reason and dp.PROTOCOL_V4 in result.reason


def test_a_log_from_an_unknown_address_is_ignored(scenario):
    result = dp.route(scenario.advance_log(address="0x" + "9" * 40), DEPLOYMENTS)
    assert result.recognised is False and "unrecognised address" in result.reason


def test_a_v5_epoch_outside_the_deployment_window_is_ignored(scenario):
    # the V5 deployment starts at epoch 7; epoch 5 belongs to the V4 lane
    log = scenario.advance_log(epoch=5)
    assert dp.route(log, DEPLOYMENTS).recognised is False


def test_routing_without_a_deployment_set_degrades_to_topic0_only(scenario):
    assert dp.route(scenario.advance_log(address=V4_REGISTRY)).protocol == dp.PROTOCOL_V5


# --------------------------------------------------------------------------- #
# V5 advance decoding
# --------------------------------------------------------------------------- #
def test_advance_round_trips_through_the_real_abi_layout(scenario):
    event = dp.decode_frontier_advanced(scenario.advance_log())
    assert event.epoch == scenario.epoch
    assert event.transition_index == 0
    assert event.miner == MINER
    assert event.parent_frontier_root == scenario.parent_root
    assert event.new_frontier_root == scenario.new_root
    assert event.eval_report_hash == scenario.eval_report_hash
    assert event.transition_bytes == scenario.transition_bytes
    assert event.benchmark_law_root == scenario.parent["benchmark_law_root"]
    assert event.runtime_abi_root == scenario.parent["runtime_abi_root"]


def test_decoded_roots_are_bare_lowercase_hex_that_frontier_accepts(scenario):
    event = scenario.event()
    for value in (event.parent_frontier_root, event.new_frontier_root, event.eval_report_hash):
        fr.check_root(value, "decoded")                # raises on 0x-prefix or uppercase


def test_transition_bytes_survive_padding(scenario):
    # canonical transition bytes are ~200 bytes: not a multiple of 32, so padding is exercised
    assert len(scenario.transition_bytes) % 32 != 0
    assert dp.decode_frontier_advanced(scenario.advance_log()).transition_bytes \
        == scenario.transition_bytes


def test_decoder_refuses_data_that_is_not_word_aligned(scenario):
    log = scenario.advance_log()
    log["data"] = log["data"] + "ff"
    with pytest.raises(dp.LogDecodeError, match="multiple of 32"):
        dp.decode_frontier_advanced(log)


def test_decoder_refuses_an_out_of_range_tail_offset(scenario):
    log = scenario.advance_log()
    raw = log["data"][2:]
    words = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    words[7] = f"{1 << 40:064x}"
    log["data"] = "0x" + "".join(words)
    with pytest.raises(dp.LogDecodeError, match="past the end"):
        dp.decode_frontier_advanced(log)


def test_decoder_refuses_a_declared_length_that_overruns(scenario):
    log = scenario.advance_log()
    raw = log["data"][2:]
    words = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    words[8] = f"{4096:064x}"                          # the tail length word
    log["data"] = "0x" + "".join(words)
    with pytest.raises(dp.LogDecodeError, match="only .* remain"):
        dp.decode_frontier_advanced(log)


def test_decoder_refuses_nonzero_tail_padding(scenario):
    log = scenario.advance_log()
    log["data"] = log["data"][:-2] + "01"
    with pytest.raises(dp.LogDecodeError, match="padding is non-zero"):
        dp.decode_frontier_advanced(log)


def test_decoder_refuses_a_dirty_address_topic(scenario):
    log = scenario.advance_log()
    log["topics"][3] = "0x" + "11" + log["topics"][3][4:]
    with pytest.raises(dp.LogDecodeError, match="left-zero-padded"):
        dp.decode_frontier_advanced(log)


def test_decoder_refuses_an_epoch_that_does_not_fit_uint64(scenario):
    log = scenario.advance_log()
    log["topics"][1] = "0x" + "f" * 64
    with pytest.raises(dp.LogDecodeError, match="uint64"):
        dp.decode_frontier_advanced(log)


def test_decoder_refuses_a_foreign_topic0(scenario):
    with pytest.raises(dp.WrongProtocolError):
        dp.decode_frontier_advanced(v4_advance_log())


# --------------------------------------------------------------------------- #
# the V4 path still works
# --------------------------------------------------------------------------- #
def test_v4_advance_still_decodes_through_the_v4_path():
    event = dp.decode_v4_state_advanced(v4_advance_log(patch=b"\x01\x02\x03"))
    assert event.epoch == 3
    assert event.transitionIndex == 0
    assert event.parentStateRoot == "aa" * 32
    assert event.newStateRoot == "bb" * 32
    assert event.patchHash == "cc" * 32
    assert event.improvementCredits == 4200
    assert event.wordCount == 1024
    assert event.compactPatchBytes == b"\x01\x02\x03"


def test_v4_and_v5_logs_can_share_one_feed(scenario):
    feed = [v4_advance_log(), scenario.advance_log(), unknown_topic_log()]
    routed = [dp.decode(log, DEPLOYMENTS) for log in feed]
    assert routed[0][0].protocol == dp.PROTOCOL_V4
    assert isinstance(routed[0][1], dp.V4StateAdvanced)
    assert routed[1][0].protocol == dp.PROTOCOL_V5
    assert isinstance(routed[1][1], dp.FrontierAdvanced)
    assert routed[2][0].recognised is False and routed[2][1] is None


# --------------------------------------------------------------------------- #
# the other V5 events
# --------------------------------------------------------------------------- #
def test_credit_accepted_decodes_and_names_its_profile(scenario):
    credit = scenario.credit_event()
    assert credit.epoch == scenario.epoch
    assert credit.miner == MINER
    assert credit.eval_report_hash == scenario.eval_report_hash
    assert credit.target_profile == "doc.tool.v1"


def test_epoch_commit_set_carries_no_data(scenario):
    commit = dp.decode_epoch_commit_set(scenario.commit_log())
    assert commit.epoch_commit == scenario.entropy_commitment
    bad = scenario.commit_log()
    bad["data"] = "0x" + "00" * 32
    with pytest.raises(dp.LogDecodeError, match="both parameters are indexed"):
        dp.decode_epoch_commit_set(bad)


def test_epoch_secret_reveal_decodes(scenario):
    assert dp.decode_epoch_secret_revealed(scenario.reveal_log()).epoch_secret == scenario.secret


# --------------------------------------------------------------------------- #
# per-epoch pins
# --------------------------------------------------------------------------- #
def test_pins_are_built_from_public_logs_alone(scenario):
    table = dp.build_pins_from_logs(scenario.context_logs(reveal=True), DEPLOYMENTS)
    pins = table[scenario.epoch]
    assert pins.runtime_abi_root == scenario.parent["runtime_abi_root"]
    assert pins.benchmark_law_root == scenario.parent["benchmark_law_root"]
    assert pins.entropy_commitment == scenario.entropy_commitment
    assert pins.revealed_secret == scenario.secret


def test_the_epoch_head_is_not_a_pin(scenario):
    """§17.237 rules 1/4/6: nothing a coordinator publishes names the epoch head.

    The context event no longer carries one and the pin set no longer exposes one, so a validator
    physically cannot take its epoch parent from a coordinator input — it must derive it.
    """
    table = dp.build_pins_from_logs(scenario.context_logs(), DEPLOYMENTS)
    assert "parent_frontier_root" not in table[scenario.epoch].as_dict()
    assert not hasattr(table[scenario.epoch], "parent_frontier_root")
    decoded = dp.decode_memory_epoch_context_set(scenario.context_log())
    assert not hasattr(decoded, "parent_frontier_root")
    # ...and the context event's shape says so: 3 law-pin words, no fourth.
    assert len(dp.from_0x(scenario.context_log()["data"], "data")) == 3 * dp.WORD


def test_the_epoch_head_publication_decodes(scenario):
    event = dp.decode_epoch_inherited(scenario.inherited_log())
    assert event.epoch == scenario.epoch
    assert event.inherited_parent_root == scenario.parent_root
    assert event.new_frontier_root == scenario.new_root
    assert event.from_genesis is True
    assert event.inherited_from_epoch == scenario.epoch


def test_a_non_genesis_epoch_head_publication_decodes(scenario):
    event = dp.decode_epoch_inherited(scenario.inherited_log(
        epoch=scenario.epoch + 3, inherited_from_epoch=scenario.epoch, from_genesis=False))
    assert event.inherited_from_epoch == scenario.epoch and event.from_genesis is False


def test_an_epoch_head_publication_that_inherits_from_itself_without_genesis_is_refused(scenario):
    with pytest.raises(dp.LogDecodeError, match="never anything else"):
        dp.decode_epoch_inherited(scenario.inherited_log(from_genesis=False))


def test_an_epoch_head_publication_claiming_genesis_from_another_epoch_is_refused(scenario):
    with pytest.raises(dp.LogDecodeError, match="never anything else"):
        dp.decode_epoch_inherited(scenario.inherited_log(
            epoch=scenario.epoch + 1, inherited_from_epoch=scenario.epoch, from_genesis=True))


def test_a_non_boolean_from_genesis_word_is_refused(scenario):
    log = scenario.inherited_log()
    log["data"] = log["data"][:-64] + f"{2:064x}"
    with pytest.raises(dp.LogDecodeError, match="not a canonical ABI bool"):
        dp.decode_epoch_inherited(log)


def test_the_epoch_head_topic0_is_committed_and_distinct():
    assert dp.event_topic(dp.V5_EPOCH_INHERITED_SIG) == dp.V5_EPOCH_INHERITED_TOPIC0
    assert dp.V5_EPOCH_INHERITED_TOPIC0 not in (dp.V5_FRONTIER_ADVANCED_TOPIC0,
                                                dp.V4_STATE_ADVANCED_TOPIC0,
                                                dp.V5_EPOCH_CONTEXT_SET_TOPIC0)
    assert dp.V5_EPOCH_INHERITED_TOPIC0 in dp.V5_TOPICS


def test_an_unarmed_epoch_yields_no_pins(scenario):
    # context set but never committed: the epoch is not armed, so it has no pins
    table = dp.build_pins_from_logs([scenario.context_log()], DEPLOYMENTS)
    assert table == {}


def test_a_zero_commitment_is_not_an_arm(scenario):
    table = dp.build_pins_from_logs(
        [scenario.context_log(), scenario.commit_log(commitment=dp.ZERO_WORD)], DEPLOYMENTS)
    assert table == {}


def test_resolve_pins_refuses_a_missing_epoch(scenario):
    resolver = dp.pins_from_mapping({scenario.epoch: scenario.pins()})
    with pytest.raises(dp.MissingEpochPinsError, match="no pins known for epoch 9"):
        dp.resolve_pins(resolver, 9)


def test_resolve_pins_refuses_an_absent_resolver():
    with pytest.raises(dp.MissingEpochPinsError, match="global assumption is refused"):
        dp.resolve_pins(None, 7)


def test_resolve_pins_refuses_pins_for_the_wrong_epoch(scenario):
    wrong = dp.pins_from_mapping({})
    resolver = lambda _epoch: scenario.pins()          # noqa: E731 - always returns epoch 7
    with pytest.raises(dp.MissingEpochPinsError, match="returned pins for epoch 7"):
        dp.resolve_pins(resolver, 8)
    assert wrong(1) is None


def test_epoch_pins_validate_their_roots(scenario):
    with pytest.raises(fr.FrontierError):
        dp.EpochPins(epoch=7, runtime_abi_root="nope",
                     benchmark_law_root="1" * 64, counter_resource_law_root="3" * 64,
                     entropy_commitment="4" * 64)


def test_pins_have_no_flat_fallback_api():
    # §17.236 / the V4 lesson: each advance is checked against ITS OWN epoch's pins. A global
    # "expected roots" entry point must not exist to be reached for by accident.
    assert not [name for name in dir(dp) if name.lower().startswith("global_pins")]
    assert not hasattr(dp, "expected_pins")


# --------------------------------------------------------------------------- #
# deployments
# --------------------------------------------------------------------------- #
def test_deployment_addresses_are_normalised():
    dep = dp.Deployment(address="0x" + "AB" * 20, protocol=dp.PROTOCOL_V5)
    assert dep.address == "0x" + "ab" * 20


def test_deployment_rejects_a_malformed_address():
    with pytest.raises(dp.DispatchTypeError):
        dp.Deployment(address="not-an-address", protocol=dp.PROTOCOL_V5)


def test_deployment_rejects_an_unknown_protocol():
    with pytest.raises(dp.DispatchTypeError):
        dp.Deployment(address="0x" + "1" * 40, protocol="coretex.v9")


def test_deployment_set_indexes_by_protocol():
    assert DEPLOYMENTS.addresses_for(dp.PROTOCOL_V5) == (V5_REGISTRY,)
    assert DEPLOYMENTS.addresses_for(dp.PROTOCOL_V4) == (V4_REGISTRY,)


@pytest.fixture()
def scenario():
    return Scenario()
