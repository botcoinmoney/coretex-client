# SPDX-License-Identifier: UNLICENSED
"""Cut V5-E — FRONTIER SYNC: confirmation depth, ordering, contiguity, gaps.

The properties under test are the ones a validator gets wrong quietly: sorting a per-epoch
counter as if it were global, treating an unconfirmed head block as settled, letting a duplicated
feed entry choose consensus, and — the worst one — replaying a partial window and reporting it as
a complete verification. Every one of those must surface as a NAMED finding.
"""
from __future__ import annotations

import pytest

from validator import dispatch as dp
from validator import sync as sy

from validator_fixtures import (DEPLOYMENTS, V5_REGISTRY, Scenario, unknown_topic_log,
                                v4_advance_log)


def advance(scenario, *, epoch, index, block, log_index=0, **overrides):
    """One decodable advance log at a chosen (epoch, index, block)."""
    return scenario.advance_log(epoch=epoch, transition_index=index, block_number=block,
                                log_index=log_index, **overrides)


@pytest.fixture()
def scenario():
    return Scenario()


# --------------------------------------------------------------------------- #
# confirmation depth
# --------------------------------------------------------------------------- #
def test_confirmed_head_is_latest_minus_depth():
    assert sy.confirmed_head(1000, 15) == 985
    assert sy.confirmed_head(1000, 0) == 1000


def test_default_confirmation_depth_matches_the_canonical_v4_validator():
    assert sy.DEFAULT_CONFIRMATION_DEPTH == 15
    assert sy.DEFAULT_CHUNK_BLOCKS == 9500


def test_confirmation_depth_must_be_non_negative():
    with pytest.raises(sy.WindowError):
        sy.confirmed_head(100, -1)


def test_logs_above_the_confirmed_head_are_pending_not_dropped(scenario):
    logs = [advance(scenario, epoch=7, index=0, block=100),
            advance(scenario, epoch=7, index=1, block=999)]
    result = sy.sync_logs(logs, latest_block=1000, confirmation_depth=15,
                          deployments=DEPLOYMENTS)
    assert [e.transition_index for e in result.events] == [0]
    assert [e.transition_index for e in result.pending] == [1]
    assert result.confirmed_head == 985


def test_without_a_latest_block_everything_is_treated_as_confirmed(scenario):
    result = sy.sync_logs([advance(scenario, epoch=7, index=0, block=10 ** 9)],
                          deployments=DEPLOYMENTS)
    assert len(result.events) == 1 and result.confirmed_head is None


# --------------------------------------------------------------------------- #
# paging
# --------------------------------------------------------------------------- #
def test_block_windows_are_inclusive_and_bounded():
    assert sy.block_windows(0, 9) == [(0, 9)]
    assert sy.block_windows(0, 10, chunk_blocks=4) == [(0, 3), (4, 7), (8, 10)]
    assert sy.block_windows(5, 4) == []


def test_fetch_caps_to_block_at_the_confirmed_head(scenario):
    source = sy.ListLogSource([advance(scenario, epoch=7, index=0, block=100),
                               advance(scenario, epoch=7, index=1, block=995)])
    logs = sy.fetch_logs(source, from_block=0, latest_block=1000, confirmation_depth=15,
                         deployments=DEPLOYMENTS)
    assert len(logs) == 1
    assert max(hi for _lo, hi in source.calls) == 985


def test_fetch_pages_in_bounded_chunks(scenario):
    source = sy.ListLogSource([advance(scenario, epoch=7, index=0, block=1)])
    sy.fetch_logs(source, from_block=0, latest_block=100, confirmation_depth=0, chunk_blocks=10)
    assert len(source.calls) == 11
    assert source.calls[0] == (0, 9)


def test_sync_filters_by_topic_and_address(scenario):
    source = sy.ListLogSource([advance(scenario, epoch=7, index=0, block=1),
                               unknown_topic_log(),
                               advance(scenario, epoch=7, index=1, block=2,
                                       address="0x" + "7" * 40)])
    result = sy.sync(source, from_block=0, latest_block=10, confirmation_depth=0,
                     deployments=DEPLOYMENTS)
    assert [e.transition_index for e in result.events] == [0]


# --------------------------------------------------------------------------- #
# ordering
# --------------------------------------------------------------------------- #
def test_ordering_is_by_epoch_then_transition_index_not_by_block(scenario):
    # transitionIndex restarts at 0 each epoch; a block-order sort would interleave the epochs
    logs = [advance(scenario, epoch=8, index=0, block=10),
            advance(scenario, epoch=7, index=1, block=20),
            advance(scenario, epoch=7, index=0, block=30),
            advance(scenario, epoch=8, index=1, block=40)]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS)
    assert [e.key for e in result.events] == [(7, 0), (7, 1), (8, 0), (8, 1)]


def test_block_order_disagreeing_with_chain_order_is_an_anomaly(scenario):
    logs = [advance(scenario, epoch=7, index=0, block=90),
            advance(scenario, epoch=7, index=1, block=10)]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS,
                          genesis_frontier_root=scenario.genesis_frontier_root)
    assert [a.code for a in result.anomalies] == ["block_order_disagrees_with_chain_order"]


def test_without_a_genesis_root_the_earliest_epoch_head_is_unverified_not_assumed(scenario):
    """§17.237 rule 7: the first-deployment genesis root is an INPUT, never a guess."""
    result = sy.sync_logs([advance(scenario, epoch=7, index=0, block=10)],
                          deployments=DEPLOYMENTS)
    assert [a.code for a in result.anomalies] == ["genesis_root_unknown"]
    assert result.epoch_parents == {} and result.epoch_parent(7) is None


def test_a_removed_log_is_an_anomaly(scenario):
    log = advance(scenario, epoch=7, index=0, block=10)
    log["removed"] = True
    result = sy.sync_logs([log], deployments=DEPLOYMENTS,
                          genesis_frontier_root=scenario.genesis_frontier_root)
    # The removed log is reported twice, deliberately: once as a log that must not be replayed,
    # and once as the EPOCH HEAD it established being invalidated (§17.237 reorg rule).
    assert [a.code for a in result.anomalies] == ["reorg_removed_log",
                                                  "reorg_invalidated_epoch_inheritance"]
    assert result.epoch_parents == {}, "the inheritance is not silently re-derived"


# --------------------------------------------------------------------------- #
# contiguity and gaps
# --------------------------------------------------------------------------- #
def test_a_contiguous_epoch_has_no_gaps(scenario):
    logs = [advance(scenario, epoch=7, index=i, block=10 + i) for i in range(4)]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS)
    assert result.gaps == [] and result.contiguous is True


def test_a_missing_index_is_reported_as_a_gap(scenario):
    logs = [advance(scenario, epoch=7, index=0, block=10),
            advance(scenario, epoch=7, index=3, block=13)]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS)
    assert [g.as_dict() for g in result.gaps] == [
        {"epoch": 7, "missing_from": 1, "missing_to": 2, "count": 2}]
    assert result.contiguous is False


def test_an_epoch_that_does_not_start_at_zero_is_a_gap(scenario):
    result = sy.sync_logs([advance(scenario, epoch=7, index=2, block=10)],
                          deployments=DEPLOYMENTS)
    assert result.gaps == [sy.Gap(epoch=7, missing_from=0, missing_to=1)]


def test_a_declared_resume_cursor_makes_a_mid_epoch_window_contiguous(scenario):
    result = sy.sync_logs([advance(scenario, epoch=7, index=5, block=10)],
                          deployments=DEPLOYMENTS, start_index={7: 5})
    assert result.gaps == [] and result.contiguous is True


def test_contiguity_is_tracked_per_epoch_not_globally(scenario):
    # both epochs restart at 0; a global counter would see 7:0, 8:0 as a duplicate/gap
    logs = [advance(scenario, epoch=7, index=0, block=10),
            advance(scenario, epoch=8, index=0, block=11),
            advance(scenario, epoch=7, index=1, block=12),
            advance(scenario, epoch=8, index=1, block=13)]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS)
    assert result.gaps == [] and result.contiguous is True


# --------------------------------------------------------------------------- #
# duplicates and conflicts
# --------------------------------------------------------------------------- #
def test_an_identical_repeat_is_a_duplicate_not_a_conflict(scenario):
    log = advance(scenario, epoch=7, index=0, block=10)
    result = sy.sync_logs([log, dict(log)], deployments=DEPLOYMENTS)
    assert len(result.events) == 1
    assert len(result.duplicates) == 1 and result.conflicts == []
    assert result.contiguous is True


def test_two_different_payloads_at_one_index_are_quarantined(scenario):
    a = advance(scenario, epoch=7, index=0, block=10)
    b = advance(scenario, epoch=7, index=0, block=11, new_frontier_root="9" * 64)
    result = sy.sync_logs([a, b], deployments=DEPLOYMENTS)
    assert result.events == []                        # neither is allowed to be canonical
    assert len(result.conflicts) == 1
    assert result.contiguous is False
    assert "conflicting_transition_index" in [x.code for x in result.anomalies]


# --------------------------------------------------------------------------- #
# the other event families
# --------------------------------------------------------------------------- #
def test_context_commit_and_reveal_are_collected_and_become_pins(scenario):
    logs = scenario.context_logs(reveal=True) + [advance(scenario, epoch=7, index=0, block=100)]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS)
    pins = dp.resolve_pins(result.pin_resolver(), 7)
    assert pins.entropy_commitment == scenario.entropy_commitment
    assert pins.revealed_secret == scenario.secret


def test_credit_events_join_their_advance_by_transaction(scenario):
    logs = [scenario.advance_log(), scenario.credit_log()]
    result = sy.sync_logs(logs, deployments=DEPLOYMENTS)
    credit = result.credit_for(result.events[0])
    assert credit is not None and credit.eval_report_hash == scenario.eval_report_hash


def test_v4_logs_are_kept_separately_and_never_join_the_v5_stream(scenario):
    result = sy.sync_logs([v4_advance_log(), scenario.advance_log()], deployments=DEPLOYMENTS)
    assert len(result.events) == 1 and len(result.v4_events) == 1
    assert result.v4_events[0].epoch == 3


def test_unknown_topics_are_counted_as_ignored_not_dropped_silently(scenario):
    result = sy.sync_logs([unknown_topic_log(), scenario.advance_log()],
                          deployments=DEPLOYMENTS)
    assert len(result.ignored) == 1 and len(result.events) == 1


def test_a_malformed_v5_log_lands_in_undecodable(scenario):
    log = scenario.advance_log()
    log["data"] = log["data"] + "ff"
    result = sy.sync_logs([log], deployments=DEPLOYMENTS)
    assert result.events == [] and len(result.undecodable) == 1


# --------------------------------------------------------------------------- #
# finalization
# --------------------------------------------------------------------------- #
def test_finalization_root_must_equal_the_reproduced_root(scenario):
    fin_log = dp.encode_simple_log(
        address=V5_REGISTRY, topic0=dp.V5_EPOCH_FINALIZED_TOPIC0,
        indexed=[f"{7:064x}"],
        words=[scenario.parent_root, scenario.new_root, scenario.parent["runtime_abi_root"],
               scenario.parent["benchmark_law_root"],
               scenario.artifact["counter_resource_law_root"], f"{1:064x}"],
        block_number=200)
    result = sy.sync_logs([scenario.advance_log(), fin_log], deployments=DEPLOYMENTS)
    assert sy.check_finalization(result, 7, scenario.new_root) is None
    bad = sy.check_finalization(result, 7, "0" * 63 + "1")
    assert bad is not None and bad.code == "final_root_mismatch"


def test_summary_is_json_safe(scenario):
    import json
    result = sy.sync_logs([scenario.advance_log()], latest_block=200, deployments=DEPLOYMENTS)
    json.dumps(result.summary())
