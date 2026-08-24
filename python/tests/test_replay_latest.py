# SPDX-License-Identifier: Apache-2.0
"""``replay-latest``: one command, from nothing to a verdict on the head advance.

WHAT IT REMOVES. Checking the newest state advance used to be a research project: page the logs
yourself, decide which of them is newest (``transitionIndex`` restarts every epoch, so a
block-order sort is wrong), assemble the per-epoch pins, find the artifact store, and only then
run ``replay-advance``. Every one of those steps is derivable from the release and the chain, so
none of them is a question a validator should have to answer.

WHY IT IS A SEPARATE SUBCOMMAND RATHER THAN ``replay-advance --latest``. Each subcommand in this
CLI has exactly one input mode, and the two differ in what they read from: ``replay-advance``
takes a FEED FILE and replays whatever is in it, offline; ``replay-latest`` takes a CHAIN and a
release, like ``reproduce``. Folding them together would make ``--logs`` conditionally required
and add ``--rpc``/``--release`` to a command whose whole point is that it needs neither.
``--logs`` is still accepted here — as an OFFLINE SOURCE for the same discovery, which is what
these tests use — but the grammar's default is the chain.

THESE FIXTURES SPEAK THE LIVE LANE (D-2). They used to be built from ``validator_fixtures.Scenario``,
which emits the RETIRED ``CoreTexMemory*`` events. That is why this file stayed green through a
defect that made the command report an idle chain on fourteen epochs of confirmed advances: it was
exercising a decoder no deployed contract feeds. ``RigScenario`` emits descriptor-v3 from the
canonical release's own three addresses, so a decoder regression fails HERE rather than in
production. ``test_rig_discovery.py`` carries the same properties against verbatim Base mainnet
bytes.

The outcome vocabulary is unchanged and uncollapsed: PASS / FAIL / BACKLOG verbatim, exit 1 on a
refutation, exit 1 on a BACKLOG only under ``--require-complete``, exit 2 when there was nothing
to replay at all. A BACKLOG is never rendered as a pass and a missing artifact is never rendered
as a refutation.
"""
from __future__ import annotations

import json
import os

import pytest

import validator_fixtures as vf
from coretex_validator import cli
from coretex_validator import publication as pub


def run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured


@pytest.fixture()
def feed(tmp_path):
    """Three confirmed advances over two epochs, in ONE artifact store — the newest is (8, 0)."""
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    scenarios = [
        vf.RigScenario(epoch=7, transition_index=0, block_number=100, store=store),
        vf.RigScenario(epoch=7, transition_index=1, block_number=110, log_index=2,
                       candidate_hash="c" * 64, store=store),
        vf.RigScenario(epoch=8, transition_index=0, block_number=200, candidate_hash="a" * 64,
                       store=store),
    ]
    logs = []
    for scenario in scenarios:
        logs.extend(scenario.logs())
    path = tmp_path / "logs.json"
    path.write_text(json.dumps({"logs": logs}))
    return {"logs": str(path), "artifacts": str(tmp_path / "cas"), "scenarios": scenarios,
            "newest": scenarios[-1], "cache": str(tmp_path / "empty-law-cache")}


def replay_latest(feed_obj, capsys, *extra):
    return run(["replay-latest", "--logs", feed_obj["logs"], "--artifacts",
                feed_obj["artifacts"], "--law-cache", feed_obj["cache"], *extra], capsys)


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def test_the_newest_confirmed_advance_is_the_one_replayed(feed, capsys):
    code, captured = replay_latest(feed, capsys)
    payload = json.loads(captured.out)
    newest = feed["newest"]
    assert payload["selected"]["epoch"] == 8
    assert payload["selected"]["transition_index"] == 0
    assert payload["selected"]["new_frontier_root"] == newest.new_root
    assert payload["selected"]["eval_report_hash"] == newest.eval_report_hash
    assert payload["feed"]["events"] == 3
    assert code in (0, 1)


def test_newest_is_epoch_then_index_not_block_order(tmp_path, capsys):
    """``transitionIndex`` restarts each epoch, so a feed whose newest advance sits in an EARLIER
    block must still be selected. This is the exact bug a block-order sort produces."""
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    early_epoch_late_block = vf.RigScenario(epoch=7, transition_index=3, block_number=999,
                                            store=store)
    late_epoch_early_block = vf.RigScenario(epoch=9, transition_index=0, block_number=100,
                                            candidate_hash="b" * 64, store=store)
    logs = []
    for scenario in (early_epoch_late_block, late_epoch_early_block):
        logs.extend(scenario.logs())
    path = tmp_path / "logs.json"
    path.write_text(json.dumps(logs))
    code, captured = run(["replay-latest", "--logs", str(path), "--artifacts",
                          str(tmp_path / "cas"), "--law-cache", str(tmp_path / "c")], capsys)
    payload = json.loads(captured.out)
    assert payload["selected"]["epoch"] == 9
    assert code in (0, 1)


def test_an_empty_feed_replays_nothing_and_claims_nothing(tmp_path, capsys):
    path = tmp_path / "logs.json"
    path.write_text(json.dumps([]))
    artifacts = tmp_path / "cas"
    artifacts.mkdir()
    code, captured = run(["replay-latest", "--logs", str(path), "--artifacts", str(artifacts),
                          "--law-cache", str(tmp_path / "c")], capsys)
    assert code == 2
    payload = json.loads(captured.out)
    assert "nothing was replayed" in payload["note"]
    assert payload["selected"] is None


def test_the_report_names_the_one_decoder_that_saw_the_chain(feed, capsys):
    """"Which decoder read this chain" must never be a question answered by reading source."""
    from coretex_validator import rig_discovery as rd

    code, captured = replay_latest(feed, capsys)
    payload = json.loads(captured.out)
    assert rd.LIVE_DECODER in payload["chain"]["decoder"]
    assert rd.LIVE_DECODER in payload["feed"]["decoder"]
    assert code in (0, 1)


# --------------------------------------------------------------------------- #
# the three outcomes
# --------------------------------------------------------------------------- #
def test_a_backlog_is_exit_0_and_require_complete_turns_it_into_exit_1(feed, capsys):
    """Nothing was contradicted. Whether that is good enough is the CALLER's policy, not ours."""
    code, captured = replay_latest(feed, capsys)
    payload = json.loads(captured.out)
    assert payload["replayed"]["outcome"] == "BACKLOG"
    assert code == 0

    code, captured = replay_latest(feed, capsys, "--require-complete")
    assert code == 1
    assert "could not be checked" in captured.err
    assert json.loads(captured.out)["replayed"]["outcome"] == "BACKLOG"


def test_a_refuted_advance_is_exit_1_with_or_without_require_complete(tmp_path, capsys):
    """A new root that does not reproduce is a REFUTATION, and it is never a retryable backlog."""
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    scenario = vf.RigScenario(epoch=7, store=store)
    logs = scenario.law_logs() + [scenario.advance_log(new_state_root="f" * 64)]
    path = tmp_path / "logs.json"
    path.write_text(json.dumps(logs))
    code, captured = run(["replay-latest", "--logs", str(path), "--artifacts",
                          str(tmp_path / "cas"), "--law-cache", str(tmp_path / "c")], capsys)
    assert code == 1
    payload = json.loads(captured.out)
    assert payload["replayed"]["outcome"] == "FAIL"
    assert payload["selected"]["new_frontier_root"] == "f" * 64


def test_the_report_names_what_was_replayed_and_where_it_came_from(feed, capsys):
    code, captured = replay_latest(feed, capsys)
    payload = json.loads(captured.out)
    assert set(payload["selected"]) >= {"epoch", "transition_index", "miner",
                                        "parent_frontier_root", "new_frontier_root",
                                        "eval_report_hash", "block_number"}
    assert payload["artifacts"]["source"] == feed["artifacts"]
    assert payload["outcomes"] == {"PASS": 0, "FAIL": 0, "BACKLOG": 1} or \
        payload["outcomes"]["BACKLOG"] + payload["outcomes"]["FAIL"] == 1
    assert payload["law"]["used"] is False
    assert code in (0, 1)


# --------------------------------------------------------------------------- #
# grammar
# --------------------------------------------------------------------------- #
def test_replay_latest_is_its_own_subcommand_and_replay_advance_is_untouched():
    parser = cli.build_parser()
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    names = set(actions[0].choices)
    assert "replay-latest" in names and "replay-advance" in names
    # replay-advance still requires a feed file: its grammar did not change
    with pytest.raises(SystemExit):
        parser.parse_args(["replay-advance", "--artifacts", "/tmp"])


def test_without_a_feed_file_the_chain_is_the_source_and_an_rpc_is_required(tmp_path, capsys):
    code, captured = run(["replay-latest", "--artifacts", str(tmp_path),
                          "--law-cache", str(tmp_path / "c")], capsys)
    assert code == 2
    assert "--rpc" in captured.err and "--logs" in captured.err


def test_an_artifact_source_is_required_and_says_both_ways_to_give_one(tmp_path, capsys):
    """The default production release publishes no artifact base url, so an advance's objects
    have to come from somewhere the caller names."""
    path = tmp_path / "logs.json"
    path.write_text(json.dumps([]))
    code, captured = run(["replay-latest", "--logs", str(path),
                          "--law-cache", str(tmp_path / "c")], capsys)
    assert code == 2
    assert "--artifacts" in captured.err or "artifact" in captured.err


def test_the_artifact_store_is_the_releases_when_none_is_named(tmp_path, capsys, monkeypatch):
    """A release that publishes an artifact base url IS an artifact source, so the operator does
    not have to repeat it — and the report says which one was used."""
    from coretex_validator import pipeline as pl

    path = tmp_path / "logs.json"
    path.write_text(json.dumps([]))
    seen = {}

    def fake_open_store(*, artifact_dir, base_url):
        seen["artifact_dir"] = artifact_dir
        seen["base_url"] = base_url
        return pub.InMemoryCAS()

    monkeypatch.setattr(pl, "open_store", fake_open_store)
    code, captured = run(["replay-latest", "--logs", str(path), "--artifact-base-url",
                          "https://cas.example/o", "--law-cache", str(tmp_path / "c")], capsys)
    assert seen["base_url"] == "https://cas.example/o"
    assert code == 2                                           # empty feed; nothing to replay
    assert os.path.isdir(str(tmp_path))
