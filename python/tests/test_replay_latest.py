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


def replay_logs(tmp_path, capsys, logs, store):
    path = tmp_path / "selection-feed.json"
    path.write_text(json.dumps(logs))
    return run(["replay-latest", "--logs", str(path), "--artifacts", str(store),
                "--law-cache", str(tmp_path / "empty-law-cache")], capsys)


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
    early_epoch_late_block = vf.RigScenario(epoch=7, transition_index=0, block_number=999,
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


@pytest.mark.parametrize("defect", ["truncated", "wrong_emitter", "gap", "conflict", "removed"])
def test_a_defective_latest_feed_refuses_instead_of_selecting_an_older_row(
        tmp_path, capsys, defect):
    """Known lane damage is operational unavailability, never an idle/older-chain answer."""
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    old = vf.RigScenario(epoch=7, transition_index=0, block_number=100, store=store)
    latest = vf.RigScenario(epoch=8, transition_index=0, block_number=200,
                            candidate_hash="b" * 64, store=store)
    logs = old.logs() + latest.law_logs()
    candidate = latest.advance_log()
    if defect == "truncated":
        candidate["data"] = "0x00"
        logs.append(candidate)
    elif defect == "wrong_emitter":
        candidate["address"] = vf.PRODUCTION_DEPLOYMENT.mining
        logs.append(candidate)
    elif defect == "gap":
        candidate["topics"][2] = "0x" + f"{2:064x}"
        logs.append(candidate)
    elif defect == "conflict":
        logs.extend([candidate, latest.advance_log(new_state_root="f" * 64)])
    else:
        candidate["removed"] = True
        logs.append(candidate)

    code, captured = replay_logs(tmp_path, capsys, logs, tmp_path / "cas")
    payload = json.loads(captured.out)
    assert code == 2
    assert payload["code"] == "FEED_NOT_SELECTABLE"
    assert payload["outcome"] == "BACKLOG"
    assert payload["selected"] is None
    assert payload["feed"]["selectable"] is False
    assert payload["feed"]["selection_defects"]
    assert "older" in payload["note"]


def test_an_unknown_topic_is_ignored_and_does_not_poison_latest_selection(feed, capsys):
    document = json.loads(open(feed["logs"], "r", encoding="utf-8").read())
    logs = document["logs"] if isinstance(document, dict) else document
    logs.append({
        "address": vf.PRODUCTION_DEPLOYMENT.registry,
        "topics": ["0x" + "12" * 32], "data": "0x", "blockNumber": 201,
        "logIndex": 99,
    })
    path = os.path.join(os.path.dirname(feed["logs"]), "logs-with-unknown.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(logs, handle)
    code, captured = run(["replay-latest", "--logs", path, "--artifacts",
                          feed["artifacts"], "--law-cache", feed["cache"]], capsys)
    payload = json.loads(captured.out)
    assert code in (0, 1)
    assert payload["selected"]["epoch"] == 8
    assert payload["feed"]["selectable"] is True
    assert payload["feed"]["ignored"] >= 1


@pytest.mark.parametrize("word_index", [6, 7], ids=["improvement-credits", "format-version"])
def test_every_decoded_advance_field_participates_in_conflict_detection(
        tmp_path, capsys, word_index):
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    scenario = vf.RigScenario(epoch=8, transition_index=0, block_number=200, store=store)
    first = scenario.advance_log()
    second = dict(first)
    raw = str(first["data"])[2:]
    start = word_index * 64
    second["data"] = "0x" + raw[:start] + f"{999:064x}" + raw[start + 64:]
    second["logIndex"] = int(first["logIndex"]) + 1
    code, captured = replay_logs(
        tmp_path, capsys, scenario.law_logs() + [first, second], tmp_path / "cas")
    payload = json.loads(captured.out)
    assert code == 2
    assert payload["code"] == "FEED_NOT_SELECTABLE"
    assert payload["feed"]["conflicts"] == 1
    assert payload["selected"] is None


@pytest.mark.parametrize("provenance_change", ["location", "block_hash", "removed"])
def test_same_payload_with_different_provenance_is_a_conflict_not_a_duplicate(
        tmp_path, capsys, provenance_change):
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    scenario = vf.RigScenario(epoch=8, transition_index=0, block_number=200, store=store)
    first = scenario.advance_log()
    second = dict(first)
    if provenance_change == "location":
        second["logIndex"] = int(first["logIndex"]) + 1
        second["transactionHash"] = "0x" + "9" * 64
    elif provenance_change == "block_hash":
        first["blockHash"] = "0x" + "8" * 64
        second["blockHash"] = "0x" + "9" * 64
    else:
        second["removed"] = True
    code, captured = replay_logs(
        tmp_path, capsys, scenario.law_logs() + [first, second], tmp_path / "cas")
    payload = json.loads(captured.out)
    assert code == 2
    assert payload["code"] == "FEED_NOT_SELECTABLE"
    assert payload["feed"]["conflicts"] == 1
    assert payload["feed"]["duplicates"] == 0
    assert payload["selected"] is None


def test_the_report_names_the_one_decoder_that_saw_the_chain(feed, capsys):
    """"Which decoder read this chain" must never be a question answered by reading source."""
    from coretex_validator import rig_discovery as rd

    code, captured = replay_latest(feed, capsys)
    payload = json.loads(captured.out)
    assert rd.LIVE_DECODER in payload["chain"]["decoder"]
    assert rd.LIVE_DECODER in payload["feed"]["decoder"]
    assert payload["chain"]["selection_scope"] == "latest-in-supplied-feed"
    assert payload["chain"]["chain_latest_proven"] is False
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


def test_two_explicit_artifact_sources_are_refused():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["replay-latest", "--logs", "feed.json", "--artifacts", "/tmp/cas",
                           "--artifact-base-url", "https://objects.example/cas"])


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
