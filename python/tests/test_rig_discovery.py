# SPDX-License-Identifier: Apache-2.0
"""D-2: the ``replay-*`` commands must decode the lane the deployed contracts emit.

THE DEFECT THESE TESTS PIN. ``replay-latest --rpc https://mainnet.base.org`` scanned the entire
production history — 600k blocks, 200,885 logs from the three addresses the release itself pins —
and reported ``events: 0``, ``selected: null``, exit 2, "the feed carries no confirmed advance".
The chain was at epoch 185 with fourteen epochs of confirmed advances inside that range.

The cause was not a filter or a window: it was the DECODER. Discovery ran through
``sync.sync_logs`` -> ``dispatch.decode``, whose two tables are the retired ``CoreTexMemory*``
memory-frontier lane (the kit manifest publishes it under
``retired_reference_do_not_build_against``) and the staged ``RigCoreTex*`` set that
``rig_events.py:6-13`` says in so many words **no deployed contract emits**. The live registry
emits ``CoreTexStateAdvanced(...)`` -> topic0 ``f2b42259…``; ``dispatch`` ignores it, and
``sync_logs``'s fail-soft "ignore unknown topics" policy — right in isolation — turned a total
lane mismatch into a silent empty feed. Meanwhile ``reproduce`` passed, because its scan goes
through ``rig_events``.

ONE LIVE DECODING AUTHORITY. :mod:`coretex_validator.rig_events` is it. :mod:`rig_discovery` is
the confirmation/ordering/selection layer over that decoder plus the projection into the shape
``replay.replay_advance`` consumes, and the ``replay-*`` commands now go through it.
:mod:`sync` keeps its table for the retired lane's regression fixtures and is no longer consulted
for live discovery — which the first test below asserts directly, because "the legacy table is
dead" is a claim worth failing on rather than a comment.

THE FEED IS REAL. ``fixtures/e184-rig-feed.json`` is thirteen VERBATIM Base mainnet logs from the
43,413-block window the clean-box fetched, including the epoch-184 advance in tx
``0xc77f8725…`` at block 50357019 — the one the shipped decoder ignored.
"""
from __future__ import annotations

import json
import os

import pytest

from coretex_validator import cli
from coretex_validator import release as rel
from coretex_validator import rig_discovery as rd
from coretex_validator import rig_events as rig
from coretex_validator import sync as sy


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
FEED = os.path.join(FIXTURES, "e184-rig-feed.json")
CAS = os.path.join(FIXTURES, "e184-cas")

E184 = {
    "epoch": 184,
    "transition_index": 0,
    "block_number": 50357019,
    "transaction_hash": "0xc77f87259de1570fc6e5b5d42e411afd1377282717f80d837d416911a850593b",
    "parent": "79da014ab4153c1331657f4a5c04bbc69384bf2626d509ac83e71aa578f5a2f6",
    "new": "ef080c11764616b17a307ecb3e7b017cbdc26ff69c9680aa56ff3f2792746bfa",
    "eval_report_hash": "5ba4435ff46e73e4ff1dc568e96c11bed44369e0db98a3fe21e6cba7a63ed60a",
}


def feed_logs():
    with open(FEED, "r", encoding="utf-8") as handle:
        return json.load(handle)["logs"]


def deployment():
    return rel.discover(rel.DEFAULT_PRODUCTION_RELEASE_URL).deployment


def run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured


# --------------------------------------------------------------------------- #
# 1. the decoder, on real bytes
# --------------------------------------------------------------------------- #
def test_the_legacy_dispatch_table_decodes_nothing_in_a_real_production_feed():
    """The RED condition, kept as a permanent assertion.

    Every one of these logs comes from an address the canonical release pins, and the feed
    provably contains a confirmed advance. The retired table finds no advance in any of them, so
    any command that discovers through it reports an idle chain. That fact is what this whole
    module exists to route around, and it must fail loudly if anyone re-points a live command at
    the retired lane."""
    synced = sy.sync_logs(feed_logs())
    assert synced.events == []                        # not one advance, out of a feed with one
    assert synced.epochs == ()
    ignored = {entry["topic0"] for entry in synced.ignored}
    assert rig.STATE_ADVANCED_TOPIC0 in ignored       # the live advance topic, decoded by nothing
    assert rig.CORETEX_CREDIT_ACCEPTED_TOPIC0 in ignored
    assert rig.EPOCH_CONTEXT_SET_TOPIC0 in ignored


def test_the_live_decoder_finds_the_epoch_184_advance_in_the_same_bytes():
    decoded = rig.scan(feed_logs(), deployment())
    assert len(decoded.advances) == 1
    advance = decoded.advances[0]
    assert (advance.epoch, advance.transition_index) == (E184["epoch"], E184["transition_index"])
    assert advance.parent_state_root == E184["parent"]
    assert advance.new_state_root == E184["new"]
    assert advance.eval_report_hash == E184["eval_report_hash"]
    assert advance.provenance.block_number == E184["block_number"]


def test_discovery_confirms_orders_and_selects_by_epoch_then_transition_index():
    feed = rd.sync_rig_logs(feed_logs(), deployment=deployment())
    newest = feed.newest()
    assert newest is not None
    assert (newest.epoch, newest.transition_index) == (184, 0)
    summary = feed.summary()
    assert summary["events"] == 1                     # the documented field name is preserved
    assert summary["advances"] == 1
    assert summary["epochs"] == [184]
    assert rd.LIVE_DECODER in summary["decoder"]
    # the standard rig receipts and the unknown administrative topics are accounted for, not lost
    assert summary["standard_credits"] == 3
    assert summary["ignored"] == 4
    assert summary["undecodable"] == 0


def test_an_unconfirmed_advance_is_pending_rather_than_selected():
    """Confirmation depth is the same fact it always was: above the head is 'not yet', never
    'does not exist'."""
    logs = feed_logs()
    feed = rd.sync_rig_logs(logs, deployment=deployment(),
                            latest_block=E184["block_number"] + 3, confirmation_depth=15)
    assert feed.newest() is None
    assert [a.epoch for a in feed.pending] == [184]
    assert feed.summary()["pending"] == 1


def test_newest_is_epoch_then_index_not_block_order():
    """``transitionIndex`` restarts at 0 every epoch, so the head advance is routinely not the
    last log in block order. Built by relabelling the REAL advance rather than a synthetic one."""
    logs = feed_logs()
    advance = [l for l in logs
               if str(l["topics"][0]).lower().replace("0x", "") == rig.STATE_ADVANCED_TOPIC0][0]
    early_epoch_late_block = dict(advance)
    early_epoch_late_block["topics"] = [advance["topics"][0], "0x" + f"{183:064x}",
                                        "0x" + f"{7:064x}", advance["topics"][3]]
    early_epoch_late_block["blockNumber"] = hex(E184["block_number"] + 900)
    feed = rd.sync_rig_logs(logs + [early_epoch_late_block], deployment=deployment())
    assert (feed.newest().epoch, feed.newest().transition_index) == (184, 0)


# --------------------------------------------------------------------------- #
# 2. the command
# --------------------------------------------------------------------------- #
def test_replay_latest_discovers_the_epoch_184_advance_from_the_offline_feed(tmp_path, capsys):
    """The clean-box's blocking symptom, inverted.

    ``--logs`` is the same discovery as ``--rpc``, offline. Before this it reported
    ``selected: null`` and exit 2 on a feed provably carrying a confirmed advance."""
    code, captured = run(["replay-latest", "--logs", FEED, "--artifacts", CAS,
                          "--law-cache", str(tmp_path / "empty-law-cache")], capsys)
    payload = json.loads(captured.out)

    selected = payload["selected"]
    assert selected is not None, payload.get("note")
    assert selected["epoch"] == 184
    assert selected["transition_index"] == 0
    assert selected["new_frontier_root"] == E184["new"]
    assert selected["parent_frontier_root"] == E184["parent"]
    assert selected["eval_report_hash"] == E184["eval_report_hash"]
    assert selected["block_number"] == E184["block_number"]
    assert selected["transaction_hash"] == E184["transaction_hash"]
    assert payload["feed"]["events"] == 1
    # exit 2 means "there was nothing to replay"; there was.
    assert code != 2


def test_replay_latest_backlogs_rather_than_claiming_an_idle_chain(tmp_path, capsys):
    """The window does not carry epoch 184's OWN context event, so the law pins cannot be
    independently recovered from confirmed logs. That is a BACKLOG — "I found the advance and
    could not check it" — and it is a different fact from "there is no advance", which is what
    the shipped command said."""
    code, captured = run(["replay-latest", "--logs", FEED, "--artifacts", CAS,
                          "--law-cache", str(tmp_path / "empty-law-cache")], capsys)
    payload = json.loads(captured.out)
    assert payload["replayed"]["outcome"] == "BACKLOG"
    assert payload["outcomes"] == {"PASS": 0, "FAIL": 0, "BACKLOG": 1}
    assert code == 0

    code, captured = run(["replay-latest", "--logs", FEED, "--artifacts", CAS,
                          "--law-cache", str(tmp_path / "empty-law-cache"),
                          "--require-complete"], capsys)
    assert code == 1


def test_replay_advance_shares_the_one_decoder(tmp_path, capsys):
    code, captured = run(["replay-advance", "--logs", FEED, "--artifacts", CAS,
                          "--law-cache", str(tmp_path / "empty-law-cache")], capsys)
    payload = json.loads(captured.out)
    assert payload["feed"]["events"] == 1
    assert len(payload["replayed"]) == 1
    assert payload["replayed"][0]["epoch"] == 184
    assert code in (0, 1)


def test_an_epoch_filter_that_matches_nothing_is_still_exit_two(tmp_path, capsys):
    code, captured = run(["replay-advance", "--logs", FEED, "--artifacts", CAS,
                          "--epoch", "9999",
                          "--law-cache", str(tmp_path / "empty-law-cache")], capsys)
    assert code == 2
    assert "nothing was replayed" in json.loads(captured.out)["note"]


def test_an_empty_feed_still_replays_nothing_and_claims_nothing(tmp_path, capsys):
    path = tmp_path / "logs.json"
    path.write_text(json.dumps([]))
    code, captured = run(["replay-latest", "--logs", str(path), "--artifacts", CAS,
                          "--law-cache", str(tmp_path / "c")], capsys)
    assert code == 2
    payload = json.loads(captured.out)
    assert payload["selected"] is None
    assert "nothing was replayed" in payload["note"]


# --------------------------------------------------------------------------- #
# 3. the projection into the replayable shape
# --------------------------------------------------------------------------- #
def test_the_projection_takes_every_field_from_chain_bound_bytes(tmp_path):
    from coretex_validator import publication as pub

    feed = rd.sync_rig_logs(feed_logs(), deployment=deployment())
    store = pub.FilesystemCAS(CAS)
    projected, provenance = rd.project_advance(feed.newest(), store=store)

    assert projected.epoch == 184
    assert projected.parent_frontier_root == E184["parent"]
    assert projected.new_frontier_root == E184["new"]
    assert projected.eval_report_hash == E184["eval_report_hash"]
    # the three fields the rig advance does not carry come from the artifact the CONFIRMED EVENT
    # named, re-hashed on arrival — never from anything the artifact merely asserts about itself
    assert provenance["eval_artifact_root"] == E184["eval_report_hash"]
    assert projected.composition_root == \
        "70714005941d58f1401f5e06f647179a47f416a336b21c92ffbe3127ce42bca8"


def test_an_unpublished_eval_artifact_is_a_backlog_not_a_refutation(tmp_path):
    from coretex_validator import publication as pub

    feed = rd.sync_rig_logs(feed_logs(), deployment=deployment())
    empty = pub.FilesystemCAS(str(tmp_path / "empty-cas"))
    with pytest.raises(rd.ProjectionError) as excinfo:
        rd.project_advance(feed.newest(), store=empty)
    assert excinfo.value.outcome == "BACKLOG"
    assert excinfo.value.code == "missing_artifact"


def test_an_artifact_that_names_a_different_transition_is_a_refutation(tmp_path):
    from coretex_validator import publication as pub

    feed = rd.sync_rig_logs(feed_logs(), deployment=deployment())
    substituted = pub.FilesystemCAS(str(tmp_path / "cas"))
    with open(os.path.join(CAS, E184["eval_report_hash"]), "rb") as handle:
        raw = handle.read()
    os.makedirs(str(tmp_path / "cas"), exist_ok=True)
    # swap the artifact's parent root; the address is left alone so the substitution is the
    # ARTIFACT disagreeing with the confirmed event, not a transport fault
    with open(os.path.join(str(tmp_path / "cas"), E184["eval_report_hash"]), "wb") as handle:
        handle.write(raw.replace(E184["parent"].encode(), (b"ab" * 32)))
    with pytest.raises(rd.ProjectionError) as excinfo:
        rd.project_advance(feed.newest(), store=substituted)
    assert excinfo.value.outcome == "FAIL"
