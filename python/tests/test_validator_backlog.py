# SPDX-License-Identifier: Apache-2.0
"""Cut V5-E — THE BACKLOG: a third outcome, persisted, never dropped.

§17.236: "unresolved artifact/context work is PERSISTED as a typed backlog entry […] never
silently passed and never dropped. A backlog entry is a distinct outcome from PASS and from
FAIL." Everything here attacks one of the two ways that requirement is usually broken: a
two-valued verdict that forces BACKLOG to masquerade, and a journal that loses rows.
"""
from __future__ import annotations

import json

import pytest

import frontier as fr
from validator import backlog as bl

from validator_fixtures import Scenario


@pytest.fixture()
def scenario():
    return Scenario()


# --------------------------------------------------------------------------- #
# three outcomes
# --------------------------------------------------------------------------- #
def test_there_are_exactly_three_outcomes():
    assert bl.OUTCOMES == (bl.PASS, bl.FAIL, bl.BACKLOG)


def test_backlog_is_neither_pass_nor_fail():
    assert bl.BACKLOG != bl.PASS and bl.BACKLOG != bl.FAIL
    assert bl.BACKLOG.is_backlog and not bl.BACKLOG.is_pass and not bl.BACKLOG.is_fail


def test_only_pass_is_ok():
    assert bl.PASS.ok is True
    assert bl.FAIL.ok is False
    assert bl.BACKLOG.ok is False


def test_outcomes_serialize_as_their_own_names():
    assert json.loads(json.dumps({"o": str(bl.BACKLOG)}))["o"] == "BACKLOG"


# --------------------------------------------------------------------------- #
# typed reasons
# --------------------------------------------------------------------------- #
def test_the_four_directive_reasons_exist():
    for reason in (bl.MISSING_ARTIFACT, bl.UNFETCHABLE_MANIFEST, bl.SANDBOX_UNAVAILABLE,
                   bl.ORACLE_SCREEN_UNAVAILABLE):
        assert reason in bl.REASONS


def test_every_reason_carries_a_remediation():
    for reason, remediation in bl.REASONS.items():
        assert remediation and len(remediation) > 40, reason


def test_the_reason_set_is_closed():
    with pytest.raises(bl.UnknownReasonError):
        bl.BacklogEntry(reason="whatever", detail="x")


def test_entry_id_is_stable_across_processes(scenario):
    event = scenario.event()
    a = bl.missing_artifact("gone", event=event)
    b = bl.missing_artifact("still gone", event=event)
    assert a.id == b.id                                # identity is the item, not the message


def test_entry_id_separates_different_reasons_for_one_event(scenario):
    event = scenario.event()
    assert bl.missing_artifact("x", event=event).id != bl.sandbox_unavailable("x",
                                                                             event=event).id


def test_entry_validates_its_roots():
    with pytest.raises(fr.FrontierError):
        bl.BacklogEntry(reason=bl.MISSING_ARTIFACT, detail="x", eval_report_hash="0xABC")


def test_entry_dict_is_canonicalizable_and_carries_the_outcome(scenario):
    entry = bl.missing_artifact("not published", event=scenario.event())
    record = entry.as_dict()
    assert record["outcome"] == "BACKLOG"
    assert record["format"] == bl.BACKLOG_ENTRY_FORMAT
    fr.canonical_bytes(record)                         # no floats, no nulls, no duplicate keys


# --------------------------------------------------------------------------- #
# in-memory behaviour
# --------------------------------------------------------------------------- #
def test_re_observing_bumps_attempts_and_keeps_the_first_detail(scenario):
    log = bl.Backlog()
    event = scenario.event()
    log.record(bl.missing_artifact("first sighting", event=event))
    stored = log.record(bl.missing_artifact("second sighting", event=event))
    assert len(log) == 1
    assert stored.attempts == 2
    assert stored.detail == "first sighting"
    assert stored.last_detail == "second sighting"


def test_resolving_keeps_the_row(scenario):
    log = bl.Backlog()
    entry = log.record(bl.missing_artifact("gone", event=scenario.event()))
    log.resolve(entry.id, "artifact republished")
    assert len(log) == 1
    assert log.open_entries() == []
    assert log.resolved_entries()[0].resolution == "artifact republished"


def test_a_resolved_item_that_recurs_reopens(scenario):
    log = bl.Backlog()
    entry = log.record(bl.missing_artifact("gone", event=scenario.event()))
    log.resolve(entry.id)
    reopened = log.record(bl.missing_artifact("gone again", event=scenario.event()))
    assert reopened.resolved is False and reopened.attempts == 2


def test_resolving_an_unknown_id_is_an_error():
    with pytest.raises(bl.BacklogError):
        bl.Backlog().resolve("nope")


def test_by_reason_filters(scenario):
    log = bl.Backlog()
    log.record(bl.missing_artifact("a", event=scenario.event()))
    log.record(bl.oracle_screen_unavailable("b", event=scenario.event()))
    assert len(log.by_reason(bl.MISSING_ARTIFACT)) == 1
    with pytest.raises(bl.UnknownReasonError):
        log.by_reason("nope")


# --------------------------------------------------------------------------- #
# persistence
# --------------------------------------------------------------------------- #
def test_entries_survive_a_restart(tmp_path, scenario):
    path = str(tmp_path / "backlog.jsonl")
    first = bl.FileBacklog(path)
    first.record(bl.missing_artifact("not published", event=scenario.event()))
    first.record(bl.sandbox_unavailable("no runtime here", event=scenario.event()))

    second = bl.FileBacklog(path)
    assert len(second) == 2
    assert {e.reason for e in second.open_entries()} == {bl.MISSING_ARTIFACT,
                                                        bl.SANDBOX_UNAVAILABLE}


def test_the_journal_is_append_only(tmp_path, scenario):
    path = str(tmp_path / "backlog.jsonl")
    log = bl.FileBacklog(path)
    entry = log.record(bl.missing_artifact("gone", event=scenario.event()))
    log.record(bl.missing_artifact("gone again", event=scenario.event()))
    log.resolve(entry.id, "republished")
    with open(path, encoding="utf-8") as fh:
        lines = [line for line in fh.read().splitlines() if line]
    assert len(lines) == 3                             # nothing was rewritten in place
    assert [json.loads(line)["action"] for line in lines] == ["record", "record", "resolve"]


def test_a_resolution_replays_from_the_journal(tmp_path, scenario):
    path = str(tmp_path / "backlog.jsonl")
    log = bl.FileBacklog(path)
    entry = log.record(bl.missing_artifact("gone", event=scenario.event()))
    log.resolve(entry.id, "republished")
    assert bl.FileBacklog(path).open_entries() == []


def test_an_edited_journal_is_refused(tmp_path, scenario):
    path = str(tmp_path / "backlog.jsonl")
    log = bl.FileBacklog(path)
    log.record(bl.missing_artifact("gone", event=scenario.event()))
    with open(path, encoding="utf-8") as fh:
        record = json.loads(fh.read().strip())
    record["entry"]["epoch"] = 999                     # id no longer recomputes
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
    with pytest.raises(bl.JournalError, match="has been edited"):
        bl.FileBacklog(path)


def test_a_non_journal_line_is_refused(tmp_path):
    path = str(tmp_path / "backlog.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write('{"hello":"world"}\n')
    with pytest.raises(bl.JournalError):
        bl.FileBacklog(path)


def test_snapshot_is_canonicalizable(tmp_path, scenario):
    log = bl.FileBacklog(str(tmp_path / "b.jsonl"))
    log.record(bl.unfetchable_manifest("no manifest", event=scenario.event(),
                                       subject=scenario.parent_root))
    fr.canonical_bytes(log.snapshot())
    assert log.snapshot()["open"] == 1


def test_observed_at_is_injected_never_wall_clock(scenario):
    entry = bl.missing_artifact("gone", event=scenario.event(), observed_at=1234)
    assert entry.as_dict()["observed_at"] == 1234
    assert "observed_at" not in bl.missing_artifact("gone", event=scenario.event()).as_dict()
