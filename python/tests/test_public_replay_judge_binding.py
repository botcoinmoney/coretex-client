# SPDX-License-Identifier: Apache-2.0
"""Public replay must accept — and insist on — the sealed ``cap.judge.v1`` binding.

These tests never run a fixed-suite evaluation and never need the sealed rows artifact: the
questions here are which refusals happen in the parent, what reaches the network-denied child, and
what the consumer sees.  The frozen engine inside the child owns the actual root check.
"""
from __future__ import annotations

import inspect
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Mapping

import pytest

from coretex_validator import benchmark_replay, cli

ENHANCED_ROOT = "a" * 64
TABLE_ROOT = "b" * 64
REPORT_ROOT = "c" * 64


def _report(*, judged: bool) -> dict[str, Any]:
    body: dict[str, Any] = {"profile_id": "conv.pref", "round_id": 1}
    if judged:
        body["judge"] = {
            "capability": "cap.judge.v1",
            "descriptor": {"id": "jev", "version": "1"},
            "descriptor_mapping": {"release": "product"},
            "enhanced_replay_root": ENHANCED_ROOT,
            "table_root": TABLE_ROOT,
        }
    return body


def _runner(monkeypatch: pytest.MonkeyPatch, run) -> benchmark_replay.ReleaseBenchmarkRunner:
    """A runner whose private materialization is never opened; only ``_run`` is exercised."""
    monkeypatch.setattr(
        benchmark_replay.evaluation, "validate_parent_stored_vector",
        lambda vector, **_kwargs: dict(vector))
    runner = benchmark_replay.ReleaseBenchmarkRunner.__new__(
        benchmark_replay.ReleaseBenchmarkRunner)
    monkeypatch.setattr(type(runner), "_run", run, raising=True)
    return runner


def _replay(runner: benchmark_replay.ReleaseBenchmarkRunner, report: Mapping[str, Any],
            **kwargs) -> Mapping[str, Any]:
    return runner.replay_report(
        report, expected_root=REPORT_ROOT,
        incumbent_execution={"release_root": "d" * 64},
        parent_stored_vector={"source_kind": "genesis"}, **kwargs)


def _rows(tmp_path: Path) -> Path:
    path = tmp_path / "sealed-judgments.jsonl"
    path.write_text('{"case_id": "one"}\n', encoding="utf-8")
    return path


def test_a_judged_report_without_its_table_is_refused_as_judge_table_required(
        monkeypatch: pytest.MonkeyPatch):
    def never(*_args, **_kwargs):
        raise AssertionError("a judged report without its table must not spawn a replay child")

    runner = _runner(monkeypatch, never)
    with pytest.raises(benchmark_replay.BenchmarkReplayError) as raised:
        _replay(runner, _report(judged=True))
    assert raised.value.code == "judge_table_required"
    assert "judge_table_required" in str(raised.value)
    assert TABLE_ROOT in str(raised.value)


def test_an_unjudged_report_with_a_table_is_refused(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    def never(*_args, **_kwargs):
        raise AssertionError("an unjudged report must not be replayed against any table")

    runner = _runner(monkeypatch, never)
    with pytest.raises(benchmark_replay.BenchmarkReplayError) as raised:
        _replay(runner, _report(judged=False), judge_rows_path=str(_rows(tmp_path)))
    assert raised.value.code == "judge_table_unexpected"


def test_a_missing_rows_file_is_refused_before_execution(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    def never(*_args, **_kwargs):
        raise AssertionError("an unreadable table must not spawn a replay child")

    runner = _runner(monkeypatch, never)
    with pytest.raises(benchmark_replay.BenchmarkReplayError) as raised:
        _replay(runner, _report(judged=True),
                judge_rows_path=str(tmp_path / "absent-judgments.jsonl"))
    assert raised.value.code == "judge_table_unreadable"


def test_the_rows_path_reaches_the_child_payload_and_the_frozen_replay_entry_point(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    captured: dict[str, Any] = {}

    def capture(_self, payload):
        captured.update(payload)
        return {"reproduced": True, "report_root": REPORT_ROOT,
                "enhanced_replay_root": ENHANCED_ROOT, "judge_table_root": TABLE_ROOT}

    runner = _runner(monkeypatch, capture)
    rows = _rows(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = _replay(runner, _report(judged=True), judge_rows_path=rows.name)

    assert captured["judge_rows"] == str(rows.resolve())
    assert Path(captured["judge_rows"]).is_absolute()
    assert result["enhanced_replay_root"] == ENHANCED_ROOT
    assert result["judge_table_root"] == TABLE_ROOT
    source = inspect.getsource(benchmark_replay).split("_CHILD = r'''", 1)[1]
    child = source.split("'''", 1)[0]
    assert "judge_rows_path=payload.get(\"judge_rows\")" in child
    assert "from validator.replay import replay_report" in child


def test_a_reproduced_judged_replay_must_match_the_reports_own_enhanced_replay_root(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    def diverging(_self, _payload):
        return {"reproduced": True, "report_root": REPORT_ROOT,
                "enhanced_replay_root": "e" * 64, "judge_table_root": TABLE_ROOT}

    runner = _runner(monkeypatch, diverging)
    with pytest.raises(benchmark_replay.BenchmarkReplayError) as raised:
        _replay(runner, _report(judged=True), judge_rows_path=str(_rows(tmp_path)))
    assert raised.value.code == "enhanced_replay_root_mismatch"

    def absent(_self, _payload):
        return {"reproduced": True, "report_root": REPORT_ROOT, "judge_table_root": TABLE_ROOT}

    runner = _runner(monkeypatch, absent)
    with pytest.raises(benchmark_replay.BenchmarkReplayError) as raised:
        _replay(runner, _report(judged=True), judge_rows_path=str(_rows(tmp_path)))
    assert raised.value.code == "enhanced_replay_root_mismatch"

    def other_table(_self, _payload):
        return {"reproduced": True, "report_root": REPORT_ROOT,
                "enhanced_replay_root": ENHANCED_ROOT, "judge_table_root": "f" * 64}

    runner = _runner(monkeypatch, other_table)
    with pytest.raises(benchmark_replay.BenchmarkReplayError) as raised:
        _replay(runner, _report(judged=True), judge_rows_path=str(_rows(tmp_path)))
    assert raised.value.code == "judge_table_root_mismatch"


def test_the_unjudged_replay_path_is_unchanged(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, Any] = {}

    def capture(_self, payload):
        captured.update(payload)
        return {"reproduced": True, "report_root": REPORT_ROOT}

    runner = _runner(monkeypatch, capture)
    result = _replay(runner, _report(judged=False))

    assert set(captured) == {"mode", "report", "expected_root", "incumbent",
                             "parent_stored_vector"}
    assert "judge_rows" not in captured
    assert set(result) == {"reproduced", "report_root"}


def test_the_screener_and_presign_paths_thread_the_table_only_when_given():
    from coretex_validator import replay as replay_module

    for function in (replay_module.replay_screener, replay_module.pre_sign_reexecute):
        parameter = inspect.signature(function).parameters["judge_rows_path"]
        assert parameter.default is None
    assert replay_module._judge_rows_argument(None) == {}  # noqa: SLF001 - wiring unit test
    assert replay_module._judge_rows_argument("/sealed/rows.jsonl") == {  # noqa: SLF001
        "judge_rows_path": "/sealed/rows.jsonl"}
    assert replay_module._judge_replay_evidence(  # noqa: SLF001
        {"reproduced": True, "report_root": REPORT_ROOT}) == {}
    assert replay_module._judge_replay_evidence({  # noqa: SLF001
        "enhanced_replay_root": ENHANCED_ROOT, "judge_table_root": TABLE_ROOT}) == {
            "enhanced_replay_root": ENHANCED_ROOT, "judge_table_root": TABLE_ROOT}


def test_the_consumer_cli_exposes_replay_report_with_judge_rows(tmp_path: Path):
    parser = cli.build_parser()
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(judged=True)), encoding="utf-8")
    arguments = [
        "replay-report", "--release", str(tmp_path / "release"), "--report", str(report),
        "--expect-root", REPORT_ROOT,
        "--incumbent-execution", str(tmp_path / "incumbent.json"),
        "--parent-stored-vector", str(tmp_path / "witness.json"),
    ]
    parsed = parser.parse_args(arguments)
    assert parsed.judge_rows is None
    assert parser.parse_args(arguments + ["--judge-rows", "/sealed/rows.jsonl"]).judge_rows \
        == "/sealed/rows.jsonl"

    stream = io.StringIO()
    with redirect_stdout(stream):
        status = cli.main(arguments)
    assert status == 1
    emitted = json.loads(stream.getvalue())
    assert emitted == {"code": "judge_table_required", "reason": emitted["reason"],
                       "reproduced": False}
    assert "judge_table_required" in emitted["reason"]
