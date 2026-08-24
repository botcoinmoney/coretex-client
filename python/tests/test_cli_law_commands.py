# SPDX-License-Identifier: Apache-2.0
"""The CLI surface of ``sync-law`` / ``replay-advance`` / ``verify-receipt`` (spec §9).

Exit codes are the interface a CI job reads, so they are asserted directly rather than inferred
from output. The law-cache ORDERING rule gets its own test because its failure mode is invisible:
pins applied after ``replay`` was imported are a no-op that looks like success, and the run would
BACKLOG at step 5 with a verified cache sitting on disk.
"""
from __future__ import annotations

import json
import os

import pytest

from coretex_validator import cli, law

from test_law_sync import build_publication, write_set                          # noqa: F401


@pytest.fixture()
def published(tmp_path):
    publication_root, manifest_bytes, objects = build_publication()
    mirror = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects)
    return {"root": publication_root, "mirror": mirror, "cache": str(tmp_path / "cache")}


def run(argv, capsys):
    code = cli.main(argv)
    captured = capsys.readouterr()
    return code, captured


# --------------------------------------------------------------------------- #
# the parser
# --------------------------------------------------------------------------- #
def test_the_existing_subcommands_are_unchanged():
    parser = cli.build_parser()
    actions = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    names = set(actions[0].choices)
    assert {"reproduce", "verify-release", "reproduce-snapshot", "topics", "selftest"} <= names
    assert {"sync-law", "replay-advance", "verify-receipt", "setup"} <= names


def test_selftest_still_passes_from_the_cli(capsys):
    code, captured = run(["selftest"], capsys)
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["version"] == "0.4.4"


# --------------------------------------------------------------------------- #
# sync-law
# --------------------------------------------------------------------------- #
def test_sync_law_reports_the_cache_it_built(published, capsys):
    code, captured = run(["sync-law", "--mirror", published["mirror"], "--root",
                          published["root"], "--cache-dir", published["cache"]], capsys)
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["law"]["publication_root"] == published["root"]
    assert set(payload["law"]["env"]) == set(law.ENV_PINS)
    assert sorted(payload["law"]["receipt"]["trees"]) == sorted(law.REQUIRED_TREES)
    assert "Pass --law-root explicitly" in payload["next"]
    assert "run setup" in payload["next"]
    assert "automatically" not in payload["next"]


def test_print_export_emits_only_shell_lines(published, capsys):
    code, captured = run(["sync-law", "--mirror", published["mirror"], "--root",
                          published["root"], "--cache-dir", published["cache"],
                          "--print-export"], capsys)
    assert code == 0
    lines = [line for line in captured.out.splitlines() if line]
    assert len(lines) == 3
    assert all(line.startswith("export CORETEX_") for line in lines)
    with pytest.raises(ValueError):                            # deliberately NOT JSON
        json.loads(captured.out)


def test_a_mirror_that_serves_nothing_exits_2(tmp_path, capsys):
    code, captured = run(["sync-law", "--mirror", str(tmp_path), "--root", "a" * 64,
                          "--cache-dir", str(tmp_path / "c")], capsys)
    assert code == 2
    assert "no layout" in captured.err


def test_sync_law_without_a_root_refuses_and_says_where_to_get_one(tmp_path, capsys):
    """No default publication. The remedy names DISCOVERY, not a value to paste."""
    code, captured = run(["sync-law", "--mirror", str(tmp_path), "--cache-dir",
                          str(tmp_path / "c")], capsys)
    assert code == 2
    assert "--root" in captured.err
    assert "setup" in captured.err
    assert captured.out == ""
    # and nothing was installed under the cache directory
    assert not os.path.isdir(str(tmp_path / "c"))


def test_a_bad_root_exits_2(published, capsys):
    code, captured = run(["sync-law", "--mirror", published["mirror"], "--root", "nope",
                          "--cache-dir", published["cache"]], capsys)
    assert code == 2
    assert "64 lowercase hex" in captured.err


# --------------------------------------------------------------------------- #
# the pins reach the later commands
# --------------------------------------------------------------------------- #
def test_a_later_command_picks_the_active_tuple_up_without_being_told(
        published, monkeypatch, capsys):
    import sys

    run(["sync-law", "--mirror", published["mirror"], "--root", published["root"],
         "--cache-dir", published["cache"]], capsys)
    law.write_active_install(
        cache_dir=published["cache"], publication_root=published["root"],
        kit_manifest_hash="1" * 64, miner_kit_sha256="2" * 64,
        miner_kit_filename="coretex-validator-miner-kit-" + "2" * 64 + ".tar",
        miner_kit_tree_sha256="3" * 64)
    for pin in law.ENV_PINS:
        monkeypatch.delenv(pin, raising=False)
    # `conftest` imports `replay` to build its aliases, which is exactly the ordering the
    # activation guard refuses. A real CLI process has not imported it at this point (asserted
    # separately below), so the test reproduces THAT state rather than working around the guard.
    monkeypatch.delitem(sys.modules, "coretex_validator.replay", raising=False)

    args = type("A", (), {"law_cache": published["cache"], "law_root": None,
                          "no_law_cache": False})()
    block = cli._activate_law(args)
    assert block["used"] is True and block["publication_root"] == published["root"]
    assert os.environ[law.ENV_BENCHMARK_V2].endswith("benchmark-v2")


def test_the_cli_has_not_imported_replay_by_the_time_it_parses():
    """The guard above is only ever a real refusal if the CLI's own ordering is right.

    ``build_parser`` touches ``law`` and ``release``; if either ever grew an import of ``replay``,
    every invocation would trip the activation guard. Asserted here so that regression is caught
    at the moment it is introduced rather than in the field.
    """
    import subprocess
    import sys

    probe = ("import sys; from coretex_validator import cli; cli.build_parser(); "
             "print('coretex_validator.replay' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert out.stdout.strip() == "False", out.stderr


def test_no_law_cache_is_honoured_and_reported(published, capsys):
    args = type("A", (), {"law_cache": published["cache"], "law_root": None,
                          "no_law_cache": True})()
    block = cli._activate_law(args)
    assert block["used"] is False and "--no-law-cache" in block["reason"]


def test_an_explicitly_named_root_that_is_absent_is_an_error_not_a_fallback(tmp_path):
    args = type("A", (), {"law_cache": str(tmp_path), "law_root": "a" * 64,
                          "no_law_cache": False})()
    with pytest.raises(law.LawCacheError):
        cli._activate_law(args)


def test_no_cache_at_all_reports_honestly_rather_than_failing(tmp_path):
    args = type("A", (), {"law_cache": str(tmp_path), "law_root": None,
                          "no_law_cache": False})()
    block = cli._activate_law(args)
    assert block["used"] is False and "setup" in block["reason"]


# --------------------------------------------------------------------------- #
# replay-advance
# --------------------------------------------------------------------------- #
def test_replay_advance_with_no_matching_advance_says_so_and_exits_2(tmp_path, capsys):
    logs = tmp_path / "logs.json"
    logs.write_text(json.dumps([]))
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    code, captured = run(["replay-advance", "--logs", str(logs), "--artifacts", str(artifacts),
                          "--law-cache", str(tmp_path / "empty-cache")], capsys)
    assert code == 2
    payload = json.loads(captured.out)
    assert "nothing was replayed and nothing is claimed" in payload["note"]
    assert payload["outcomes"] == {"PASS": 0, "FAIL": 0, "BACKLOG": 0}


def test_replay_advance_refuses_a_logs_file_that_is_not_logs(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"nope": 1}))
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    code, captured = run(["replay-advance", "--logs", str(bad), "--artifacts", str(artifacts),
                          "--law-cache", str(tmp_path / "empty-cache")], capsys)
    assert code == 2
    assert "carries no logs list" in captured.err


# --------------------------------------------------------------------------- #
# verify-receipt
# --------------------------------------------------------------------------- #
def test_verify_receipt_without_a_law_cache_backlogs_rather_than_failing(tmp_path, capsys):
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"receipt": {}, "receipt_hash": "0" * 64}))
    code, captured = run(["verify-receipt", str(receipt), "--law-cache",
                          str(tmp_path / "empty-cache")], capsys)
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["outcome"] == "BACKLOG"
    assert payload["code"] == "SANDBOX_UNAVAILABLE"
    assert payload["law"]["used"] is False


def test_require_complete_turns_that_backlog_into_a_failure(tmp_path, capsys):
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"receipt": {}, "receipt_hash": "0" * 64}))
    code, captured = run(["verify-receipt", str(receipt), "--law-cache",
                          str(tmp_path / "empty-cache"), "--require-complete"], capsys)
    assert code == 1
    assert json.loads(captured.out)["outcome"] == "BACKLOG"
    assert "--require-complete" in captured.err
