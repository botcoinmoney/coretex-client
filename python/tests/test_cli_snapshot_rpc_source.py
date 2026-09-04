from __future__ import annotations

import pytest

from coretex_validator import cli


def _snapshot_args(*extra: str):
    parser = cli.build_parser()
    return parser.parse_args([
        "snapshot",
        "--release", "release-dir",
        "--activation", "activation.json",
        "--objects", "https://coordinator.example/coretex/v5/object/",
        "--out", "snapshot-out",
        *extra,
    ])


def test_snapshot_rpc_can_be_read_from_private_file(tmp_path):
    rpc_file = tmp_path / "rpc-url"
    rpc_file.write_text("https://rpc.example/token\n", encoding="utf-8")

    args = _snapshot_args("--rpc-file", str(rpc_file))

    assert cli._read_rpc_url(args) == "https://rpc.example/token"  # noqa: SLF001


def test_snapshot_rpc_can_be_read_from_environment(monkeypatch):
    monkeypatch.setenv("CORETEX_TEST_RPC_URL", "https://rpc.example/from-env")

    args = _snapshot_args("--rpc-env", "CORETEX_TEST_RPC_URL")

    assert cli._read_rpc_url(args) == "https://rpc.example/from-env"  # noqa: SLF001


def test_snapshot_rpc_file_is_single_line(tmp_path):
    rpc_file = tmp_path / "rpc-url"
    rpc_file.write_text("https://rpc.example/a\nhttps://rpc.example/b\n", encoding="utf-8")

    args = _snapshot_args("--rpc-file", str(rpc_file))

    with pytest.raises(ValueError, match="exactly one line"):
        cli._read_rpc_url(args)  # noqa: SLF001


def test_snapshot_requires_exactly_one_rpc_source():
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([
            "snapshot",
            "--release", "release-dir",
            "--activation", "activation.json",
            "--objects", "https://coordinator.example/coretex/v5/object/",
            "--out", "snapshot-out",
        ])
    with pytest.raises(SystemExit):
        _snapshot_args("--rpc", "https://rpc.example/a", "--rpc-env", "CORETEX_TEST_RPC_URL")
