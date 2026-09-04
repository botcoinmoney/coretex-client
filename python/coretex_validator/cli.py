# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for the first-public validator."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from . import __version__


def _reject_duplicates(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = member
    return value


def _emit(value: Any) -> None:
    json.dump(value, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        value = json.load(
            handle, object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value {token!r}")))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _cmd_verify_release(args: argparse.Namespace) -> int:
    from . import release

    installed = release.load(args.release)
    result = {
        "artifacts": sorted(installed.artifacts),
        "genesis_frontier_root": installed.genesis_frontier_root,
        "objects": sorted(installed.objects),
        "release_root": installed.release_root,
        "sequence": installed.release.raw["sequence"],
        "version": installed.release.raw["version"],
    }
    if args.activation:
        result["activation"] = installed.activation(args.activation).as_document()["activation"]
    _emit(result)
    return 0


def _cmd_verify_descriptor(args: argparse.Namespace) -> int:
    from . import frontier, release, replay, rig_events

    installed = release.load(args.release)
    activation = installed.activation(args.activation)
    activation.require_epoch(args.epoch)
    descriptor_bytes = bytes.fromhex(args.descriptor.removeprefix("0x"))
    descriptor = rig_events.decode_transition_descriptor(
        descriptor_bytes,
        expected_patch_hash=args.patch_hash,
        parent_state_root=args.parent_root,
        new_state_root=args.new_root,
        transition_format_version=args.transition_format_version)
    with open(args.transition_artifact, "rb") as handle:
        artifact_bytes = handle.read()
    artifact = rig_events.verify_transition_artifact_bytes(
        artifact_bytes, descriptor=descriptor,
        score_delta_ppm=args.score_after_ppm - args.score_before_ppm,
        epoch_context_root_=args.epoch_context_root)
    parent = _load_json(args.parent_manifest)
    context = _load_json(args.epoch_context)
    pins = replay.verify_epoch_context(
        context, args.epoch, args.epoch_context_root, release=installed,
        active_frontier_root=args.epoch_parent_root.removeprefix("0x"))
    child = rig_events.replay_transition_artifact(parent, artifact, epoch_pins=pins)
    observed = frontier.frontier_root(child)
    if observed != args.new_root.removeprefix("0x"):
        raise ValueError(f"transition replay produced {observed}, not {args.new_root}")
    _emit({
        "activation": activation.as_document()["activation"],
        "checks": ["descriptor_v3", "transition_artifact_address", "transition_replay"],
        "new_state_root": observed,
        "outcome": "PASS",
        "patch_artifact_hash": descriptor.patch_artifact_hash,
        "release_root": installed.release_root,
    })
    return 0


def _cmd_topics(_args: argparse.Namespace) -> int:
    from . import rig_events

    _emit({name: topic for topic, name in sorted(rig_events.EVENT_NAMES.items())})
    return 0


def _cmd_selftest(_args: argparse.Namespace) -> int:
    from . import canonical_suite
    from .keccak256 import keccak256
    from .rig_receipt_binding import TRANSITION_DESCRIPTOR_BYTES, TRANSITION_DESCRIPTOR_VERSION

    if keccak256(b"").hex() \
            != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise RuntimeError("keccak256 known-answer test failed")
    _emit({
        "descriptor_bytes": TRANSITION_DESCRIPTOR_BYTES,
        "descriptor_version": TRANSITION_DESCRIPTOR_VERSION,
        "law_id": canonical_suite.suite_law_id(),
        "ok": True,
        "suite_root": canonical_suite.suite_root(),
        "version": __version__,
    })
    return 0


def _read_rpc_url(args: argparse.Namespace) -> str:
    sources = [
        bool(getattr(args, "rpc", None)),
        bool(getattr(args, "rpc_file", None)),
        bool(getattr(args, "rpc_env", None)),
    ]
    if sum(sources) != 1:
        raise ValueError("choose exactly one RPC source: --rpc, --rpc-file, or --rpc-env")
    if args.rpc:
        return args.rpc
    if args.rpc_file:
        path = Path(args.rpc_file)
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError(f"cannot read RPC URL file {path}: {exc}") from exc
        if "\n" in value or "\r" in value:
            raise ValueError("RPC URL file must contain exactly one line")
        if not value:
            raise ValueError("RPC URL file is empty")
        return value
    name = args.rpc_env
    if not name or not name.replace("_", "A").isalnum() or not (
            name[0].isalpha() or name[0] == "_"):
        raise ValueError("--rpc-env must name one environment variable")
    value = os.environ.get(name, "").strip()
    if "\n" in value or "\r" in value:
        raise ValueError("RPC URL environment value must contain exactly one line")
    if not value:
        raise ValueError(f"RPC URL environment variable {name} is empty or unset")
    return value


def _cmd_snapshot(args: argparse.Namespace) -> int:
    from . import release, snapshot
    from .rpc import JsonRpc

    installed = release.load(args.release)
    activation = installed.activation(args.activation)
    rpc_url = _read_rpc_url(args)
    document = snapshot.build_from_public(
        release=installed, activation=activation, rpc=JsonRpc(rpc_url),
        object_base_url=args.objects, output_dir=args.out,
        to_block=args.to_block, confirmation_depth=args.confirmations)
    _emit({
        "epoch": document["epoch"]["id"],
        "frontier_root": document["frontier"]["root"],
        "output": args.out,
        "profiles": {
            profile: {"exec": row["exec"], "release_root": row["release_root"]}
            for profile, row in document["profiles"].items()
        },
        "release_root": document["release_root"],
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="coretex-validator", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify-release", help="verify a closed release directory")
    verify.add_argument("--release", required=True)
    verify.add_argument("--activation")
    verify.set_defaults(func=_cmd_verify_release)

    descriptor = commands.add_parser(
        "verify-descriptor", help="replay one descriptor-v3 transition")
    descriptor.add_argument("--release", required=True)
    descriptor.add_argument("--activation", required=True)
    descriptor.add_argument("--epoch", required=True, type=int)
    descriptor.add_argument("--epoch-context", required=True)
    descriptor.add_argument("--epoch-context-root", required=True)
    descriptor.add_argument("--parent-manifest", required=True)
    descriptor.add_argument("--parent-root", required=True)
    descriptor.add_argument(
        "--epoch-parent-root", required=True,
        help="the epoch's CoreTexEpochContextSet parent (distinct after transition index 0)")
    descriptor.add_argument("--new-root", required=True)
    descriptor.add_argument("--descriptor", required=True)
    descriptor.add_argument("--patch-hash", required=True)
    descriptor.add_argument("--transition-artifact", required=True)
    descriptor.add_argument("--transition-format-version", type=int, default=0x21)
    descriptor.add_argument("--score-before-ppm", required=True, type=int)
    descriptor.add_argument("--score-after-ppm", required=True, type=int)
    descriptor.set_defaults(func=_cmd_verify_descriptor)

    topics = commands.add_parser("topics", help="print the current public event topics")
    topics.set_defaults(func=_cmd_topics)
    snapshot = commands.add_parser(
        "snapshot", help="materialize confirmed current routing for the memory adapter")
    snapshot.add_argument("--release", required=True)
    snapshot.add_argument(
        "--activation", required=True,
        help="local canonical record or coordinator /coretex/v5/activation URL")
    rpc_source = snapshot.add_mutually_exclusive_group(required=True)
    rpc_source.add_argument(
        "--rpc",
        help="JSON-RPC URL. Convenient, but visible in process listings while a long scan runs.")
    rpc_source.add_argument(
        "--rpc-file",
        help="path to a single-line JSON-RPC URL file; preferred for secret-bearing URLs")
    rpc_source.add_argument(
        "--rpc-env",
        help="environment variable containing the JSON-RPC URL")
    snapshot.add_argument(
        "--objects", required=True,
        help="public /coretex/v5/object/ base URL (the validator sends hashRule)")
    snapshot.add_argument("--out", required=True)
    snapshot.add_argument("--to-block", type=int)
    snapshot.add_argument("--confirmations", type=int, default=12)
    snapshot.set_defaults(func=_cmd_snapshot)
    selftest = commands.add_parser("selftest", help="run embedded identity checks")
    selftest.set_defaults(func=_cmd_selftest)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.func(args))
    except Exception as exc:  # noqa: BLE001 - stable command boundary
        _emit({"error": type(exc).__name__, "message": str(exc), "outcome": "FAIL"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
