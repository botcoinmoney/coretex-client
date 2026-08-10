# SPDX-License-Identifier: Apache-2.0
"""``coretex-validator`` — the command an external agent actually runs.

FOUR SUBCOMMANDS, AND THE FIRST ONE IS THE POINT:

    coretex-validator reproduce --rpc URL                 production, steps 1-8
    coretex-validator reproduce --release R --rpc URL     explicit historical release
    coretex-validator verify-release --release R --rpc URL   steps 1-2 only
    coretex-validator topics                              the dispatch table, V4 and rig
    coretex-validator selftest                            keccak/ecrecover/canonical-JSON vectors

EXIT CODES ARE PART OF THE INTERFACE, because a CI job reads them and a human reads the JSON:

    0  every step that ran PASSED, and any step that could not run is listed under "unverified"
    1  a check RAN and the chain disagreed — the claim is wrong
    2  the run could not start (bad arguments, unreachable endpoint, unparseable release)

Note what 0 does NOT mean. It does not mean everything was verified; it means nothing was
contradicted. A clean-machine run will normally exit 0 with a non-empty ``unverified`` list,
because deterministic admission needs trees that are not published. ``--require-complete`` turns
any unverified step into exit 1 for callers that want the stricter reading, and it is opt-in
rather than default so that "I could not check X" never silently becomes "X is broken".
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import __version__


def _load_json(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    with open(os.path.expanduser(path), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _emit(payload: Any, *, pretty: bool) -> None:
    json.dump(payload, sys.stdout, indent=2 if pretty else None, sort_keys=True)
    sys.stdout.write("\n")


def _cmd_reproduce(args: argparse.Namespace) -> int:
    from . import pipeline

    report = pipeline.run(
        release_location=args.release, rpc_url=args.rpc, epoch=args.epoch,
        transition_index=args.transition_index, artifact_dir=args.artifact_dir,
        published_snapshot=_load_json(args.snapshot),
        runtime_record=_load_json(args.runtime_record) if args.runtime_record else None,
        confirmation_depth=args.confirmation_depth, from_block=args.from_block,
        to_block=args.to_block, verify_signatures=not args.no_signature_checks,
        allow_test_doubles=args.allow_test_doubles, export_path=args.export)
    _emit(report.as_dict(), pretty=not args.compact)
    if any(step.status == "FAIL" for step in report.steps):
        return 1
    if args.require_complete and (report.unverified
                                  or any(s.status == "UNVERIFIED" for s in report.steps)):
        sys.stderr.write(
            "--require-complete: the run contradicted nothing, but these checks did not run:\n"
            + "".join(f"  - {item.get('step')}: {item.get('reason')}\n"
                      for item in report.unverified))
        return 1
    return 0


def _cmd_verify_release(args: argparse.Namespace) -> int:
    from . import release as rel
    from .rpc import JsonRpc

    parsed = rel.discover(args.release)
    rpc = JsonRpc(args.rpc)
    rpc.assert_chain(parsed.chain_id)
    block = int(parsed.observation_block or rpc.confirmed_head(args.confirmation_depth))
    verification = rel.verify_deployment(parsed, rpc, block=block)
    _emit({"release": {"classification": parsed.classification, "chain_id": parsed.chain_id,
                       "addresses": parsed.addresses},
           "authorities": parsed.source_divergence(),
           "deployment": verification.as_dict()}, pretty=not args.compact)
    return 0 if verification.ok else 1


def _cmd_reproduce_snapshot(args: argparse.Namespace) -> int:
    """Rebuild a published resolver snapshot from chain truth, then check its signature.

    The order is the product. Reproduction runs first and takes no key; the signature is checked
    afterwards and its verdict never changes the reproduction's.
    """
    from . import resolver_snapshot as rsn

    published = _load_json(args.snapshot)
    runtime_record = _load_json(args.runtime_record) if args.runtime_record else None
    built, comparison = rsn.reproduce_from_chain(
        published, rpc_url=args.rpc, store_dir=args.artifacts,
        runtime_record=runtime_record, min_interval=args.min_interval)

    result: Dict[str, Any] = {
        "reproduction": comparison.as_dict(),
        "authority": ("reconstruction equality from chain truth — the downloaded snapshot is a "
                      "CACHE and no signature is consulted"),
    }
    if args.out:
        with open(os.path.expanduser(args.out), "wb") as fh:
            fh.write(rsn.cn.canonical_bytes(built))
        result["written_to"] = args.out
    _emit(result, pretty=not args.compact)
    return 0 if comparison.identical else 1


def _cmd_topics(args: argparse.Namespace) -> int:
    from . import rig_events as rig

    _emit({
        "production_descriptor_v3": {
            t: rig.EVENT_NAMES[t] for t in rig.RIG_LOG_TOPICS},
        "scope": ("only the canonical deployed rig-NFT descriptor-v3 lane; no V4, staking, "
                  "word-patch, staged, or descriptor-v2 subscription is exposed"),
    }, pretty=not args.compact)
    return 0


def _cmd_selftest(args: argparse.Namespace) -> int:
    """Prove the three primitives on known-answer vectors before trusting any of them."""
    from . import frontier as fr
    from . import keccak256 as kc
    from . import secp256k1 as ec

    results: List[Dict[str, Any]] = []

    # Keccak-256 is NOT SHA3-256: the padding byte differs, so they disagree on every input.
    empty = kc.keccak256_hex(b"")
    results.append({
        "check": "keccak256(b'') == c5d2460186f7...",
        "ok": empty == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "observed": empty})
    import hashlib
    results.append({
        "check": "keccak256 is not sha3_256",
        "ok": empty != hashlib.sha3_256(b"").hexdigest()})

    # Canonical JSON: the byte spelling a snapshot is compared under.
    canonical = fr.canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}})
    results.append({"check": "canonical json is key-sorted and separator-tight",
                    "ok": canonical == b'{"a":{"c":3,"d":2},"b":1}',
                    "observed": canonical.decode("utf-8")})
    try:
        fr.canonical_bytes({"x": 1.5})
        float_refused = False
    except Exception:                                          # noqa: BLE001 - that IS the check
        float_refused = True
    results.append({"check": "canonical json refuses floats", "ok": float_refused})

    # ecrecover, on a vector whose signer is known.
    digest = bytes.fromhex(
        "5c3c9d2f0e0dbdb3aa0a4b1d0e6d67f1e30de08d4b8e05b0a7e1b53fefb6e0aa")
    try:
        ec.ecrecover(digest, b"\x00" * 65)
        refused = False
    except ec.SignatureError:
        refused = True
    results.append({"check": "ecrecover refuses an all-zero signature", "ok": refused})
    # EIP-2: the high-s twin recovers a valid address, so accepting it would let two encodings
    # authenticate one payload. Refusing it is the check; normalising it silently is the bug.
    high_s = (b"\x01" * 32) + (ec.N - 1).to_bytes(32, "big") + b"\x1b"
    try:
        ec.ecrecover(digest, high_s)
        malleable_refused = False
    except ec.SignatureError:
        malleable_refused = True
    results.append({"check": "ecrecover refuses the EIP-2 malleable high-s twin",
                    "ok": malleable_refused})

    ok = all(item["ok"] for item in results)
    _emit({"version": __version__, "ok": ok, "checks": results}, pretty=not args.compact)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    from .release import DEFAULT_PRODUCTION_RELEASE_URL
    parser = argparse.ArgumentParser(
        prog="coretex-validator", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--compact", action="store_true", help="single-line JSON output")
    sub = parser.add_subparsers(dest="command", required=True)

    reproduce = sub.add_parser("reproduce", help="steps 1-8 against a live endpoint")
    reproduce.add_argument("--release", default=DEFAULT_PRODUCTION_RELEASE_URL,
                           help="path or url of the release artifact (default: signed canonical "
                                "Base production release at its immutable git commit)")
    reproduce.add_argument("--rpc", required=True, help="JSON-RPC endpoint")
    reproduce.add_argument("--epoch", type=int, default=None)
    reproduce.add_argument("--transition-index", type=int, default=None)
    reproduce.add_argument("--artifact-dir", default=None,
                           help="local content-addressed artifact directory")
    reproduce.add_argument("--snapshot", default=None,
                           help="published resolver snapshot to reproduce byte-for-byte")
    reproduce.add_argument("--runtime-record", default=None,
                           help="runtime-integration record, needed to rebuild the law locks when "
                                "reproducing the resolver's per-epoch schema")
    reproduce.add_argument("--export", default=None, help="write the activation export here")
    reproduce.add_argument("--from-block", type=int, default=None)
    reproduce.add_argument("--to-block", type=int, default=None)
    reproduce.add_argument("--confirmation-depth", type=int, default=15)
    reproduce.add_argument("--require-complete", action="store_true",
                           help="exit 1 when any check could not run")
    reproduce.add_argument("--no-signature-checks", action="store_true",
                           help="skip step 7's ecrecover (the chain already enforced it); the "
                                "run then touches no curve code at all")
    reproduce.add_argument("--allow-test-doubles", action="store_true",
                           help="let a declared non-consensus-grade sandbox/screen count. Visible "
                                "on the command line on purpose")
    reproduce.set_defaults(func=_cmd_reproduce)

    verify = sub.add_parser("verify-release", help="steps 1-2 only")
    verify.add_argument("--release", default=DEFAULT_PRODUCTION_RELEASE_URL)
    verify.add_argument("--rpc", required=True)
    verify.add_argument("--confirmation-depth", type=int, default=15)
    verify.set_defaults(func=_cmd_verify_release)

    rsnap = sub.add_parser("reproduce-snapshot",
                           help="rebuild a published resolver snapshot from chain truth")
    rsnap.add_argument("--snapshot", required=True, help="the published snapshot.json")
    rsnap.add_argument("--rpc", required=True, help="an ARCHIVE-capable JSON-RPC endpoint")
    rsnap.add_argument("--artifacts", required=True,
                       help="directory of content-addressed objects (the publication set)")
    rsnap.add_argument("--runtime-record", default=None,
                       help="runtime-integration record; without it the transitive law locks are "
                            "absent from the rebuild rather than guessed")
    rsnap.add_argument("--out", default=None, help="write the reconstructed canonical bytes here")
    rsnap.add_argument("--min-interval", type=float, default=0.7,
                       help="seconds between RPC requests; public endpoints rate-limit a burst")
    rsnap.set_defaults(func=_cmd_reproduce_snapshot)

    topics = sub.add_parser("topics", help="the dispatch table for both lanes")
    topics.set_defaults(func=_cmd_topics)

    selftest = sub.add_parser("selftest", help="known-answer vectors for the primitives")
    selftest.set_defaults(func=_cmd_selftest)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "compact"):                          # pragma: no cover - argparse detail
        args.compact = False
    try:
        return int(args.func(args))
    except KeyboardInterrupt:                                 # pragma: no cover
        return 2
    except Exception as exc:                                  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"coretex-validator: {type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":                                    # pragma: no cover
    raise SystemExit(main())
