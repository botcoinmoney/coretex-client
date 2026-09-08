# SPDX-License-Identifier: Apache-2.0
"""Small current-state CLI around the unchanged memory adapter."""
import argparse
import json
import sys
import time

from .config import DEFAULT_PROFILE, init_sync_config, load_authority, load_config, sync_config
from .current_state import CurrentState


def main(argv=None):
    parser = argparse.ArgumentParser(prog="coretex-consumer")
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync", help="adopt confirmed current modules without admission replay")
    sync.add_argument("--config", required=True)
    sync.add_argument("--release-dir")
    sync.add_argument("--expected-release-root")
    rpc = sync.add_mutually_exclusive_group()
    rpc.add_argument("--rpc")
    rpc.add_argument("--rpc-env")
    rpc.add_argument("--rpc-file")
    sync.add_argument("--objects", default="https://coordinator.agentmoney.net/coretex/v5/object/")
    sync.add_argument("--out")
    sync.add_argument("--store")
    sync.add_argument("--profile", default=DEFAULT_PROFILE)
    sync.add_argument("--confirmations", type=int, default=12)
    for name in ("status", "ingest", "context", "prewarm"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True)
        if name == "ingest":
            command.add_argument("text")
            command.add_argument("--id")
        if name == "context":
            command.add_argument("query")
            command.add_argument("--budget", type=int, default=800)
            command.add_argument("--as-of", type=int)
    args = parser.parse_args(argv)
    start = time.monotonic()
    def progress(message):
        print(message, file=sys.stderr, flush=True)
    try:
        if args.command == "sync":
            if args.release_dir is None:
                if any((args.rpc, args.rpc_env, args.rpc_file, args.expected_release_root, args.store, args.out)):
                    raise ValueError("existing sync uses its config; initialization requires --release-dir")
                path = sync_config(load_config(args.config), progress=progress)
            else:
                if not args.expected_release_root or not args.out:
                    raise ValueError("initial sync requires --expected-release-root and --out")
                path = init_sync_config(args.config, release_dir=args.release_dir,
                    settings={"expected_release_root": args.expected_release_root,
                        "rpc": args.rpc, "rpc_env": args.rpc_env, "rpc_file": args.rpc_file,
                        "objects": args.objects, "output_dir": args.out, "confirmations": args.confirmations},
                    store=args.store, profile=args.profile, progress=progress)
            snapshot = CurrentState.load(path)
            result = {"ok": True, "snapshot": str(path), "epoch": snapshot.epoch,
                      "frontier_root": snapshot.frontier_root,
                      "provenance": snapshot.document["provenance"],
                      "elapsed_seconds": round(time.monotonic() - start, 3)}
        else:
            config = load_config(args.config)
            authority = load_authority(config, progress=progress)
            with authority.open_memory(config["profile"], config["store"]) as memory:
                if args.command == "status":
                    result = memory.health()
                elif args.command == "prewarm":
                    result = memory.memory.prewarm(progress=lambda done, total:
                        progress(f"vector index {done}/{total}"))
                elif args.command == "ingest":
                    result = memory.sync_turn(messages=[{"role": "user", "content": args.text, "id": args.id}])
                else:
                    pack = memory.prefetch(args.query, budget=args.budget, as_of=args.as_of)
                    result = {"context": pack.render(), "receipt": pack.receipt, "items": pack.compact()}
        print(json.dumps(result, sort_keys=True, default=str))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc), "type": type(exc).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
