# SPDX-License-Identifier: Apache-2.0
"""``coretex-validator`` — the command an external agent actually runs.

    coretex-validator setup                               install-time: verify, kit packages,
                                                          chain head, AND the admission law
    coretex-validator reproduce --rpc URL                 production, steps 1-8
    coretex-validator reproduce --release R --rpc URL     explicit historical release
    coretex-validator verify-release --release R --rpc URL   steps 1-2 only
    coretex-validator reproduce-snapshot --snapshot F --rpc URL --artifacts DIR
    coretex-validator sync-law --mirror URL --root ROOT   fetch + VERIFY a NAMED publication
                                                          (no default: `setup` discovers the live
                                                          root from the coordinator kit)
    coretex-validator replay-latest --rpc URL --artifacts DIR    the NEWEST confirmed advance,
                                                          discovered from the chain and replayed
    coretex-validator replay-advance --logs F --artifacts DIR   confirmed advances from a feed file
    coretex-validator verify-receipt RECEIPT.json         Benchmark-v2 receipt replay
    coretex-validator preview-current-parent MODULE.py    OPTIONAL miner aid: score a candidate
        --manifest M.json --profile P --parent-root ROOT  against the CURRENT confirmed parent.
                                                          Under the fixed-suite law it scores the
                                                          LAW'S OWN exam and predicts the verdict;
                                                          under the retired walk law it scored
                                                          public dev cases and predicted nothing.
                                                          Read `lawEra` in the report.
    coretex-validator topics                              the dispatch table, V4 and rig
    coretex-validator selftest                            keccak/ecrecover/canonical-JSON vectors

EXIT CODES ARE PART OF THE INTERFACE, because a CI job reads them and a human reads the JSON:

    0  every step that ran PASSED, and any step that could not run is listed under "unverified"
    1  a check RAN and the chain disagreed — the claim is wrong
    2  the run could not start (bad arguments, unreachable endpoint, unparseable release)

Note what 0 does NOT mean. It does not mean everything was verified; it means nothing was
contradicted. ``--require-complete`` turns any unverified step into exit 1 for callers that want
the stricter reading, and it is opt-in rather than default so that "I could not check X" never
silently becomes "X is broken".

THE LAW CACHE, AND WHY IT IS APPLIED BEFORE ANY IMPORT
=====================================================
The seven published admission objects are fetched by publication root, every one verified against the
same tree-hash rule the signed receipt's ``code_roots`` binds, and materialized under
``~/.local/share/coretex/law/<root>/``. A normal ``setup`` atomically activates that law together
with the exact current miner-kit tar. Default commands use only that active tuple. ``sync-law``
can verify a publication named explicitly, but does not silently replace the canonical active
tuple.

``setup`` does this for you, and the root is DISCOVERED rather than defaulted: the coordinator
kit's ``law_publication`` component names which publication its chain head binds. ``sync-law``
remains for naming a publication explicitly, and it has no default root — verifying a set proves
it hashes to the root you asked for, never that the root is the live one, so a default would
choose the law silently.

The pins are applied by :func:`_activate_law` BEFORE the module that reads them is imported, and
that ordering is load-bearing rather than tidy: ``replay.py`` reads the three env vars at IMPORT
time (they become the sandbox's and the oracle screen's default arguments), so pins set afterwards
are a no-op that looks like it worked — the run would BACKLOG with a verified law cache sitting
right there. ``law.activate`` refuses that ordering out loud rather than shrugging.
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


def _activate_law(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    """Apply a verified law cache's env pins, and say in the report which one was used.

    MUST run before ``pipeline``/``replay`` is imported — see the module docstring. Returns the
    block the command reports under ``law``, or ``None`` when no active tuple is available (in
    which case the run proceeds to honest BACKLOGs at step 5).

    An explicitly-named ``--law-root`` that is NOT present is an error, never a silent fallback to
    "no law": a caller who named a publication meant that publication.
    """
    from . import law as law_mod

    cache_dir = getattr(args, "law_cache", None)
    root = getattr(args, "law_root", None)
    if getattr(args, "no_law_cache", False):
        return {"used": False, "reason": "--no-law-cache: the law cache was not consulted"}
    active = law_mod.load_active_install(cache_dir=cache_dir)
    if root:
        cache = law_mod.load_cache(root, cache_dir=cache_dir)   # raises if absent or tampered
        if active is not None and active["law_publication_root"] != root:
            active = None
    else:
        cache = law_mod.find_cache(cache_dir=cache_dir)
    if cache is None:
        return {"used": False,
                "reason": ("no verified law cache was found; deterministic admission will BACKLOG. "
                           "Run `coretex-validator setup` to activate the current kit and law"),
                "cache_dir": cache_dir or law_mod.default_cache_dir()}
    pins = law_mod.activate(cache)
    # THE SUITE COMES FROM THE SEALED TREE, NOT FROM THIS WHEEL. `canonical_suite` defaults to the
    # copy shipped inside the package so that a clean install can still validate a v3 artifact's
    # schema; once a verified law cache is active the SEALED bytes supersede it, because those are
    # the bytes inside the `validator` tree whose root every receipt's `code_roots` binds. A
    # mismatch is reported, never reconciled: a changed suite is a new law (LAW §3A.6).
    suite_block = None
    suite_bytes = cache.canonical_suite_bytes()
    if suite_bytes is not None:
        from . import canonical_suite as cs
        packaged = cs.packaged_suite_root()
        try:
            installed = cs.install_suite_bytes(
                suite_bytes, source=f"law cache {cache.publication_root}")
            suite_block = {"root": installed, "source": "sealed validator tree",
                           "packaged_root": packaged,
                           "agrees_with_packaged": installed == packaged}
        except cs.CanonicalSuiteError as exc:
            # AND REFUSE, rather than carrying on with the wheel's copy. `install_suite_bytes`
            # assigns nothing on failure, so continuing would leave the PACKAGED suite deciding
            # while the run reports a verified law cache — and `_resolve_fixed_suite` would then
            # compare a receipt's `canonical_suite_root` against the wrong document and emit
            # `CANONICAL_SUITE_MISMATCH`, exit 1. This CLI defines exit 1 as "a check ran and the
            # chain disagreed". A corrupt local cache must never be reportable as a refutation.
            raise law_mod.LawCacheError(
                f"the law cache at {cache.root_dir} carries a canonical suite this validator "
                f"refuses ({exc}). Refusing to fall back to the copy inside this wheel: a run "
                "that decided against a different exam than the receipt names would report the "
                "disagreement as though the chain were wrong. Re-run `sync-law` for publication "
                f"{cache.publication_root}") from exc
    return {"used": True, "publication_root": cache.publication_root,
            "canonical_suite": suite_block,
            "companion_files": cache.receipt.get("companion_files"),
            "cache_dir": cache.root_dir, "env": pins,
            "trees": cache.receipt["trees"],
            # The seventh sealed root is a FILE, not a tree (D-3). Reported separately so a reader
            # can tell at a glance whether this cache can compute `code_roots` at all.
            "files": cache.files, "mirror": cache.receipt.get("mirror"),
            "active_install": active}


def _cmd_reproduce(args: argparse.Namespace) -> int:
    law_block = _activate_law(args)                            # BEFORE the import below
    from . import pipeline

    report = pipeline.run(
        release_location=args.release, rpc_url=args.rpc, epoch=args.epoch,
        transition_index=args.transition_index, artifact_dir=args.artifact_dir,
        published_snapshot=_load_json(args.snapshot),
        runtime_record=_load_json(args.runtime_record) if args.runtime_record else None,
        confirmation_depth=args.confirmation_depth, from_block=args.from_block,
        to_block=args.to_block, verify_signatures=not args.no_signature_checks,
        allow_test_doubles=args.allow_test_doubles, export_path=args.export)
    payload = report.as_dict()
    payload["law"] = law_block
    _emit(payload, pretty=not args.compact)
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


def _cmd_setup(args: argparse.Namespace) -> int:
    from . import setup as su

    payload = su.run(
        rpc_url=args.rpc, coordinator=args.coordinator, release=args.release,
        confirmation_depth=args.confirmation_depth, packages_dir=args.packages_dir,
        skip_packages=args.skip_packages, skip_law=args.skip_law, law_cache=args.law_cache)
    _emit(payload, pretty=not args.compact)
    return 0 if payload["ok"] else 1


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


def _snapshot_eval_artifact_families(published, *, store_dir):
    """Read each eval-artifact ref's REAL family off its own bytes, where they are on this host.

    The published `kind` is a label the publisher wrote without opening the object. An artifact's
    law is fixed in the bytes `evalReportHash` addresses (`eval_artifact.artifact_law`), so it is
    read from there or reported UNRESOLVED — never inferred from the label, and never from the
    transition-descriptor version, which is a different versioning axis entirely.
    """
    from . import eval_artifact as ea
    from . import publication as pub

    # SELECTED BY CHAIN BINDING, NOT BY THE LABEL. Filtering on `kind` would have excluded exactly
    # the ref this function exists to catch — one the publisher labelled wrongly or not at all. The
    # `chain_binding` text is what says "this root is an evalReportHash", and it comes from the
    # same place the root does.
    prefix = "coretex.memory-eval-artifact."
    refs = [ref for ref in (published.get("artifacts") or [])
            if isinstance(ref, dict) and isinstance(ref.get("root"), str)
            and (str(ref.get("kind", "")).startswith(prefix)
                 or "evalReportHash" in str(ref.get("chain_binding", "")))]
    if not refs:
        return {"refs": 0}
    out = []
    store = None
    if store_dir:
        try:
            store = pub.FilesystemCAS(os.path.expanduser(store_dir))
        except Exception:                                    # pragma: no cover - defensive
            store = None
    for ref in refs:
        row = {"root": ref.get("root"), "published_label": ref.get("kind"),
               "observed_format": None,
               "note": "not resolved on this host; the published label is not evidence"}
        if store is not None:
            try:
                artifact = pub.fetch_json(ref["root"], hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                          store=store)
                row["observed_format"] = artifact.get("format")
                row["authority_law"] = ea.artifact_law(artifact)
                row["note"] = ("read from the artifact's own bytes"
                               + ("" if row["observed_format"] == ref.get("kind")
                                  else "; the published label disagrees and the BYTES win"))
            except Exception as exc:
                row["note"] = f"not resolvable from --artifacts: {type(exc).__name__}: {exc}"
        out.append(row)
    return {"refs": len(out), "entries": out}


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
        # ADMISSION IS NOT WHAT THIS COMMAND CHECKS, and saying so is the point. A reproduced
        # snapshot proves the published index of roots is the one chain truth implies; it fetches
        # no eval artifact, runs no exam and re-executes nothing, so whether each advance was a
        # legal admission is UNRESOLVED here and only `reproduce` (steps 5-8) settles it. This
        # block exists because a reader who saw `"reproduction": {"identical": true}` and nothing
        # else had no way to tell which of the two questions had been answered.
        "admission": {
            "outcome": "UNRESOLVED",
            "reason": ("reproduce-snapshot rebuilds the resolver snapshot from chain truth and "
                       "compares it; it does not fetch eval artifacts, resolve the canonical "
                       "suite or the genesis floor, or re-execute a candidate. Admission is "
                       "settled by `coretex-validator reproduce`, which runs the full replay"),
            "settled_by": "coretex-validator reproduce --rpc URL --release ROOT",
        },
        # ERA-AWARE ARTIFACT KIND. The snapshot's `kind` label for an eval-artifact ref is the
        # PUBLISHER's descriptive label — `ArtifactRef.kind` is documented as descriptive, the ROOT
        # is the identity — and it is emitted without fetching the artifact, so it cannot tell a
        # walk-era v1/v2 from a fixed-suite v3. It is reproduced byte-for-byte (that is what
        # reproduction means) and it is NOT read here as evidence of which law an advance was
        # decided under. Where the local store actually holds the artifact, its real family is
        # read off its own bytes and reported beside the label.
        "eval_artifact_families": _snapshot_eval_artifact_families(
            published, store_dir=args.artifacts),
    }
    if args.out:
        with open(os.path.expanduser(args.out), "wb") as fh:
            fh.write(rsn.cn.canonical_bytes(built))
        result["written_to"] = args.out
    _emit(result, pretty=not args.compact)
    return 0 if comparison.identical else 1


def _cmd_sync_law(args: argparse.Namespace) -> int:
    """Fetch, VERIFY and materialize the published admission law (spec §9.3).

    The verdict is binary and there is no partial success: either every object reproduced the
    address it was fetched under and every required tree is present, or nothing is installed.

    ``--root`` is REQUIRED and has no default. Verifying a publication proves its trees hash to
    the root that was asked for; it says nothing about whether that root is the one the chain head
    binds. A default therefore chose the law silently, which is what a rehearsal root did on live
    hosts until this command stopped offering one.
    """
    from . import law as law_mod

    if not args.root:
        sys.stderr.write(
            "coretex-validator sync-law: --root is required and has no default.\n"
            "  The publication to install is a property of the deployment you are verifying, and\n"
            "  verifying a set proves only that it hashes to the root you asked for — never that\n"
            "  the root is the live one. Discover it instead of pasting one:\n"
            "    coretex-validator setup            # syncs the law itself, from the "
            "coordinator kit\n"
            "  and it is reported under `law.publicationRoot`. A historical publication may be\n"
            "  named explicitly with --root ROOT.\n")
        return 2
    cache = law_mod.sync_law(args.root, mirror=args.mirror, cache_dir=args.cache_dir,
                             force=args.force, timeout=args.timeout,
                             max_object_bytes=args.max_object_bytes)
    if args.print_export:
        # Shell-only output, deliberately NOT mixed with the JSON: `eval "$(... --print-export)"`.
        for line in cache.export_lines():
            sys.stdout.write(line + "\n")
        return 0
    _emit({"law": cache.as_dict(),
           "verified": ("every object was rehashed under benchmark-v2/validator/receipt.py's "
                        "tree-hash rule from the bytes that arrived; the mirror was used, never "
                        "trusted"),
           "next": ("this named publication is verified. Pass --law-root explicitly to inspect "
                    "it, or run setup to verify and atomically activate the coordinator's one "
                    "current kit/law tuple")},
          pretty=not args.compact)
    return 0


def _load_logs(path: str) -> List[Dict[str, Any]]:
    """Raw chain logs from a file: either a bare list or ``{"logs": [...]}``."""
    document = _load_json(path)
    logs = document.get("logs") if isinstance(document, dict) else document
    if not isinstance(logs, list):
        raise ValueError(f"{path} carries no logs list (expected a JSON list, or an object with "
                         "a 'logs' key)")
    return logs


def _replay_one(advance, *, feed, store, screen, sandbox, burned, live_root,
                allow_test_doubles: bool):
    """Project ONE confirmed rig advance and replay it. Returns a :class:`replay.ReplayResult`.

    THE ONE LIVE DECODING AUTHORITY (see :mod:`rig_discovery`). A projection that cannot be built
    is turned into the outcome the failure actually is — BACKLOG for an unavailable object, FAIL
    for published bytes that contradict the confirmed event — and never into "there was no
    advance", which is what the retired-table discovery reported for fourteen epochs of them.
    """
    from . import backlog as bl
    from . import replay as rp
    from . import rig_discovery as rd

    def refused(exc: "rd.ProjectionError") -> "rp.ReplayResult":
        return rp.ReplayResult(
            outcome=(bl.BACKLOG if exc.outcome == "BACKLOG" else bl.FAIL),
            stage=exc.stage, reason=str(exc), code=exc.code, epoch=advance.epoch,
            transition_index=advance.transition_index, miner=advance.miner,
            parent_frontier_root=advance.parent_state_root,
            new_frontier_root=advance.new_state_root,
            eval_report_hash=advance.eval_report_hash)

    try:
        projected, provenance = rd.project_advance(advance, store=store)
    except rd.ProjectionError as exc:
        return refused(exc)
    try:
        pins, _pin_provenance = rd.pins_for(advance, feed=feed, store=store)
    except rd.ProjectionError as exc:
        return refused(exc)
    result = rp.replay_advance(
        projected, store=store, pins=pins, screen=screen, sandbox=sandbox,
        burned=burned, live_root=live_root, allow_test_doubles=allow_test_doubles)
    result.auxiliary = {**dict(result.auxiliary), "projection": provenance,
                        "consensus_critical": False}
    return result


def _cmd_replay_advance(args: argparse.Namespace) -> int:
    """Replay confirmed frontier advances against a law cache and a local artifact store.

    PASS / FAIL / BACKLOG are surfaced VERBATIM, one result per advance. Nothing here collapses a
    BACKLOG into either of the other two, and there is no flag that does — the whole point of the
    third outcome is that "I could not check that" is a distinct fact.
    """
    law_block = _activate_law(args)                            # BEFORE the imports below
    from . import backlog as bl
    from . import publication as pub
    from . import release as rel
    from . import replay as rp
    from . import rig_discovery as rd

    release = rel.discover(args.release)
    logs = _load_logs(args.logs)
    feed = rd.sync_rig_logs(logs, deployment=release.deployment,
                            latest_block=args.latest_block,
                            confirmation_depth=args.confirmation_depth)
    advances = list(feed.advances)
    if args.epoch is not None:
        advances = [a for a in advances if a.epoch == args.epoch]
    if args.transition_index is not None:
        advances = [a for a in advances if a.transition_index == args.transition_index]

    store = pub.FilesystemCAS(os.path.expanduser(args.artifacts))
    screen = rp.default_oracle_screen()
    sandbox = rp.default_sandbox()
    burned = _load_json(args.burned) if args.burned else None
    results = [
        _replay_one(advance, feed=feed, store=store, screen=screen, sandbox=sandbox,
                    burned=burned, live_root=args.live_root,
                    allow_test_doubles=args.allow_test_doubles)
        for advance in advances]

    payload = {
        "law": law_block,
        "release": release.classification,
        "feed": feed.summary(),
        "screen": {"name": getattr(screen, "name", type(screen).__name__),
                   "available": bool(screen.available())},
        "sandbox": {"name": getattr(sandbox, "name", type(sandbox).__name__),
                    "available": bool(sandbox.available())},
        "replayed": [r.as_dict() for r in results],
        "outcomes": {name: sum(1 for r in results if str(r.outcome) == name)
                     for name in ("PASS", "FAIL", "BACKLOG")},
    }
    if not advances:
        payload["note"] = ("the supplied feed carries no confirmed advance matching the filters; "
                           "nothing was replayed and nothing is claimed")
    _emit(payload, pretty=not args.compact)

    if any(r.outcome == bl.FAIL for r in results):
        return 1
    unresolved = [r for r in results if r.outcome == bl.BACKLOG]
    if not advances:
        return 2
    if args.require_complete and unresolved:
        sys.stderr.write(
            "--require-complete: nothing was contradicted, but these advances could not be "
            "checked:\n" + "".join(f"  - {r.stage}: {r.reason}\n" for r in unresolved))
        return 1
    return 0


def _cmd_replay_latest(args: argparse.Namespace) -> int:
    """Replay the NEWEST confirmed advance, discovering everything it needs.

    WHY THIS IS A SEPARATE COMMAND rather than ``replay-advance --latest``. Every subcommand here
    has exactly one input mode, and these two read from different worlds: ``replay-advance`` takes
    a FEED FILE and replays what is in it, offline and without a chain; this takes a CHAIN and a
    release, like ``reproduce``. Folding them together would make ``--logs`` conditionally
    required and bolt ``--rpc``/``--release`` onto a command whose value is needing neither.
    ``--logs`` is accepted here too — as an offline source for the same discovery — but the
    default source is the chain.

    NEWEST IS (epoch, transitionIndex), NOT BLOCK ORDER. ``transitionIndex`` restarts at 0 every
    epoch, so the last log in a block-ordered feed is routinely not the head advance.
    ``sync.order_events`` already sorts by the chain's order; the newest is its last element, and
    that is the only place this command decides anything.
    """
    law_block = _activate_law(args)                            # BEFORE the imports below
    from . import backlog as bl
    from . import pipeline
    from . import release as rel
    from . import replay as rp
    from . import rig_discovery as rd
    from . import sync as sy

    release = rel.discover(args.release)
    chain: Dict[str, Any] = {
        "source": "logs-file" if args.logs else "rpc", "release": release.classification,
        "decoder": rd.DECODER_NOTE,
        "selection_scope": ("latest-in-supplied-feed" if args.logs
                            else "confirmed-chain-latest"),
        "chain_latest_proven": False,
    }
    completeness_views = None
    if args.logs:
        logs = _load_logs(args.logs)
        latest_block = args.latest_block
    else:
        if not args.rpc:
            sys.stderr.write(
                "coretex-validator replay-latest: --rpc is required unless --logs names a feed "
                "file.\n  The newest advance is discovered from the chain; with neither there is "
                "nothing to discover it from.\n")
            return 2
        from .rpc import JsonRpc

        rpc = JsonRpc(args.rpc)
        rpc.assert_chain(release.chain_id)
        latest_block = rpc.block_number()
        head = sy.confirmed_head(latest_block, args.confirmation_depth)
        from_block = int(args.from_block if args.from_block is not None else release.deploy_block)
        logs = rpc.get_logs(addresses=list(release.deployment.addresses), topics=[],
                            from_block=from_block, to_block=head)
        from .rpc import RigViews
        completeness_views = RigViews(rpc, release.deployment, block=head)
        chain.update({"rpc": args.rpc, "latest_block": latest_block, "confirmed_head": head,
                      "scanned_blocks": [from_block, head]})

    feed = rd.sync_rig_logs(logs, deployment=release.deployment, latest_block=latest_block,
                            confirmation_depth=args.confirmation_depth)
    # THE ONE DECISION: the chain's order, last element. Never the feed's order.
    newest = feed.newest()

    if not feed.selectable:
        payload = {
            "law": law_block, "chain": chain, "feed": feed.summary(),
            "artifacts": {"source": args.artifacts or args.artifact_base_url
                          or release.artifact_base_url},
            "selected": None, "outcome": "BACKLOG", "code": "FEED_NOT_SELECTABLE",
            "reason": ("the confirmed feed cannot identify one latest advance: "
                       + "; ".join(feed.selection_defects)),
            "note": ("no older advance was selected and the feed was not described as idle; "
                     "repair or rescan the confirmed range"),
            "outcomes": {"PASS": 0, "FAIL": 0, "BACKLOG": 1},
        }
        _emit(payload, pretty=not args.compact)
        return 2

    if completeness_views is not None:
        raw_cutover = release.raw.get("cutover_epoch", release.raw.get("cutoverEpoch"))
        if not isinstance(raw_cutover, int) or isinstance(raw_cutover, bool):
            sys.stderr.write("coretex-validator replay-latest: release has no valid cutover epoch\n")
            return 2
        try:
            completeness = rd.prove_rpc_latest_complete(
                feed, views=completeness_views, cutover_epoch=raw_cutover)
        except rd.FeedCompletenessError as exc:
            payload = {
                "law": law_block, "chain": chain, "feed": feed.summary(),
                "artifacts": {"source": args.artifacts or args.artifact_base_url
                              or release.artifact_base_url},
                "selected": None, "outcome": "BACKLOG",
                "code": "FEED_COMPLETENESS_UNPROVEN", "reason": str(exc),
                "note": ("no older advance was selected and the chain was not described as "
                         "idle; use an RPC that returns the full confirmed range"),
                "outcomes": {"PASS": 0, "FAIL": 0, "BACKLOG": 1},
            }
            _emit(payload, pretty=not args.compact)
            return 2
        chain.update({"chain_latest_proven": True, "completeness": completeness})

    try:
        store = pipeline.open_store(artifact_dir=args.artifacts,
                                    base_url=args.artifact_base_url or release.artifact_base_url)
    except pipeline.PipelineError as exc:
        sys.stderr.write(f"coretex-validator replay-latest: {exc.message}\n")
        return 2

    payload: Dict[str, Any] = {
        "law": law_block, "chain": chain, "feed": feed.summary(),
        "artifacts": {"source": args.artifacts or args.artifact_base_url
                      or release.artifact_base_url},
        "selected": None if newest is None else rd.selected_summary(newest),
    }
    if newest is None:
        payload["note"] = ("the feed carries no confirmed advance; nothing was replayed and "
                           "nothing is claimed")
        payload["outcomes"] = {"PASS": 0, "FAIL": 0, "BACKLOG": 0}
        _emit(payload, pretty=not args.compact)
        return 2

    screen = rp.default_oracle_screen()
    sandbox = rp.default_sandbox()
    result = _replay_one(
        newest, feed=feed, store=store, screen=screen, sandbox=sandbox,
        burned=_load_json(args.burned) if args.burned else None,
        live_root=args.live_root, allow_test_doubles=args.allow_test_doubles)
    payload.update({
        "screen": {"name": getattr(screen, "name", type(screen).__name__),
                   "available": bool(screen.available())},
        "sandbox": {"name": getattr(sandbox, "name", type(sandbox).__name__),
                    "available": bool(sandbox.available())},
        "replayed": result.as_dict(),
        "outcomes": {name: (1 if str(result.outcome) == name else 0)
                     for name in ("PASS", "FAIL", "BACKLOG")},
    })
    _emit(payload, pretty=not args.compact)

    if result.outcome == bl.FAIL:
        return 1
    if args.require_complete and result.outcome == bl.BACKLOG:
        sys.stderr.write(
            "--require-complete: nothing was contradicted, but the newest advance could not be "
            f"checked:\n  - {result.stage}: {result.reason}\n")
        return 1
    return 0


def _resolve_fixed_suite(wrapper, artifact):
    """Resolve the LAW-BOUND exam and the constructor-genesis floor a v4 receipt decided against.

    THE GAP THIS CLOSES. ``verify-receipt`` resolved the exact PARENT and nothing else, which was
    the whole comparison under the walk law: the cases came from committed entropy and the rule was
    a Pareto clause over two measured sides. Under the fixed suite a decision has THREE law-bound
    comparands — the immutable suite, the exact parent's stored vector, and the constructor-genesis
    floor — and two of them were being taken on the receipt's word. They are resolved here, from
    this installation's own suite document, and any disagreement is stated rather than replayed
    past.

    Returns the ``fixed_suite`` section of the report. It is ``{"applies": False, ...}`` for a
    walk-era receipt, which is not a gap: those receipts were never decided against a suite, and
    saying so is the era-aware answer.
    """
    from collections import abc as _abc

    from . import canonical_suite as cs
    from . import eval_artifact as ea

    body = wrapper.get("receipt") if isinstance(wrapper, _abc.Mapping) \
        and isinstance(wrapper.get("receipt"), _abc.Mapping) else wrapper
    if not isinstance(body, _abc.Mapping):
        return {"applies": False, "reason": "the receipt carries no report body"}
    descriptor = body.get("evaluation_law") or {}
    law_id = descriptor.get("law_id") if isinstance(descriptor, _abc.Mapping) else None
    if law_id != ea.FIXED_SUITE_LAW_ID:
        return {"applies": False, "law_id": law_id,
                "reason": ("this receipt is bound to a prior law era, whose cases were drawn from "
                           "committed entropy rather than from a canonical suite; there is no "
                           "suite or floor for it to be resolved against")}

    block = {"applies": True, "law_id": law_id,
             "decision_engine": descriptor.get("decision_engine")}
    try:
        block["suite"] = {
            "resolved_root": cs.suite_root(),
            "version": cs.suite_version(),
            "source": cs.suite_source(),
            "bound_root": descriptor.get("canonical_suite_root"),
        }
        if descriptor.get("canonical_suite_root") != cs.suite_root():
            block.update({
                "outcome": "FAIL", "code": "CANONICAL_SUITE_MISMATCH",
                "reason": (f"the receipt is bound to canonical suite "
                           f"{descriptor.get('canonical_suite_root')} and this installation "
                           f"carries {cs.suite_root()}. A changed suite is a NEW LAW (LAW "
                           "§3A.6), never a variation of this one — replaying it here would "
                           "decide one exam's answers under another exam's rules")})
            return block
        profile_id = str(body.get("profile_id") or "")
        block["suite"]["profile_id"] = profile_id
        block["suite"]["counts"] = cs.suite_counts(profile_id)
        expected = cs.suite_cases(profile_id)
        hashes = cs.suite_case_hashes(profile_id)
        selection = body.get("selection")
        if not isinstance(selection, _abc.Mapping):
            block.update({
                "outcome": "FAIL", "code": "SUITE_SELECTION_MALFORMED",
                "reason": ("the receipt claims the fixed-suite law but its `selection` is "
                           f"{type(selection).__name__}, not an object of partitions")})
            return block
        for label in ea.SELECTION_LABELS:
            bound = list(selection.get(label) or ())
            if not all(isinstance(case, _abc.Mapping) for case in bound):
                block.update({
                    "outcome": "FAIL", "code": "SUITE_SELECTION_MALFORMED",
                    "reason": f"the receipt's {label!r} partition holds a non-object case"})
                return block
            want = expected[label]
            if len(bound) != len(want):
                block.update({
                    "outcome": "FAIL", "code": "SUITE_PARTITION_MISMATCH",
                    "reason": (f"the receipt's {label!r} partition holds {len(bound)} cases; the "
                               f"canonical suite declares {len(want)} and a partition is never "
                               "subsetted, extended or re-ordered")})
                return block
            for index, (case, suite_case) in enumerate(zip(bound, want)):
                for field in ("instance_id", "profile_id", "scale", "seed"):
                    if case.get(field) != suite_case[field]:
                        block.update({
                            "outcome": "FAIL", "code": "SUITE_CASE_MISMATCH",
                            "reason": (f"selection[{label!r}][{index}].{field} is "
                                       f"{case.get(field)!r}; the canonical suite declares "
                                       f"{suite_case[field]!r}")})
                        return block
                if case.get("instance_hash") != hashes[suite_case["instance_id"]]:
                    block.update({
                        "outcome": "FAIL", "code": "SUITE_INSTANCE_HASH_MISMATCH",
                        "reason": (f"selection[{label!r}][{index}] was scored on an instance that "
                                   "is not the one the law names")})
                    return block
        # THE FLOOR IS A REFUSAL WHEN PENDING, never a skipped check (LAW §3A.3).
        authority = cs.genesis_floor_authority()
        block["genesis_floor"] = {"status": authority.get("status"),
                                  "source": authority.get("source")}
        if not cs.genesis_floor_resolved():
            block.update({
                "outcome": "BACKLOG", "code": cs.GENESIS_FLOOR_PENDING,
                "reason": ("this installation's constructor-genesis floor is pending, so no v4 "
                           "admission is computable and none can be checked here")})
            return block
        block["genesis_floor"]["partitions"] = {
            label: cs.genesis_floor_vector(profile_id, label) for label in ea.SELECTION_LABELS}
        if isinstance(artifact, _abc.Mapping) and artifact.get("genesis_floor"):
            block["genesis_floor"]["artifact_agrees"] = all(
                artifact["genesis_floor"]["partitions"].get(label)
                == block["genesis_floor"]["partitions"][label] for label in ea.SELECTION_LABELS)
        block["resolved"] = True
        return block
    except cs.CanonicalSuiteError as exc:
        block.update({"outcome": "FAIL", "code": getattr(exc, "code", "CANONICAL_SUITE_INVALID"),
                      "reason": str(exc)})
        return block


def _resolve_incumbent_execution(wrapper, artifact, *, store):
    """Resolve the EXACT-PARENT incumbent this receipt names, from public content-addressed bytes.

    THE DEFECT THIS CLOSES (D-4). ``benchmark-v2/validator/replay.py`` refuses an exact-parent
    report without ``incumbent_execution``, the CLI never passed one, and no flag could supply it
    — so ``verify-receipt`` could never verify the receipt shape that is 0.4.3's whole point. The
    only caller that resolved it was ``replay.replay_advance``.

    The resolution is the same public one ``replay_advance`` and ``preview-current-parent`` use:
    frontier -> composition -> release -> module, every hop re-hashed, and the result compared for
    EXACT equality against the five-field identity the report binds. The coordinator's worker
    objects are transport; this follows the graph itself.

    Returns ``(execution_or_None, block)``. ``block`` is the ``incumbent`` section of the report
    and always says which of the three situations held.
    """
    from collections import abc as _abc

    from . import eval_artifact as ea
    from . import frontier as fr
    from . import parent_execution as pe
    from . import publication as pub

    body = wrapper.get("receipt") if isinstance(wrapper, _abc.Mapping) \
        and isinstance(wrapper.get("receipt"), _abc.Mapping) else wrapper
    reported = body.get("incumbent") if isinstance(body, _abc.Mapping) else None
    exact = (isinstance(reported, _abc.Mapping)
             and frozenset(reported) == frozenset(ea.INCUMBENT_EXACT_FIELDS))
    if not exact:
        return None, {"resolved": False, "kind": "reference_or_historical",
                      "reason": ("the report's incumbent is not the exact five-field identity, so "
                                 "the frozen replayer reconstructs it and REFUSES a supplied "
                                 "execution (`incumbent_execution_unexpected`)")}

    profile_id = str((body or {}).get("profile_id")
                     or ((artifact or {}).get("candidate") or {}).get("target_profile") or "")
    parent_root = ((artifact or {}).get("frontier") or {}).get("parent_frontier_root")
    if not profile_id or not isinstance(parent_root, str):
        return None, {
            "resolved": False, "kind": "exact_parent", "code": "PARENT_EXECUTION_UNRESOLVABLE",
            "outcome": "BACKLOG",
            "reason": ("this receipt names an exact parent, but the target profile and the parent "
                       "frontier root could not be read from the report and the eval artifact. "
                       "Pass the artifact that binds the receipt with --artifact")}
    try:
        parent_manifest = pub.fetch_json(parent_root, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                         store=store)
        execution = pe.fetch_parent_execution(store=store, parent_manifest=parent_manifest,
                                              target_profile=profile_id)
    except pub.PublicationUnavailableError as exc:
        # AN UNAVAILABLE OBJECT, and therefore a BACKLOG. Reporting it as FAIL/exit 1 — the code
        # the docs define as a refutation — would raise a refutation alarm against a healthy
        # production receipt because a publisher had not served an object yet.
        return None, {
            "resolved": False, "kind": "exact_parent", "code": "PARENT_EXECUTION_UNAVAILABLE",
            "outcome": "BACKLOG", "parent_frontier_root": parent_root,
            "target_profile": profile_id,
            "reason": (f"the exact parent's release/composition/module bytes are not published by "
                       f"this artifact source: {exc}. The receipt was not contradicted; it could "
                       "not be checked")}
    except (pub.PublicationError, pe.ParentExecutionError, fr.FrontierError, ValueError) as exc:
        return None, {
            "resolved": False, "kind": "exact_parent", "code": "PARENT_EXECUTION_INVALID",
            "outcome": "FAIL", "parent_frontier_root": parent_root,
            "target_profile": profile_id,
            "reason": f"the exact parent release graph does not resolve: {exc}"}
    try:
        identity = pe.compact_identity(execution)
    except pe.ParentExecutionError as exc:
        return None, {"resolved": False, "kind": "exact_parent",
                      "code": "PARENT_EXECUTION_INVALID", "outcome": "FAIL",
                      "reason": str(exc)}
    if dict(reported) != dict(identity):
        return None, {
            "resolved": False, "kind": "exact_parent", "code": "PARENT_EXECUTION_MISMATCH",
            "outcome": "FAIL", "parent_frontier_root": parent_root,
            "target_profile": profile_id, "resolved_identity": identity,
            "reason": ("the report's incumbent is not the parent release independently resolved "
                       "from confirmed public bytes")}
    return execution, {"resolved": True, "kind": "exact_parent",
                       "parent_frontier_root": parent_root, "target_profile": profile_id,
                       "release_root": identity.get("release_root"),
                       "authority": ("frontier -> composition -> release -> module, every hop "
                                     "re-hashed; compared for EXACT equality against the identity "
                                     "the report binds")}


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    """Drive ``benchmark-v2/validator/replay.replay_receipt`` through the law cache.

    Same pattern as ``reproduce``'s step 5, exposed on its own so a receipt can be checked without
    a chain at all. Exact-parent reports additionally need the eval artifact and the public parent
    graph; a receipt plus law trees alone does not contain those bytes. The frozen replay runs in
    a child interpreter that installs and PROVES a networkless seccomp filter before executing the
    candidate; a host where that cannot be installed BACKLOGs rather than running it unconfined.

    EXACT-PARENT RECEIPTS (D-4). When the report names the five-field exact incumbent, the
    incumbent EXECUTION is resolved here from the artifact store rather than demanded from a flag
    that never existed — see :func:`_resolve_incumbent_execution`.
    """
    law_block = _activate_law(args)                            # BEFORE the import below
    from . import pipeline
    from . import publication as pub
    from . import replay as rp

    wrapper = _load_json(args.receipt)
    artifact = _load_json(args.artifact) if args.artifact else {}
    sandbox = rp.BenchmarkV2Sandbox() if args.repo_root is None else rp.BenchmarkV2Sandbox(
        repo_root=args.repo_root,
        bench_v2_dir=os.path.join(args.repo_root, "benchmark-v2"),
        coretex_dir=os.path.join(args.repo_root, "coretex-memory"))

    # The receipt is normally named by its own address INSIDE a content-addressed directory, so
    # that directory is the artifact source unless the caller names another. Requiring --artifacts
    # for a directory the command was already pointed into would be a second way to say one thing.
    artifact_dir = args.artifacts
    if artifact_dir is None and args.artifact_base_url is None:
        artifact_dir = os.path.dirname(
            os.path.abspath(os.path.expanduser(args.receipt))) or None
    try:
        store = pipeline.open_store(artifact_dir=artifact_dir,
                                    base_url=args.artifact_base_url)
    except pipeline.PipelineError as exc:                      # pragma: no cover - defensive
        sys.stderr.write(f"coretex-validator verify-receipt: {exc.message}\n")
        return 2

    base = {"law": law_block, "sandbox": {"name": sandbox.name,
                                          "available": bool(sandbox.available())},
            "artifacts": {"source": args.artifacts or args.artifact_base_url or artifact_dir}}

    incumbent_execution, incumbent_block = _resolve_incumbent_execution(
        wrapper, artifact, store=store)
    base["incumbent"] = incumbent_block
    # THE OTHER TWO LAW-BOUND COMPARANDS. Resolved before the sandbox runs, because a receipt that
    # names an exam this installation does not carry cannot be replayed under it at all. Both are
    # RESOLVED here and the refusals are RANKED below — a FAIL is a determination about the chain
    # and outranks any BACKLOG, which is only ever a statement about this host.
    suite_block = _resolve_fixed_suite(wrapper, artifact)
    base["fixed_suite"] = suite_block
    for block in sorted((b for b in (incumbent_block, suite_block)
                         if b.get("outcome") in ("FAIL", "BACKLOG")),
                        key=lambda b: 0 if b["outcome"] == "FAIL" else 1):
        base.update({"outcome": block["outcome"], "code": block["code"],
                     "reason": block["reason"]})
        _emit(base, pretty=not args.compact)
        if block["outcome"] == "FAIL":
            return 1
        if args.require_complete:
            sys.stderr.write("--require-complete: the receipt was not replayed: "
                             f"{block['reason']}\n")
            return 1
        return 0

    try:
        result = sandbox.execute(receipt_wrapper=wrapper, artifact=artifact,
                                 incumbent_execution=incumbent_execution)
    except rp.SandboxDependencyError as exc:
        # An ENVIRONMENT fault, and deliberately a FAIL: the reader's next move is one `pip
        # install`, not a re-read of our documentation. Conflating it with "unavailable" is the
        # single most misleading thing this command could do.
        base.update({"outcome": "FAIL", "code": "MISSING_DEPENDENCY",
                     "dependency": exc.dependency, "reason": str(exc), "remedy": exc.remedy})
        _emit(base, pretty=not args.compact)
        return 1
    except rp.SandboxUnavailable as exc:
        base.update({"outcome": "BACKLOG", "code": "SANDBOX_UNAVAILABLE", "reason": str(exc)})
        _emit(base, pretty=not args.compact)
        if args.require_complete:
            sys.stderr.write(f"--require-complete: the receipt was not replayed: {exc}\n")
            return 1
        return 0

    # THREE OUTCOMES, NOT TWO. A refusal because an INPUT was missing is unresolved work, and in
    # this client's vocabulary FAIL/exit-1 means "a receipt did not reproduce" — the chain is
    # lying. Printing a never-published law file as a refutation is what made a CI wired to the
    # documented contract alarm on a healthy production receipt.
    if not result["reproduced"] and result.get("code") in rp.AVAILABILITY_REPLAY_CODES:
        base.update({"outcome": "BACKLOG", "code": result.get("code"),
                     "reason": result.get("reason", ""), "replay": result})
        _emit(base, pretty=not args.compact)
        if args.require_complete:
            sys.stderr.write("--require-complete: the receipt was not replayed: "
                             f"{result.get('reason', '')}\n")
            return 1
        return 0

    base.update({"outcome": "PASS" if result["reproduced"] else "FAIL", "replay": result})
    _emit(base, pretty=not args.compact)
    return 0 if result["reproduced"] else 1


def _cmd_preview_current_parent(args: argparse.Namespace) -> int:
    """Score a candidate against the CURRENT confirmed parent, under whichever law is pinned.

    WHAT THIS PREDICTS IS ERA-DEPENDENT, and the report says which era it used (``lawEra``).
    Under the RETIRED walk law the official evaluation re-drew cases from future entropy, so this
    scored the kit's public dev cases, ``predictsAdmission`` was a hard ``false``, and the number
    was a sanity check. Under the CURRENT fixed-suite law the exam is the immutable public
    canonical suite and the rule is componentwise dominance over the exact parent plus the genesis
    floor, with no input from any secret, the candidate id, the rig or the author — so this scores
    THE SAME CASES the adjudicator scores and ``predictsDeterministicAdmission`` is ``true``. What
    it still cannot predict is the chain race and the adjudicating host's own hard prerequisites.

    WHY THE EXIT CODES LOOK LIKE THIS. Losing to the live parent is the single most useful thing
    this command can tell a miner, so it is exit 0 — the same as winning. Non-zero means the
    comparison could not be made: no pinned law trees (2), an unverifiable parent chain (2), a
    scorer that could not run (2). A miner's CI must never learn to read "exit 1" as "you lost",
    because then a genuine operational failure would read as a verdict.
    """
    law_block = _activate_law(args)                            # BEFORE the imports below
    from . import law as law_mod
    from . import pipeline
    from . import preview as pv

    def _fail(payload: Dict[str, Any]) -> int:
        payload["law"] = law_block
        _emit(payload, pretty=not args.compact)
        return 2

    # The trees come from THE CACHE THIS RUN ACTIVATED, or from an explicit --repo-root. They are
    # deliberately NOT read out of the ambient environment: inherited pins are host state, and a
    # preview scored against whatever happened to be exported in this shell is exactly the
    # unpinned number this command must never produce. `--no-law-cache` therefore refuses here.
    pins = (law_block or {}).get("env") or {}
    if args.repo_root:
        bench_dir = os.path.join(args.repo_root, "benchmark-v2")
        coretex_dir = os.path.join(args.repo_root, "coretex-memory")
        repo_root = args.repo_root
    else:
        bench_dir = pins.get(law_mod.ENV_BENCHMARK_V2, "")
        coretex_dir = pins.get(law_mod.ENV_MEMORY_RUNTIME, "")
        repo_root = pins.get(law_mod.ENV_REPO_ROOT, "")
    if not (bench_dir and coretex_dir):
        return _fail(pv.PreviewError(
            "no pinned law trees are active, so there is nothing to score inside. A preview "
            "produced by an unpinned local runtime would be a number the adjudicator never "
            "computes, which is worse than no number at all",
            code="LAW_TREES_UNAVAILABLE",
            remedy=("run `coretex-validator sync-law --mirror URL` (and drop --no-law-cache), or "
                    "pass --repo-root DIR for a host that already holds benchmark-v2 and "
                    "coretex-memory")).as_dict())

    # TWO PUBLICATIONS, COMPOSED. The five sealed benchmark-v2 subtrees and coretex-memory come
    # from the law cache; `kit` and `integration` are NOT sealed code roots, can never appear in a
    # law publication, and come from the hash-pinned miner-kit tar `setup` already extracted. The
    # resolution is reported under `law.scoring_trees` so a refusal for want of an UNSEALED tree
    # can never read as "the law cache is missing" while `law.used` says otherwise.
    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=bench_dir, coretex_dir=coretex_dir, packages_dir=args.packages_dir,
        active_install=(law_block or {}).get("active_install"))
    if law_block is not None:
        law_block = {**law_block, "scoring_trees": resolution.as_dict()}
    try:
        pv.require_scoring_trees(resolution)
        store = pipeline.open_store(artifact_dir=args.artifact_dir,
                                    base_url=args.artifact_base_url)
        with open(os.path.expanduser(args.module), "r", encoding="utf-8") as fh:
            module_source = fh.read()
        manifest = _load_json(args.manifest)
        report = pv.preview_current_parent(
            child=pv.LawTreeChild(bench_v2_dir=bench_dir, coretex_dir=coretex_dir,
                                  repo_root=repo_root,
                                  support_dirs=resolution.support_dirs),
            store=store, parent_root=args.parent_root, target_profile=args.profile,
            module_source=module_source, candidate_manifest=manifest, scale=args.scale,
            portability_breadth=args.portability)
    except pv.PreviewError as exc:
        return _fail(exc.as_dict())

    report["law"] = law_block
    _emit(report, pretty=not args.compact)
    return 0                                                   # win or lose, this ran


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


def _add_law_arguments(parser: argparse.ArgumentParser) -> None:
    """The law-cache selection every admission-driving command shares."""
    parser.add_argument("--law-root", default=None,
                        help="publication root of the verified law cache to use (default: the "
                             "one sync-law wrote, when exactly one is unambiguous)")
    parser.add_argument("--law-cache", default=None,
                        help="law cache directory (default: ~/.local/share/coretex/law)")
    parser.add_argument("--no-law-cache", action="store_true",
                        help="ignore any law cache; deterministic admission then BACKLOGs exactly "
                             "as it did before sync-law existed")


def build_parser() -> argparse.ArgumentParser:
    from .law import MAX_OBJECT_BYTES
    # Safe to import here even though `build_parser` runs BEFORE `_activate_law`: unlike
    # `replay`, this module reads no law pins at import time.
    from .preview import DEFAULT_SCALE as pv_default_scale
    from .release import DEFAULT_PRODUCTION_RELEASE_URL
    from .setup import DEFAULT_COORDINATOR, DEFAULT_RPC
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
    _add_law_arguments(reproduce)
    reproduce.set_defaults(func=_cmd_reproduce)

    lawp = sub.add_parser(
        "sync-law",
        help="fetch + verify the published admission trees, and pin them for later commands")
    lawp.add_argument("--mirror", required=True,
                      help="http(s) url, file:// url or local directory serving the publication "
                           "set (a bare CAS naming each object by its root, or a published "
                           "evidence directory with a MANIFEST.json — the layout is discovered)")
    lawp.add_argument("--root", default=None,
                      help="publication root to fetch. REQUIRED — there is no default, because a "
                           "default would choose the law silently. `setup` discovers and syncs "
                           "the live one for you; name a root here to install a historical "
                           "publication instead")
    lawp.add_argument("--cache-dir", default=None,
                      help="where to materialize (default: ~/.local/share/coretex/law)")
    lawp.add_argument("--force", action="store_true",
                      help="re-materialize even if a verified cache is already present")
    lawp.add_argument("--timeout", type=float, default=30.0)
    lawp.add_argument("--max-object-bytes", type=int, default=MAX_OBJECT_BYTES,
                      help="per-object download ceiling; a mirror serving more is abandoned")
    lawp.add_argument("--print-export", action="store_true",
                      help="print `export VAR=...` lines instead of JSON, for "
                           "`eval \"$(coretex-validator sync-law --mirror URL --print-export)\"`")
    lawp.set_defaults(func=_cmd_sync_law)

    advance = sub.add_parser(
        "replay-advance", help="replay confirmed frontier advances (PASS/FAIL/BACKLOG, verbatim)")
    advance.add_argument("--logs", required=True,
                         help="JSON file of raw chain logs (a list, or {\"logs\": [...]})")
    advance.add_argument("--artifacts", required=True,
                         help="directory of content-addressed objects the advance points at")
    advance.add_argument("--epoch", type=int, default=None)
    advance.add_argument("--transition-index", type=int, default=None)
    advance.add_argument("--latest-block", type=int, default=None,
                         help="chain head; without it the feed is taken as already confirmed by "
                              "the caller's own policy, and that is reported rather than assumed")
    advance.add_argument("--confirmation-depth", type=int, default=15)
    advance.add_argument("--release", default=DEFAULT_PRODUCTION_RELEASE_URL,
                         help="path or url of the release artifact. It names the three addresses "
                              "the live lane is scoped to — topic0 alone is not an identity, so a "
                              "feed is decoded AGAINST a deployment, never on its own")
    advance.add_argument("--live-root", default=None,
                         help="the confirmed live root the advance must build on")
    advance.add_argument("--burned", default=None, help="JSON list of burned instance ids")
    advance.add_argument("--require-complete", action="store_true",
                         help="exit 1 when any advance BACKLOGs")
    advance.add_argument("--allow-test-doubles", action="store_true",
                         help="let a declared non-consensus-grade screen/sandbox count. Visible "
                              "on the command line on purpose")
    _add_law_arguments(advance)
    advance.set_defaults(func=_cmd_replay_advance)

    latest = sub.add_parser(
        "replay-latest",
        help="discover and replay the NEWEST confirmed advance (one command, from the chain)")
    latest.add_argument("--rpc", default=None,
                        help="JSON-RPC endpoint. Required unless --logs supplies the feed")
    latest.add_argument("--release", default=DEFAULT_PRODUCTION_RELEASE_URL,
                        help="path or url of the release artifact (default: signed canonical "
                             "Base production release)")
    latest.add_argument("--logs", default=None,
                        help="replay from this feed file instead of the chain (a JSON list, or "
                             "{\"logs\": [...]}) — the same discovery, offline")
    latest_source = latest.add_mutually_exclusive_group()
    latest_source.add_argument(
        "--artifacts", default=None,
        help="directory of content-addressed objects the advance points at")
    latest_source.add_argument(
        "--artifact-base-url", default=None,
        help="http(s) CAS serving the advance's objects by root (default: the release's "
             "artifact_base_url, when it publishes one)")
    latest.add_argument("--from-block", type=int, default=None,
                        help="start of the log scan (default: the release's deploy block)")
    latest.add_argument("--latest-block", type=int, default=None,
                        help="chain head for a --logs feed; without it the feed is taken as "
                             "already confirmed by the caller's own policy")
    latest.add_argument("--confirmation-depth", type=int, default=15)
    latest.add_argument("--live-root", default=None,
                        help="the confirmed live root the advance must build on")
    latest.add_argument("--burned", default=None, help="JSON list of burned instance ids")
    latest.add_argument("--require-complete", action="store_true",
                        help="exit 1 when the newest advance BACKLOGs")
    latest.add_argument("--allow-test-doubles", action="store_true",
                        help="let a declared non-consensus-grade screen/sandbox count. Visible "
                             "on the command line on purpose")
    _add_law_arguments(latest)
    latest.set_defaults(func=_cmd_replay_latest)

    receipt = sub.add_parser(
        "verify-receipt", help="replay a signed Benchmark-v2 receipt through the law cache")
    receipt.add_argument("receipt", help="path to a signed receipt wrapper JSON")
    receipt.add_argument("--artifact", default=None,
                         help="the V5 eval artifact that binds it (needed for a v2 report, and "
                              "for an exact-parent receipt: it names the parent frontier root the "
                              "incumbent execution is resolved from)")
    receipt_source = receipt.add_mutually_exclusive_group()
    receipt_source.add_argument(
        "--artifacts", default=None,
        help="directory of content-addressed objects the receipt's exact parent is resolved from "
             "(default: the directory holding the receipt)")
    receipt_source.add_argument(
        "--artifact-base-url", default=None,
        help="http(s) CAS serving those objects by root, instead of a directory")
    receipt.add_argument("--repo-root", default=None,
                         help="use these trees instead of the law cache — the directory that "
                              "CONTAINS benchmark-v2 and coretex-memory")
    receipt.add_argument("--require-complete", action="store_true",
                         help="exit 1 when the receipt could not be replayed at all")
    _add_law_arguments(receipt)
    receipt.set_defaults(func=_cmd_verify_receipt)

    parent_preview = sub.add_parser(
        "preview-current-parent",
        help="OPTIONAL: score a candidate against the CURRENT confirmed parent on PUBLIC dev "
             "cases (a preview, never an admission prediction)")
    parent_preview.add_argument("module", help="path to your submission module")
    parent_preview.add_argument("--manifest", required=True,
                                help="your candidate manifest JSON — the candidate arm is scored "
                                     "with ITS capabilities and max_compute_ms, and the parent "
                                     "arm with the parent release manifest's")
    parent_preview.add_argument("--profile", required=True, help="target profile id")
    parent_preview.add_argument("--parent-root", required=True,
                                help="the CONFIRMED frontier root to preview against; every "
                                     "object it names is re-hashed before it is used")
    parent_preview.add_argument("--artifact-dir", default=None,
                                help="local content-addressed artifact directory")
    parent_preview.add_argument("--artifact-base-url", default=None,
                                help="http(s) CAS serving the parent's objects by root")
    parent_preview.add_argument("--scale", default=pv_default_scale,
                                help="dev scale; refused unless the pinned kit publishes it")
    parent_preview.add_argument("--portability", nargs="?", const="full", default=None,
                                help="EXECUTE the portability support matrix locally at this "
                                     "breadth (full|x86|host). Omitted: the prerequisite is "
                                     "reported as not established rather than assumed")
    parent_preview.add_argument("--repo-root", default=None,
                                help="use these trees instead of the law cache — the directory "
                                     "that CONTAINS benchmark-v2 and coretex-memory")
    parent_preview.add_argument("--packages-dir", default=None,
                                help="where `setup` cached and extracted the miner-kit tar, which "
                                     "is where benchmark-v2/kit and benchmark-v2/integration come "
                                     "from (they are not sealed code roots, so no law publication "
                                     "carries them). Default: "
                                     "~/.local/share/coretex/packages")
    _add_law_arguments(parent_preview)
    parent_preview.set_defaults(func=_cmd_preview_current_parent)

    setup = sub.add_parser(
        "setup",
        help="verify the live deployment, cache kit packages, read the chain head")
    setup.add_argument("--rpc", default=DEFAULT_RPC,
                       help=f"JSON-RPC endpoint (default: {DEFAULT_RPC})")
    setup.add_argument("--coordinator", default=DEFAULT_COORDINATOR,
                       help="coordinator base URL serving /coretex/v5/kit (default: "
                            f"{DEFAULT_COORDINATOR})")
    setup.add_argument("--release", default=DEFAULT_PRODUCTION_RELEASE_URL)
    setup.add_argument("--confirmation-depth", type=int, default=15)
    setup.add_argument("--packages-dir", default=None,
                       help="where to cache kit packages (default: "
                            "~/.local/share/coretex/packages)")
    setup.add_argument("--skip-packages", action="store_true",
                       help="verify + read chain only; do not fetch the miner-kit tar")
    setup.add_argument("--skip-law", action="store_true",
                       help="diagnostic only: do not fetch the published admission law and do "
                            "not activate a new current tuple; run setup normally to activate "
                            "the coordinator's current kit and law together")
    setup.add_argument("--law-cache", default=None,
                       help="where to materialize the law (default: ~/.local/share/coretex/law)")
    setup.set_defaults(func=_cmd_setup)

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
