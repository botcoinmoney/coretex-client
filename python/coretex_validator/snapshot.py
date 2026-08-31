# SPDX-License-Identifier: Apache-2.0
"""Materialize the confirmed current CoreTex frontier for an installable adapter.

The chain selects the frontier; the public object surface supplies content-addressed bytes.  This
module joins those facts and writes one closed local resolver bundle.  It never accepts a manual
module path and never invents a second release registry.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable, Mapping, Optional

from . import benchmark_replay
from . import eval_artifact as evaluation
from . import frontier, join, parent_execution, publication, replay, rig_events
from .activation import PublicActivation
from .discovery import PublicScan, coordinator_signer_at, scan_public_feed
from .release import ReleaseDirectory
from .rpc import DEFAULT_CONFIRMATION_DEPTH, JsonRpc, RigViews

SNAPSHOT_FORMAT = "coretex.resolver-snapshot/v1"
SNAPSHOT_VERSION = 1
PROFILE_IDS = frontier.PROFILE_IDS


class SnapshotBuildError(RuntimeError):
    """Confirmed state or published bytes cannot produce one executable snapshot."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _load_json_bytes(raw: bytes, label: str) -> dict:
    def reject(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SnapshotBuildError(f"{label} repeats JSON key {key!r}")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject)
    except SnapshotBuildError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise SnapshotBuildError(f"{label} is not duplicate-free UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SnapshotBuildError(f"{label} must be a JSON object")
    return value


class PublicObjectReader:
    """Fetch one object under its declared rule from the coordinator's public object route."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def __call__(self, root: str, hash_rule: str) -> bytes:
        store = publication.HttpCAS(
            self.base_url, root_hash_rule=hash_rule, send_hash_rule=True)
        return store.get(root)


def _seed_genesis_objects(release: ReleaseDirectory, store: publication.InMemoryCAS) -> dict:
    release_path = Path(release.path)
    try:
        frontier_wrapper = _load_json_bytes(
            (release_path / "GENESIS-FRONTIER.json").read_bytes(), "GENESIS-FRONTIER.json")
        composition_raw = (release_path / "GENESIS-COMPOSITION.json").read_bytes()
        baseline_raw = (release_path / "GENESIS-BASELINE.json").read_bytes()
    except OSError as exc:
        raise SnapshotBuildError(f"release genesis objects are unavailable: {exc}") from exc
    if set(frontier_wrapper) != {"format", "frontier_root", "manifest"} \
            or frontier_wrapper.get("format") != "coretex.genesis-frontier/v1" \
            or frontier.frontier_root(frontier_wrapper["manifest"]) \
            != release.genesis_frontier_root \
            or frontier_wrapper.get("frontier_root") != release.genesis_frontier_root:
        raise SnapshotBuildError("release GENESIS-FRONTIER.json does not reproduce the release")
    composition_root = release.release.raw["genesis"]["composition_root"]
    composition = _load_json_bytes(composition_raw, "GENESIS-COMPOSITION.json")
    body = {key: value for key, value in composition.items() if key != "composition_root"}
    if composition.get("composition_root") != composition_root \
            or _sha(_canonical(body)) != composition_root:
        raise SnapshotBuildError("release genesis composition does not reproduce its root")
    store.put(composition_root, composition_raw)
    baseline_root = release.release.raw["genesis"]["baseline_root"]
    baseline = _load_json_bytes(baseline_raw, "GENESIS-BASELINE.json")
    baseline_body = {key: value for key, value in baseline.items() if key != "baseline_root"}
    if baseline.get("baseline_root") != baseline_root \
            or _sha(_canonical(baseline_body)) != baseline_root:
        raise SnapshotBuildError("release genesis baseline does not reproduce its root")
    store.put(baseline_root, baseline_raw)
    for profile in PROFILE_IDS:
        declaration = release.release.raw["genesis"]["profile_releases"][profile]
        path = release_path / declaration["path"]
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise SnapshotBuildError(f"genesis descriptor {profile} is unavailable: {exc}") \
                from exc
        descriptor = _load_json_bytes(raw, f"genesis descriptor {profile}")
        if _sha(_canonical(descriptor)) != declaration["root"]:
            raise SnapshotBuildError(f"genesis descriptor {profile} does not reproduce its root")
        store.put(declaration["root"], raw)
    return frontier_wrapper["manifest"]


def _fetch_item(item: Mapping[str, Any], *, fetch: Callable[[str, str], bytes],
                store: publication.InMemoryCAS, label: str) -> bytes:
    try:
        publication.availability_item(item["root"], item["hash_rule"], item["bytes"])
        raw = fetch(item["root"], item["hash_rule"])
        observed = publication.root_of(raw, item["hash_rule"])
    except Exception as exc:
        raise SnapshotBuildError(f"cannot fetch {label}: {exc}") from exc
    if observed != item["root"] or len(raw) != item["bytes"]:
        raise SnapshotBuildError(f"{label} bytes disagree with their availability record")
    store.put(item["root"], raw)
    return raw


def _context_event_for_advance(decoded: rig_events.DecodedLogs, advance):
    context_event = decoded.context_for(advance.epoch)
    if context_event is None or context_event.epoch_context_root != advance.epoch_context_root:
        raise SnapshotBuildError(
            f"transition {advance.epoch}/{advance.transition_index} has no matching "
            "confirmed epoch context event")
    return context_event


def _transition_rows(decoded: rig_events.DecodedLogs, *, rpc: JsonRpc,
                     views: RigViews, scan: Optional[PublicScan] = None,
                     release: Optional[ReleaseDirectory] = None) -> tuple[join.JoinResult, dict]:
    def calldata_for(tx_hash: str) -> str:
        transaction = rpc.transaction(tx_hash)
        calldata = transaction.get("input")
        if not isinstance(calldata, str):
            raise SnapshotBuildError(f"transaction {tx_hash} carries no calldata")
        return calldata

    if scan is None or release is None:
        signer = views.coordinator_signer()
    else:
        signer = lambda provenance: coordinator_signer_at(
            initial_signer=str(release.authority["initial_coordinator_signer"]),
            updates=scan.signer_updates, position=provenance.position)
    result = join.join_all(
        decoded, calldata_for=calldata_for, domain_separator=views.domain_separator(),
        coordinator_signer=signer, verify_signature=True)
    if result.unresolved:
        raise SnapshotBuildError(
            f"public CoreTex transitions did not fully join: {result.unresolved}")
    by_key = {item.key: item for item in result.transitions}
    if len(by_key) != len(result.transitions) or len(result.transitions) != len(decoded.advances):
        raise SnapshotBuildError("public advances do not have one unique joined receipt each")
    return result, by_key


def _reconstruct_frontier(*, release: ReleaseDirectory, scan: PublicScan,
                          rpc: JsonRpc, views: RigViews,
                          fetch: Callable[[str, str], bytes],
                          store: publication.InMemoryCAS,
                          benchmark_runner: Any) -> tuple[dict, dict]:
    current = _seed_genesis_objects(release, store)
    joined, joined_by_key = _transition_rows(
        scan.decoded, rpc=rpc, views=views, scan=scan, release=release)
    artifacts = {}
    epoch_contexts = {}
    frontier_timeline: list[tuple[tuple[int, int], dict]] = []
    initial_frontier = current
    for advance in scan.decoded.advances:
        joined_transition = joined_by_key[advance.join_key]
        descriptor = rig_events.decode_transition_descriptor(
            advance.compact_patch_bytes, expected_patch_hash=advance.patch_hash,
            parent_state_root=advance.parent_state_root, new_state_root=advance.new_state_root,
            transition_format_version=advance.transition_format_version)
        artifact_raw = fetch(
            descriptor.patch_artifact_hash, publication.HASH_RULE_FRONTIER_JSON)
        score_delta = int(joined_transition.receipt["scoreAfterPpm"]) \
            - int(joined_transition.receipt["scoreBeforePpm"])
        artifact = rig_events.verify_transition_artifact_bytes(
            artifact_raw, descriptor=descriptor, score_delta_ppm=score_delta,
            epoch_context_root_=advance.epoch_context_root)
        store.put(descriptor.patch_artifact_hash, artifact_raw)
        try:
            evaluation_raw = fetch(
                advance.eval_report_hash, publication.HASH_RULE_FRONTIER_JSON)
            evaluation_artifact = _load_json_bytes(
                evaluation_raw,
                f"epoch {advance.epoch} evaluation {advance.eval_report_hash}")
            if evaluation.eval_report_hash(evaluation_artifact) \
                    != advance.eval_report_hash:
                raise SnapshotBuildError(
                    f"epoch {advance.epoch} evaluation artifact does not reproduce its "
                    "on-chain address")
        except SnapshotBuildError:
            raise
        except Exception as exc:
            raise SnapshotBuildError(
                f"cannot fetch or validate epoch {advance.epoch} evaluation artifact: {exc}") \
                from exc
        store.put(advance.eval_report_hash, evaluation_raw)
        availability = evaluation_artifact["availability"]
        publication.validate_availability(availability)
        for kind in sorted(availability):
            item = availability[kind]
            if not store.has(item["root"]):
                _fetch_item(item, fetch=fetch, store=store,
                            label=f"epoch {advance.epoch} transition {advance.transition_index} "
                                  f"{kind}")
        witness = evaluation_artifact["determinism_witness"]
        witness_root = witness["source_root"]
        if not store.has(witness_root):
            try:
                witness_raw = fetch(witness_root, publication.HASH_RULE_FRONTIER_JSON)
                if publication.root_of(
                        witness_raw, publication.HASH_RULE_FRONTIER_JSON) != witness_root:
                    raise SnapshotBuildError("determinism witness source rehash mismatch")
            except Exception as exc:
                raise SnapshotBuildError(
                    f"cannot fetch determinism witness source {witness_root}: {exc}") from exc
            store.put(witness_root, witness_raw)
        context_event = _context_event_for_advance(scan.decoded, advance)
        cached = epoch_contexts.get(advance.epoch)
        if cached is None:
            context_raw = fetch(
                advance.epoch_context_root, publication.HASH_RULE_FRONTIER_JSON)
            context = _load_json_bytes(
                context_raw, f"epoch {advance.epoch} context {advance.epoch_context_root}")
            pins = replay.verify_epoch_context(
                context, advance.epoch, advance.epoch_context_root, release=release,
                active_frontier_root=context_event.parent_state_root)
            epoch_contexts[advance.epoch] = (context, pins, context_event.parent_state_root)
        else:
            context, pins, epoch_parent_root = cached
            if epoch_parent_root != context_event.parent_state_root:
                raise SnapshotBuildError(
                    f"epoch {advance.epoch} context parent changed within one scan")
        if frontier.frontier_root(current) != advance.parent_state_root:
            raise SnapshotBuildError(
                f"transition {advance.epoch}/{advance.transition_index} does not build on the "
                "reconstructed public frontier")
        try:
            evaluation_report = publication.fetch_json(
                availability["eval_report"]["root"],
                hash_rule=availability["eval_report"]["hash_rule"], store=store,
                expected_bytes_len=availability["eval_report"]["bytes"])
            counter_resource_law = publication.fetch_json(
                availability["counter_resource_law"]["root"],
                hash_rule=availability["counter_resource_law"]["hash_rule"], store=store,
                expected_bytes_len=availability["counter_resource_law"]["bytes"])
            replay.replay_descriptor_v3(
                joined=joined_transition,
                parent_manifest=current,
                release=release,
                epoch_parent_root=context_event.parent_state_root,
                transition_artifact_bytes=artifact_raw,
                evaluation_artifact=evaluation_artifact,
                evaluation_report=evaluation_report,
                epoch_context=context,
                counter_resource_law=counter_resource_law,
                store=store,
                require_availability=True,
                resolve_witness_source=True,
                benchmark_runner=benchmark_runner,
            )
        except Exception as exc:
            raise SnapshotBuildError(
                f"full descriptor-v3 replay failed for epoch {advance.epoch} transition "
                f"{advance.transition_index}: {exc}") from exc
        current = rig_events.replay_transition_artifact(current, artifact, epoch_pins=pins)
        frontier_timeline.append((joined_transition.credit.provenance.position, current))
        artifacts[advance.join_key] = artifact

    for screener in sorted(
            joined.screener_passes, key=lambda item: item.credit.provenance.position):
        parent = initial_frontier
        for position, candidate_parent in frontier_timeline:
            if position >= screener.credit.provenance.position:
                break
            parent = candidate_parent
        receipt = screener.receipt
        eval_root = str(receipt["evalReportHash"]).lower().removeprefix("0x")
        try:
            evaluation_raw = fetch(eval_root, publication.HASH_RULE_FRONTIER_JSON)
            evaluation_artifact = _load_json_bytes(
                evaluation_raw,
                f"epoch {screener.credit.epoch} screener evaluation {eval_root}")
            if evaluation.eval_report_hash(evaluation_artifact) != eval_root:
                raise SnapshotBuildError(
                    "screener evaluation artifact does not reproduce its signed evalReportHash")
            scored_release = evaluation_artifact.get("candidate", {}).get("release_root")
            signed_artifact = str(receipt["artifactHash"]).lower().removeprefix("0x")
            if signed_artifact != scored_release:
                raise SnapshotBuildError(
                    "screener artifactHash is not the scored candidate release_root")
        except SnapshotBuildError:
            raise
        except Exception as exc:
            raise SnapshotBuildError(
                f"cannot fetch or validate epoch {screener.credit.epoch} screener evaluation "
                f"artifact: {exc}") from exc
        store.put(eval_root, evaluation_raw)
        availability = evaluation_artifact.get("availability")
        try:
            publication.validate_availability(availability)
            for kind in sorted(availability):
                item = availability[kind]
                if not store.has(item["root"]):
                    _fetch_item(
                        item, fetch=fetch, store=store,
                        label=f"epoch {screener.credit.epoch} screener {kind}")
            witness_root = evaluation_artifact["determinism_witness"]["source_root"]
            if not store.has(witness_root):
                witness_raw = fetch(witness_root, publication.HASH_RULE_FRONTIER_JSON)
                if publication.root_of(
                        witness_raw, publication.HASH_RULE_FRONTIER_JSON) != witness_root:
                    raise SnapshotBuildError("screener determinism witness source rehash mismatch")
                store.put(witness_root, witness_raw)
            report_item = availability["eval_report"]
            law_item = availability["counter_resource_law"]
            evaluation_report = publication.fetch_json(
                report_item["root"], hash_rule=report_item["hash_rule"], store=store,
                expected_bytes_len=report_item["bytes"])
            counter_resource_law = publication.fetch_json(
                law_item["root"], hash_rule=law_item["hash_rule"], store=store,
                expected_bytes_len=law_item["bytes"])
        except Exception as exc:
            raise SnapshotBuildError(
                f"screener evaluation evidence is unavailable or malformed: {exc}") from exc
        context_event = scan.decoded.context_for(screener.credit.epoch)
        if context_event is None \
                or context_event.epoch_context_root != receipt["epochContextRoot"]:
            raise SnapshotBuildError(
                f"screener epoch {screener.credit.epoch} has no matching confirmed context")
        cached = epoch_contexts.get(screener.credit.epoch)
        if cached is None:
            context_raw = fetch(
                receipt["epochContextRoot"], publication.HASH_RULE_FRONTIER_JSON)
            context = _load_json_bytes(
                context_raw, f"epoch {screener.credit.epoch} screener context")
            pins = replay.verify_epoch_context(
                context, screener.credit.epoch, receipt["epochContextRoot"], release=release,
                active_frontier_root=context_event.parent_state_root)
            epoch_contexts[screener.credit.epoch] = (
                context, pins, context_event.parent_state_root)
        else:
            context, _pins, context_parent = cached
            if context_parent != context_event.parent_state_root:
                raise SnapshotBuildError("screener epoch context parent changed within one scan")
        try:
            replay.replay_screener(
                screener=screener, parent_manifest=parent, release=release,
                epoch_parent_root=context_event.parent_state_root,
                evaluation_artifact=evaluation_artifact,
                evaluation_report=evaluation_report,
                epoch_context=context,
                counter_resource_law=counter_resource_law,
                store=store, benchmark_runner=benchmark_runner)
        except Exception as exc:
            raise SnapshotBuildError(
                f"full screener replay failed for epoch {screener.credit.epoch} rig "
                f"{screener.credit.rig_id} solve {screener.credit.solve_index}: {exc}") from exc
    return current, artifacts


def _rig_receipt_rows(*, scan: PublicScan, activation_views: RigViews,
                      head_views: RigViews, joined: join.JoinResult) -> list[dict]:
    coretex_receipts = {
        (item.credit.rig_id, item.credit.solve_index): item.receipt
        for item in [*joined.transitions, *joined.screener_passes]
        if item.receipt is not None
    }
    credits = [("coretex", item) for item in scan.decoded.coretex_credits] \
        + [("standard", item) for item in scan.decoded.standard_credits]
    by_rig: dict[int, list[tuple[str, Any]]] = {}
    for kind, item in credits:
        by_rig.setdefault(item.rig_id, []).append((kind, item))
    rows = []
    for rig_id in sorted(by_rig):
        ordered = sorted(by_rig[rig_id], key=lambda entry: entry[1].provenance.position)
        start_index = activation_views.rig_next_index(rig_id)
        start_hash = activation_views.rig_last_receipt_hash(rig_id)
        expected_hash = start_hash
        receipts = []
        for offset, (kind, credit) in enumerate(ordered):
            expected_index = start_index + offset
            if credit.solve_index != expected_index:
                raise SnapshotBuildError(
                    f"rig {rig_id} public receipt index {credit.solve_index} is not dense from "
                    f"pre-activation index {start_index}")
            if kind == "coretex":
                receipt = coretex_receipts.get((rig_id, credit.solve_index))
                if receipt is None or receipt["prevReceiptHash"] != expected_hash:
                    raise SnapshotBuildError(
                        f"rig {rig_id} CoreTex receipt {credit.solve_index} does not bind the "
                        "shared predecessor receipt hash")
            receipts.append({
                "block_number": credit.provenance.block_number,
                "kind": kind,
                "log_index": credit.provenance.log_index,
                "receipt_hash": credit.receipt_hash,
                "solve_index": credit.solve_index,
                "transaction_hash": credit.provenance.transaction_hash,
            })
            expected_hash = credit.receipt_hash
        end_index = head_views.rig_next_index(rig_id)
        end_hash = head_views.rig_last_receipt_hash(rig_id)
        if end_index != start_index + len(receipts) or end_hash != expected_hash:
            raise SnapshotBuildError(
                f"rig {rig_id} head index/hash do not close the public receipt window")
        rows.append({
            "end_index": end_index,
            "end_receipt_hash": end_hash,
            "receipts": receipts,
            "rig_id": rig_id,
            "start_index": start_index,
            "start_receipt_hash": start_hash,
        })
    return rows


def _advance_row(item: rig_events.StateAdvanced) -> dict:
    return {
        "block_number": item.provenance.block_number,
        "core_version_hash": item.core_version_hash,
        "epoch": item.epoch,
        "epoch_context_root": item.epoch_context_root,
        "eval_report_hash": item.eval_report_hash,
        "improvement_credits": item.improvement_credits,
        "log_index": item.provenance.log_index,
        "miner": item.miner,
        "new_state_root": item.new_state_root,
        "parent_state_root": item.parent_state_root,
        "patch_hash": item.patch_hash,
        "transaction_hash": item.provenance.transaction_hash,
        "transition_format_version": item.transition_format_version,
        "transition_index": item.transition_index,
    }


def _verify_current_context_object(*, epoch: int, context: Mapping[str, str],
                                   release: ReleaseDirectory,
                                   object_fetch: Callable[[str, str], bytes]) -> dict:
    try:
        raw = object_fetch(
            context["epoch_context_root"], publication.HASH_RULE_FRONTIER_JSON)
        document = _load_json_bytes(raw, f"current epoch {epoch} context")
        replay.verify_epoch_context(
            document, epoch, context["epoch_context_root"], release=release,
            active_frontier_root=context["parent_state_root"])
    except Exception as exc:
        raise SnapshotBuildError(
            f"current epoch context object is unavailable or invalid: {exc}") from exc
    return document


def materialize(*, release: ReleaseDirectory, activation: PublicActivation,
                scan: PublicScan, rpc: JsonRpc, object_fetch: Callable[[str, str], bytes],
                output_dir: str, confirmation_depth: int) -> dict:
    """Build a closed resolver directory from one already confirmed public scan."""
    activation_hash = rpc.block_hash_at(activation.confirmed_block)
    if rpc.block_hash_at(scan.head.number) != scan.head.hash:
        raise SnapshotBuildError("confirmed head changed before snapshot materialization")
    head_views = RigViews(rpc, scan.deployment, block=scan.head.number)
    epoch = head_views.current_epoch()
    activation.require_epoch(epoch, what="current epoch")
    if not head_views.epoch_has_context(epoch):
        raise SnapshotBuildError(f"current epoch {epoch} has no CoreTex context")
    context_event = scan.decoded.context_for(epoch)
    if context_event is None:
        raise SnapshotBuildError(f"public scan has no context event for current epoch {epoch}")
    context = {
        "core_version_hash": head_views.epoch_core_version_hash(epoch),
        "epoch_context_root": head_views.epoch_context_root(epoch),
        "parent_state_root": head_views.epoch_parent_state_root(epoch),
    }
    if context != {
            "core_version_hash": context_event.core_version_hash,
            "epoch_context_root": context_event.epoch_context_root,
            "parent_state_root": context_event.parent_state_root}:
        raise SnapshotBuildError("current epoch views disagree with the confirmed context event")
    if context["core_version_hash"] != release.release.raw["compatibility_lock_root"]:
        raise SnapshotBuildError("current epoch does not bind this 1.0.0 compatibility lock")
    _verify_current_context_object(
        epoch=epoch, context=context, release=release, object_fetch=object_fetch)
    continuity = rig_events.context_parent_continuity(scan.decoded)
    if continuity["problems"]:
        raise SnapshotBuildError(
            f"public epoch context/advance ordering is invalid: {continuity['problems']}")

    current_advances = [item for item in scan.decoded.advances if item.epoch == epoch]
    current_advances.sort(key=lambda item: item.transition_index)
    count = head_views.transition_count(epoch)
    live_root = head_views.live_state_root(epoch)
    if len(current_advances) != count:
        raise SnapshotBuildError(
            f"current epoch chain count is {count}, scan has {len(current_advances)} advances")

    store = publication.InMemoryCAS()
    with benchmark_replay.ReleaseBenchmarkRunner(release) as benchmark_runner:
        current, _artifacts = _reconstruct_frontier(
            release=release, scan=scan, rpc=rpc, views=head_views,
            fetch=object_fetch, store=store, benchmark_runner=benchmark_runner)
        if frontier.frontier_root(current) != live_root:
            raise SnapshotBuildError("reconstructed frontier does not equal current chain live root")

        reference_roots = {
            profile: release.release.raw["genesis"]["profile_releases"][profile]["root"]
            for profile in PROFILE_IDS
        }
        executions = {}
        for profile in PROFILE_IDS:
            try:
                executions[profile] = parent_execution.fetch_parent_execution(
                    store=store, parent_manifest=current, target_profile=profile,
                    fr_module=frontier, pub_module=publication,
                    reference_release_roots=reference_roots, validate_runtime=True,
                    runtime_validator=benchmark_runner.validate_execution)
            except Exception as exc:
                raise SnapshotBuildError(
                    f"cannot resolve and runtime-validate current execution for {profile}: "
                    f"{exc}") from exc

    activation_views = RigViews(
        rpc, scan.deployment, block=activation.confirmed_block - 1)
    joined, _joined_by_key = _transition_rows(
        scan.decoded, rpc=rpc, views=head_views, scan=scan, release=release)
    rig_receipts = _rig_receipt_rows(
        scan=scan, activation_views=activation_views, head_views=head_views, joined=joined)
    rules_version = head_views.active_rules_version(epoch)
    rules = head_views.core_tex_policy(rules_version)
    if rules is None:
        raise SnapshotBuildError(f"current rules version {rules_version} does not exist")

    target = Path(output_dir).expanduser().resolve()
    if target.exists():
        raise SnapshotBuildError(f"snapshot output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=target.name + ".tmp-", dir=target.parent))
    profiles = {}
    try:
        for profile in PROFILE_IDS:
            execution = executions[profile]
            if execution["exec"] == "reference":
                profiles[profile] = {
                    "exec": "reference", "release_root": execution["release_root"]}
                continue
            manifest_raw = store.get(execution["release_root"])
            module_root = execution["module"]["sha256"]
            module_raw = store.get(module_root)
            composition_root = current["default_composition_root"]
            composition_raw = store.get(composition_root)
            bundle_rel = f"bundles/{profile}"
            bundle_dir = temporary / bundle_rel
            bundle_dir.mkdir(parents=True)
            (bundle_dir / "manifest.json").write_bytes(manifest_raw)
            (bundle_dir / "module.py").write_bytes(module_raw)
            provenance_rel = f"provenance/{profile}.composition.json"
            provenance_path = temporary / provenance_rel
            provenance_path.parent.mkdir(parents=True, exist_ok=True)
            provenance_path.write_bytes(composition_raw)
            profiles[profile] = {
                "bundle": {
                    "directory": bundle_rel,
                    "manifest": "manifest.json",
                    "manifest_sha256": _sha(manifest_raw),
                    "manifest_size": len(manifest_raw),
                    "module": "module.py",
                    "module_sha256": module_root,
                    "module_size": len(module_raw),
                },
                "candidate_hash": execution["candidate_hash"],
                "exec": "candidate_module",
                "provenance": {
                    "composition": provenance_rel,
                    "composition_root": composition_root,
                    "composition_sha256": _sha(composition_raw),
                    "composition_size": len(composition_raw),
                },
                "release_root": execution["release_root"],
            }
        document = {
            "advances": [_advance_row(item) for item in current_advances],
            "chain": {
                "chain_id": scan.deployment.chain_id,
                "observation": {
                    "block_hash": scan.head.hash,
                    "block_number": scan.head.number,
                    "confirmation_depth": int(confirmation_depth),
                },
            },
            "deployment": {
                "mining": scan.deployment.mining,
                "registry": scan.deployment.registry,
                "verifier": scan.deployment.verifier,
            },
            "epoch": {
                "context": context,
                "finalized": head_views.epoch_finalized(epoch),
                "id": epoch,
                "live_state_root": live_root,
                "rules": rules,
                "transition_count": count,
            },
            "format": SNAPSHOT_FORMAT,
            "frontier": {"manifest": current, "root": live_root},
            "profiles": profiles,
            "public_activation": {
                "confirmed_block": activation.confirmed_block,
                "epoch": activation.epoch,
                "genesis_frontier_root": release.genesis_frontier_root,
            },
            "release_root": release.release_root,
            "rig_receipts": rig_receipts,
            "version": SNAPSHOT_VERSION,
        }
        (temporary / "resolver-snapshot.json").write_bytes(_json_bytes(document))
        if rpc.block_hash_at(activation.confirmed_block) != activation_hash \
                or rpc.block_hash_at(scan.head.number) != scan.head.hash:
            raise SnapshotBuildError(
                "chain changed while context, receipts, and public artifacts were materialized")
        os.replace(temporary, target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return document


def build_from_public(*, release: ReleaseDirectory, activation: PublicActivation,
                      rpc: JsonRpc, object_base_url: str, output_dir: str,
                      to_block: Optional[int] = None,
                      confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH) -> dict:
    scan = scan_public_feed(
        rpc, activation=activation, release=release, to_block=to_block,
        confirmation_depth=confirmation_depth)
    return materialize(
        release=release, activation=activation, scan=scan, rpc=rpc,
        object_fetch=PublicObjectReader(object_base_url), output_dir=output_dir,
        confirmation_depth=confirmation_depth)


__all__ = [
    "SNAPSHOT_FORMAT", "SNAPSHOT_VERSION", "SnapshotBuildError", "PublicObjectReader",
    "materialize", "build_from_public",
]
