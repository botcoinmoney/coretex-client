# SPDX-License-Identifier: Apache-2.0
"""The eight steps, in order, as one run.

    1. discover the rehearsal release                              :mod:`.release`
    2. verify contract bytecode against the release's runtime hashes
    3. replay per-rig receipt continuity                            :mod:`.receipt_chain`
    4. reconstruct the exact transition (§7 join, patchHash-keyed)  :mod:`.join`
    5. rerun deterministic Benchmark-v2 admission                   :mod:`.replay`
    6. verify artifacts and HISTORICAL law                          :mod:`.historical_law`
    7. reproduce the resolver snapshot, THEN check its signature    :mod:`.snapshot`
    8. export the verified snapshot                                 :mod:`.export`

THE ORDER IS NOT A STYLE CHOICE. Each step is only meaningful once the ones above it have passed:
verifying a receipt chain against contracts you have not identified proves nothing, joining
calldata to logs you have not attributed proves nothing, and reproducing a snapshot from a
transition you have not joined is just restating the snapshot. So the run STOPS at the first step
that fails outright, and records the remaining steps as NOT REACHED rather than as passing or
failing. "Not reached" and "passed" must never render the same way in a report.

TWO KINDS OF NEGATIVE OUTCOME, KEPT APART EVERYWHERE.

* **FAIL** — a check ran and the chain disagreed with the claim. The claim is wrong.
* **BACKLOG / unverified** — a check could not run on this host. Nothing was learned. Step 5 is
  the one that lands here routinely, because deterministic admission needs the ``benchmark-v2``
  and ``coretex-memory`` trees and those are not published (see ``docs/V5-RIG-VALIDATOR.md``).

Collapsing the second into the first would make a normal clean-machine run look like a detected
fraud; collapsing it into a pass would be a lie. :class:`RunReport` carries them separately and
:mod:`.export` copies the unverified list into the export verbatim.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from . import dispatch as dp
from . import export as ex
from . import frontier as fr
from . import historical_law as hl
from . import join as jn
from . import publication as pub
from . import receipt_chain as rc
from . import release as rel
from . import release_graph as rg
from . import replay as rp
from . import resolver_snapshot as rsn
from . import rig_events as rig
from . import snapshot as snap
from .rpc import JsonRpc, RigViews, DEFAULT_CONFIRMATION_DEPTH

STEP_NAMES = ("discover_release", "verify_deployment", "receipt_continuity", "join_transition",
              "deterministic_admission", "historical_law", "resolver_snapshot", "export")


class PipelineError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- #
# Artifact storage
# --------------------------------------------------------------------------- #
class UrlContentStore(pub.ContentStore):
    """A read-only content-addressed store served over HTTP.

    ``get`` returns the bytes the surface would serve a third party and nothing else — no local
    cache fallback, no retry against a different base. :func:`publication.read_back` re-hashes
    whatever comes back, so a substituted body fails there; the job here is only to not quietly
    substitute one ourselves.
    """

    def __init__(self, base_url: str, *, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _url(self, root: str) -> str:
        return f"{self.base_url}/{root}"

    def put(self, root: str, data: bytes) -> None:
        raise pub.PublicationError("this store is read-only; a validator publishes nothing")

    def get(self, root: str) -> bytes:
        try:
            with urllib.request.urlopen(self._url(root), timeout=self.timeout) as response:  # noqa: S310,E501
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise pub.ObjectNotFoundError(f"{root} is not published at {self.base_url}") from exc
            raise pub.AvailabilityError(f"{root}: {exc}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise pub.AvailabilityError(f"{root}: {exc}") from exc

    def has(self, root: str) -> bool:
        try:
            self.get(root)
        except pub.PublicationError:
            return False
        return True


def open_store(*, artifact_dir: Optional[str], base_url: Optional[str]) -> pub.ContentStore:
    if artifact_dir:
        return pub.FilesystemCAS(os.path.expanduser(artifact_dir))
    if base_url:
        return UrlContentStore(base_url)
    raise PipelineError(
        "ARTIFACT_STORE_UNCONFIGURED",
        "no artifact source: pass --artifact-dir, or publish artifact_base_url in the release. "
        "The eval artifact and candidate manifest are addressed by hash in the confirmed advance, "
        "so they can come from anywhere — but they must come from somewhere")


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
@dataclass
class StepResult:
    name: str
    status: str                       # "PASS" | "FAIL" | "UNVERIFIED" | "NOT_REACHED"
    detail: Dict[str, Any] = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {"step": self.name, "status": self.status, "detail": self.detail,
                "problems": list(self.problems)}


@dataclass
class RunReport:
    ok: bool
    steps: List[StepResult]
    unverified: List[Dict[str, Any]] = field(default_factory=list)
    export: Optional[ex.Export] = None

    def step(self, name: str) -> Optional[StepResult]:
        return next((s for s in self.steps if s.name == name), None)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "format": "coretex.rig-validator-run/v1",
            "ok": self.ok,
            "steps": [s.as_dict() for s in self.steps],
            "unverified": list(self.unverified),
            "export_root": self.export.root() if self.export is not None else None,
        }


# --------------------------------------------------------------------------- #
# The run
# --------------------------------------------------------------------------- #
def run(*, release_location: str, rpc_url: str,
        runtime_record: Optional[Mapping[str, Any]] = None,
        epoch: Optional[int] = None,
        transition_index: Optional[int] = None,
        artifact_dir: Optional[str] = None,
        published_snapshot: Optional[Mapping[str, Any]] = None,
        confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
        from_block: Optional[int] = None,
        to_block: Optional[int] = None,
        verify_signatures: bool = True,
        allow_test_doubles: bool = False,
        export_path: Optional[str] = None) -> RunReport:
    """Run steps 1-8 against a live endpoint. Returns a report; raises only on caller error."""
    steps: List[StepResult] = []
    unverified: List[Dict[str, Any]] = []

    def record(name: str, status: str, detail: Optional[Dict[str, Any]] = None,
               problems: Optional[Sequence[str]] = None) -> StepResult:
        result = StepResult(name, status, dict(detail or {}), list(problems or ()))
        steps.append(result)
        return result

    def stop(report_ok: bool = False) -> RunReport:
        for name in STEP_NAMES:
            if not any(s.name == name for s in steps):
                steps.append(StepResult(name, "NOT_REACHED"))
        return RunReport(ok=report_ok, steps=steps, unverified=unverified)

    # -- 1. discover -------------------------------------------------------- #
    try:
        release = rel.discover(release_location)
    except rel.ReleaseError as exc:
        record("discover_release", "FAIL", {"code": exc.code}, [exc.message])
        return stop()
    record("discover_release", "PASS", {
        "classification": release.classification, "chain_id": release.chain_id,
        "network": release.network, "addresses": release.addresses,
        "authorities": release.source_divergence()})

    rpc = JsonRpc(rpc_url)
    try:
        rpc.assert_chain(release.chain_id)
    except Exception as exc:                                   # noqa: BLE001 - reported
        record("verify_deployment", "FAIL", {}, [str(exc)])
        return stop()

    head = rpc.confirmed_head(confirmation_depth)
    observation_block = int(release.observation_block or head)
    if observation_block > head:
        record("verify_deployment", "FAIL", {"observation_block": observation_block, "head": head},
               [f"the release names observation block {observation_block}, which is not yet "
                f"{confirmation_depth} blocks deep (confirmed head {head})"])
        return stop()
    pinned = rpc.block(observation_block)

    # -- 2. bytecode + wiring ----------------------------------------------- #
    verification = rel.verify_deployment(release, rpc, block=observation_block)
    record("verify_deployment", "PASS" if verification.ok else "FAIL",
           {"block": observation_block, "block_hash": pinned.hash,
            **verification.as_dict()}, verification.failures)
    if not verification.ok:
        return stop()

    deployment = release.deployment
    views = RigViews(rpc, deployment, block=observation_block)

    # -- scan ---------------------------------------------------------------- #
    scan_from = int(from_block if from_block is not None else release.deploy_block)
    scan_to = int(to_block if to_block is not None else observation_block)
    logs = rpc.get_logs(addresses=list(deployment.addresses), topics=[],
                        from_block=scan_from, to_block=scan_to)
    decoded = rig.scan(logs, deployment)

    # -- 3. receipt continuity ---------------------------------------------- #
    chains = rc.replay_all(decoded, views=views)
    context_continuity = rig.context_parent_continuity(decoded)
    chain_problems = ([p for result in chains.values() for p in result.problems]
                      + list(context_continuity["problems"]))
    record("receipt_continuity", "PASS" if not chain_problems else "FAIL",
           {"rigs": {str(k): v.as_dict() for k, v in sorted(chains.items())},
            "coretex_state_continuity": context_continuity,
            "scanned_blocks": [scan_from, scan_to], "logs_seen": len(logs),
            "logs_ignored": decoded.ignored}, chain_problems)
    if chain_problems:
        return stop()

    # -- 4. the join --------------------------------------------------------- #
    try:
        domain_separator = views.domain_separator()
        coordinator_signer = views.coordinator_signer()
    except Exception as exc:                                   # noqa: BLE001 - reported
        record("join_transition", "FAIL", {}, [f"mining view calls failed: {exc}"])
        return stop()

    calldata_cache: Dict[str, str] = {}

    def calldata_for(tx_hash: str) -> str:
        if tx_hash not in calldata_cache:
            calldata_cache[tx_hash] = str(rpc.transaction(tx_hash).get("input", ""))
        return calldata_cache[tx_hash]

    joined = jn.join_all(decoded, calldata_for=calldata_for,
                         domain_separator=domain_separator,
                         coordinator_signer=coordinator_signer,
                         verify_signature=verify_signatures)
    if not joined.transitions:
        if joined.unresolved:
            record("join_transition", "FAIL", joined.as_dict(),
                   ["accepted CoreTex activity exists, but no state advance could be joined"])
            return stop()
        reason = ("no accepted CoreTex state advance exists in the scanned production range; "
                  "deployment and receipt-chain checks passed, but transition replay and "
                  "activation export are not available until the first advance")
        unverified.append({"step": "join_transition", "code": "NO_ACCEPTED_TRANSITION",
                           "reason": reason})
        record("join_transition", "UNVERIFIED", joined.as_dict(), [reason])
        return stop(report_ok=True)
    selected = _select(joined.transitions, epoch=epoch, transition_index=transition_index)
    if selected is None:
        record("join_transition", "FAIL", joined.as_dict(),
               [f"no joined transition matches epoch={epoch} index={transition_index}"])
        return stop()
    lineage, lineage_problems = jn.walk_lineage(
        views, from_epoch=selected.advance.epoch, back_to=max(0, selected.advance.epoch - 32))
    for item in joined.unresolved:
        unverified.append({"step": "join_transition", **dict(item)})
    record("join_transition", "PASS", {
        **joined.as_dict(), "selected": selected.as_dict(),
        "lineage": [{"epoch": s.epoch, "served": s.served, "sealed": s.sealed,
                     "final_state_root": s.final_root, "source": s.source,
                     "flagged": s.flagged, "note": s.note} for s in lineage]},
        lineage_problems)
    if lineage_problems:
        steps[-1].status = "FAIL"
        return stop()

    # -- 6a. historical law (needed before admission: it supplies the pins) --- #
    try:
        chain_policy = None
        try:
            active = views.active_rules_version(selected.advance.epoch)
            chain_policy = views.core_tex_policy(active)
        except Exception:                                  # noqa: BLE001 - fall back to the logs
            chain_policy = None
        law = hl.law_for_epoch(decoded, selected.advance.epoch, chain_policy=chain_policy)
    except hl.LawError as exc:
        record("deterministic_admission", "NOT_REACHED")
        record("historical_law", "FAIL", {"code": exc.code}, [exc.message])
        return stop()
    law_problems = hl.check_advance_against_law(selected.advance, law)
    law_problems += hl.check_receipt_against_law(selected.receipt.values, law)

    # -- 5. deterministic admission ------------------------------------------ #
    admission: Dict[str, Any]
    try:
        store = open_store(artifact_dir=artifact_dir, base_url=release.artifact_base_url)
    except PipelineError as exc:
        admission = {"outcome": "BACKLOG", "code": exc.code, "reason": exc.message}
        record("deterministic_admission", "UNVERIFIED", admission, [exc.message])
        unverified.append({"step": "deterministic_admission", "code": exc.code,
                           "reason": exc.message})
        artifact = None
    else:
        artifact, admission = _admit(selected, law, store,
                                     allow_test_doubles=allow_test_doubles)
        status = {"PASS": "PASS", "FAIL": "FAIL"}.get(admission["outcome"], "UNVERIFIED")
        record("deterministic_admission", status, admission,
               [admission["reason"]] if status != "PASS" else [])
        if status == "UNVERIFIED":
            unverified.append({"step": "deterministic_admission", "code": admission.get("code"),
                               "reason": admission["reason"]})
        elif status == "FAIL":
            record("historical_law", "NOT_REACHED")
            return stop()

    # -- 6b. law verdict ------------------------------------------------------ #
    record("historical_law", "PASS" if not law_problems else "FAIL",
           {"law": law.as_dict(),
            "artifact_verified": bool(artifact is not None)}, law_problems)
    if law_problems:
        return stop()

    # -- 7. the resolver snapshot --------------------------------------------- #
    observation = snap.ChainObservation(
        chain_id=release.chain_id, block_number=observation_block, block_hash=pinned.hash,
        registry=deployment.registry, mining=deployment.mining, verifier=deployment.verifier,
        live_state_root=views.live_state_root(selected.advance.epoch),
        transition_count=views.transition_count(selected.advance.epoch),
        epoch_finalized=views.epoch_finalized(selected.advance.epoch),
        coordinator_signer=coordinator_signer)
    artifact_roots = {"eval_artifact": selected.advance.eval_report_hash,
                      "candidate_release": selected.receipt["artifactHash"]}
    published_payload = None
    if published_snapshot is not None:
        published_payload = published_snapshot.get("payload", published_snapshot)

    # WHICH SCHEMA IS BEING REPRODUCED IS DECIDED BY THE PUBLISHED PAYLOAD, not by this module.
    #
    # The RESOLVER's per-epoch schema is the published one; this package's own per-transition
    # shape lost the scope decision and survives only as an internal projection for a run with
    # nothing to compare against. So when a caller supplies a real published snapshot, the
    # reproduction is delegated to `resolver_snapshot`, which speaks that schema. Building this
    # lane's retired shape and then reporting SCHEMA_UNSUPPORTED against the published one would
    # be this module refusing to do the job it was asked to do.
    if (published_payload is not None
            and published_payload.get("schema") in rsn.SUPPORTED_SCHEMAS):
        try:
            reconstructed, comparison = rsn.reproduce_from_chain(
                published_payload, rpc_url=rpc_url, store_dir=artifact_dir or "",
                runtime_record=runtime_record,
                production_authority=release.production_authority)
        except Exception as exc:                           # noqa: BLE001 - reported, not raised
            record("resolver_snapshot", "FAIL", {"code": "RESOLVER_SCHEMA_REBUILD_FAILED"},
                   [str(exc)])
            return stop()
        reproduction = snap.ReproductionResult(
            reproduced=comparison.identical,
            reconstructed_hash=comparison.reproduced_sha256,
            published_hash=comparison.published_sha256,
            differences=[k.key for k in comparison.keys if not k.equal],
            byte_length=comparison.reproduced_length)
    else:
        reconstructed = snap.build_unsigned(transition=selected, law=law, observation=observation,
                                            artifact_roots=artifact_roots, lineage=lineage,
                                            classification=release.classification,
                                            production_authority=release.production_authority)
        reproduction = snap.reproduce(reconstructed, published_payload)
    # NO SIGNATURE CHECK. A downloaded snapshot is a cache; what makes it true is that the bytes
    # reconstruct from chain truth. See export.build_export for the full reasoning.
    record("resolver_snapshot",
           "PASS" if (reproduction.reproduced or published_payload is None) else "FAIL",
           {"reproduction": reproduction.as_dict(), "unsigned_payload": reconstructed},
           reproduction.differences if published_payload is not None else [])
    if published_payload is None:
        unverified.append({
            "step": "resolver_snapshot", "code": "NO_PUBLISHED_SNAPSHOT",
            "reason": ("nothing was published to compare against, so the payload was RECONSTRUCTED "
                       "but not REPRODUCED. Byte-for-byte agreement with a resolver is unproven")})
    elif not reproduction.reproduced:
        return stop()

    # -- 8. export ------------------------------------------------------------ #
    if published_payload is None:
        # Reproduction is what an export attests to. Without a published payload there is a
        # verified reconstruction and no agreement, so the export is withheld rather than
        # emitted with a weaker meaning under the same format.
        record("export", "UNVERIFIED",
               {"reason": "withheld: an export attests to byte-for-byte reproduction, and no "
                          "published snapshot was supplied to reproduce"})
        return stop(report_ok=True)
    try:
        exported = ex.build_export(
            snapshot_payload=reconstructed, reproduction=reproduction,
            release_document=release.raw,
            source_divergence=release.source_divergence(),
            deployment_verification=verification.as_dict(),
            receipt_chains={k: v.as_dict() for k, v in chains.items()},
            admission=admission, unverified=unverified,
            classification=release.classification)
    except ex.ExportError as exc:
        record("export", "FAIL", {"code": exc.code}, [exc.message])
        return stop()
    detail: Dict[str, Any] = {"classification": exported.document["classification"],
                              "export_root": exported.root(),
                              "unverified_count": len(exported.unverified)}
    if export_path:
        exported.write(export_path)
        detail["written_to"] = export_path
    record("export", "PASS", detail)
    report = RunReport(ok=True, steps=steps, unverified=unverified, export=exported)
    return report


def _select(transitions: Sequence[jn.JoinedTransition], *, epoch: Optional[int],
            transition_index: Optional[int]) -> Optional[jn.JoinedTransition]:
    """Pick the transition to verify. With no selector, the LAST one — the current head."""
    candidates = list(transitions)
    if epoch is not None:
        candidates = [t for t in candidates if t.advance.epoch == int(epoch)]
    if transition_index is not None:
        candidates = [t for t in candidates
                      if t.advance.transition_index == int(transition_index)]
    return candidates[-1] if candidates else None


def _admit(selected: jn.JoinedTransition, law: hl.EpochLaw, store: pub.ContentStore, *,
           allow_test_doubles: bool) -> Tuple[Optional[Mapping[str, Any]], Dict[str, Any]]:
    """Step 5, over a PROJECTION whose every field is the confirmed event's or hashes to one.

    The projection is what makes this safe. ``replay_advance`` takes the memory lane's
    :class:`dispatch.FrontierAdvanced`, and the fields it needs that the rig advance does not
    carry — ``composition_root``, ``benchmark_law_root``, ``runtime_abi_root`` — are read from the
    fetched eval artifact. That artifact was fetched BY the hash the confirmed advance names and
    re-hashed on arrival, so those values are the chain's transitively; nothing the artifact
    merely asserts about itself is promoted here.
    """
    try:
        artifact = pub.fetch_json(selected.advance.eval_report_hash,
                                  hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.PublicationError as exc:
        return None, {"outcome": "BACKLOG", "code": "missing_artifact",
                      "reason": f"the eval artifact {selected.advance.eval_report_hash} could not "
                                f"be fetched and re-hashed: {exc}"}
    front = artifact.get("frontier") if isinstance(artifact, Mapping) else None
    if not isinstance(front, Mapping):
        return artifact, {"outcome": "FAIL", "code": "MALFORMED_ARTIFACT",
                          "reason": "the eval artifact carries no frontier block"}
    for name, artifact_value, event_value in (
            ("parent_state_root", front.get("parent_frontier_root"),
             selected.advance.parent_state_root),
            ("new_state_root", front.get("new_frontier_root"), selected.advance.new_state_root)):
        if artifact_value != event_value:
            return artifact, {
                "outcome": "FAIL", "code": "ARTIFACT_SUBSTITUTION",
                "reason": f"the fetched artifact says {name}={artifact_value!r}, the confirmed "
                          f"advance says {event_value!r}"}

    # Resolve the two frontier law pins from the separately content-addressed epoch context, not
    # from the eval or transition artifact. The root is independently recovered from the
    # verifier's confirmed context event by ``historical_law``; bytes at that root are then fetched,
    # rehashed, canonicalized and closed-schema validated before they can authorize adoption.
    if selected.advance.epoch_context_root != law.epoch_context_root:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_EPOCH_CONTEXT_MISMATCH,
            "reason": (f"the advance carries epochContextRoot "
                       f"{selected.advance.epoch_context_root}, but the independently recovered "
                       f"epoch law pins {law.epoch_context_root}")}
    try:
        epoch_context_bytes = pub.read_back(
            law.epoch_context_root,
            hash_rule=pub.HASH_RULE_FRONTIER_JSON,
            store=store)
    except pub.ObjectNotFoundError as exc:
        return artifact, {
            "outcome": "BACKLOG", "code": rig.EPOCH_CONTEXT_UNAVAILABLE,
            "reason": (f"the epoch-context manifest {law.epoch_context_root} is not served: "
                       f"{exc}. No artifact field may substitute for independently verified "
                       "epoch pins")}
    except (pub.ReadBackMismatchError, pub.StoreIntegrityError, pub.HashRuleError) as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.EPOCH_CONTEXT_ADDRESS_MISMATCH,
            "reason": (f"the bytes served for epoch-context root {law.epoch_context_root} are "
                       f"substituted or non-canonical: {exc}")}
    except pub.PublicationError as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.EPOCH_CONTEXT_MALFORMED,
            "reason": f"fetching the epoch context failed in an unclassified way: {exc}"}
    try:
        epoch_context = rig.verify_epoch_context_bytes(
            epoch_context_bytes, expected_root=law.epoch_context_root)
    except rig.EpochContextError as exc:
        return artifact, {"outcome": "FAIL", "code": exc.code, "reason": str(exc)}
    if epoch_context["epoch"] != selected.advance.epoch:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_EPOCH_CONTEXT_MISMATCH,
            "reason": (f"the verified epoch context is for epoch {epoch_context['epoch']}, the "
                       f"advance is for epoch {selected.advance.epoch}")}
    epoch_pins = {
        "epoch": epoch_context["epoch"],
        "epoch_context_root": law.epoch_context_root,
        "benchmark_law_root": epoch_context["benchmark_law_root"],
        "runtime_abi_root": epoch_context["runtime_abi_root"],
    }

    # ── THE EDIT: coretex.transition-descriptor/v3 — a commitment, not the edit ────────────────
    #
    # The rig lane's `compactPatchBytes` is now a FIXED 97-byte commitment (version,
    # patchArtifactHash, parentStateRoot, newStateRoot), never JSON, never a
    # variable-length word-diff struct. It does not carry the edit; it addresses it. So step 5 is
    # now three steps: decode the descriptor and cross-check it against the confirmed receipt,
    # FETCH the canonical patch artifact it addresses (by `patchArtifactHash`, sha256, separate
    # from the eval artifact above), and only then take the memory-lane transition the
    # deterministic replay needs from what was fetched. This is the §6.3 fail-closed availability
    # rule applied off chain: an artifact nobody can fetch and rehash never reaches replay.
    try:
        descriptor = rig.decode_transition_descriptor(
            selected.advance.compact_patch_bytes,
            parent_state_root=selected.advance.parent_state_root,
            new_state_root=selected.advance.new_state_root,
            expected_patch_hash=selected.advance.patch_hash,
            transition_format_version=selected.advance.transition_format_version)
    except rig.TransitionDescriptorError as exc:
        return artifact, {"outcome": "FAIL", "code": exc.code, "reason": str(exc)}

    # ── §6.3 "REFUSE, DO NOT DEGRADE" — three outcomes, not one ───────────────────────────────
    #
    # `read_back` recomputes the root and, under HASH_RULE_FRONTIER_JSON, parses and re-serialises
    # the served bytes and refuses non-canonical bytes. The EXACT served bytes then reach
    # `verify_transition_artifact_bytes`; the validator never verifies a re-encoded in-memory
    # document in place of what the publication surface actually returned. The failures it can
    # raise are three MATERIALLY DIFFERENT facts, and a single `except pub.PublicationError`
    # collapsed all of them into "could not be fetched" -> BACKLOG, i.e. TRY AGAIN LATER:
    #
    #   * ObjectNotFoundError   — the publication surface serves nothing at this address.
    #     Availability genuinely failed and a later retry can genuinely succeed, so BACKLOG is the
    #     honest outcome and the ONLY one of the three that is.
    #   * ReadBackMismatchError — the store served bytes that do NOT re-hash to the committed
    #     address: a SUBSTITUTED artifact. Retrying cannot make that right, and reporting it as an
    #     outage is the exact opposite of §5.4's "disagreeing with the descriptor's newStateRoot is
    #     a PUBLICLY PROVABLE refutation".
    #   * HashRuleError         — the bytes at the address are not a canonical serialisation under
    #     the repo's one canonical-JSON law. Also permanent, also a refutation.
    #
    # A publisher serving the wrong bytes at the committed address MUST NOT be indistinguishable,
    # to this pipeline, from a publisher that is temporarily down. The subclasses are listed
    # BEFORE the base class so Python's first-match-wins ordering cannot swallow them, and the
    # residual `PublicationError` FAILS rather than backlogs: an unclassified publication failure
    # is not evidence of availability.
    try:
        patch_artifact_bytes = pub.read_back(
            descriptor.patch_artifact_hash,
            hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        return artifact, {
            "outcome": "BACKLOG", "code": rig.TRANSITION_ARTIFACT_UNAVAILABLE,
            "reason": (f"the canonical patch artifact {descriptor.patch_artifact_hash} is not "
                       f"served by this publication surface: {exc}. The descriptor is "
                       "structurally valid; what is missing is the off-chain edit it addresses, "
                       "and an artifact that is merely UNAVAILABLE may become available")}
    except (pub.ReadBackMismatchError, pub.StoreIntegrityError) as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_ARTIFACT_ADDRESS_MISMATCH,
            "reason": (f"the store served bytes at {descriptor.patch_artifact_hash} that do not "
                       f"re-hash to that address: {exc}. This is a SUBSTITUTED artifact, not an "
                       "outage — it is a publicly provable refutation of the advance and must "
                       "never sit in a backlog waiting for a retry that cannot help")}
    except pub.HashRuleError as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_ARTIFACT_NOT_CANONICAL,
            "reason": (f"the bytes published at {descriptor.patch_artifact_hash} are not a "
                       f"canonical serialisation under the repo's canonical-JSON law: {exc}. A "
                       "content address names ONE byte string; a document that does not "
                       "re-serialise to it was never addressable and cannot become so")}
    except pub.PublicationError as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_ARTIFACT_MALFORMED,
            "reason": (f"fetching the canonical patch artifact {descriptor.patch_artifact_hash} "
                       f"failed in a way this pipeline does not classify: {exc}. Refused rather "
                       "than backlogged — an unclassified publication failure is not evidence "
                       "that the artifact is merely unavailable")}

    try:
        patch_artifact = rig.verify_transition_artifact_bytes(
            patch_artifact_bytes, descriptor=descriptor,
            score_delta_ppm=(int(selected.receipt["scoreAfterPpm"])
                             - int(selected.receipt["scoreBeforePpm"])),
            epoch_context_root_=selected.advance.epoch_context_root)
    except rig.TransitionArtifactError as exc:
        return artifact, {"outcome": "FAIL", "code": exc.code, "reason": str(exc)}

    # The full generalized artifact replays from the exact parent manifest addressed by the
    # confirmed event. This is where stale per-profile priors, dependency closure, law-pin moves
    # and resulting-root disagreement are evaluated; none may degrade to a one-profile projection.
    try:
        parent_manifest = pub.fetch_json(
            selected.advance.parent_state_root,
            hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        return artifact, {
            "outcome": "BACKLOG", "code": rig.TRANSITION_ARTIFACT_UNAVAILABLE,
            "reason": (f"the parent manifest {selected.advance.parent_state_root} is not served "
                       f"by this publication surface: {exc}. Full transition-artifact replay "
                       "cannot run without the exact parent state")}
    except (pub.ReadBackMismatchError, pub.StoreIntegrityError) as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_ARTIFACT_ADDRESS_MISMATCH,
            "reason": (f"the store served substituted bytes for parent manifest "
                       f"{selected.advance.parent_state_root}: {exc}")}
    except pub.HashRuleError as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_ARTIFACT_NOT_CANONICAL,
            "reason": (f"the parent manifest {selected.advance.parent_state_root} is not "
                       f"canonical JSON: {exc}")}
    except pub.PublicationError as exc:
        return artifact, {
            "outcome": "FAIL", "code": rig.TRANSITION_ARTIFACT_MALFORMED,
            "reason": (f"fetching parent manifest {selected.advance.parent_state_root} failed "
                       f"in an unclassified way: {exc}")}
    try:
        rig.replay_transition_artifact(
            parent_manifest, patch_artifact, epoch_pins=epoch_pins)
    except rig.TransitionArtifactError as exc:
        return artifact, {"outcome": "FAIL", "code": exc.code, "reason": str(exc)}

    # The eval artifact and transition artifact are distinct commitments. The receipt signs the
    # release the evaluator scored; it must equal `candidate.release_root` and, whenever the
    # generalized transition moves releases, be one of those moved roots. Composition-only moves
    # legitimately have an empty release-root set and bind through the composition root below.
    candidate = artifact.get("candidate") if isinstance(artifact, Mapping) else None
    if not isinstance(candidate, Mapping):
        return artifact, {"outcome": "FAIL", "code": "MALFORMED_ARTIFACT",
                          "reason": "the eval artifact carries no candidate block"}
    artifact_hash = str(selected.receipt["artifactHash"]).lower().replace("0x", "")
    candidate_release = str(candidate.get("release_root", "")).lower().replace("0x", "")
    if candidate_release != artifact_hash:
        return artifact, {
            "outcome": "FAIL", "code": "RIG_ARTIFACT_HASH_SUBSTITUTION",
            "reason": (f"the eval artifact scored candidate.release_root "
                       f"{candidate_release!r}, not the signed artifactHash {artifact_hash}")}

    releases = patch_artifact.get("profile_releases") or {}
    release_roots = tuple(
        releases[profile_id]["new_release_root"]
        for profile_id in fr.PROFILE_IDS if profile_id in releases)
    if release_roots and candidate_release not in release_roots:
        return artifact, {
            "outcome": "FAIL", "code": "RIG_ARTIFACT_HASH_SUBSTITUTION",
            "reason": (f"the eval artifact scored release root {candidate_release!r}, but the "
                       f"confirmed transition artifact moves {list(release_roots)}")}

    resulting_composition = patch_artifact["resulting_composition_root"]
    if front.get("composition_root") != resulting_composition:
        return artifact, {
            "outcome": "FAIL", "code": "RIG_COMPOSITION_ROOT_SUBSTITUTION",
            "reason": (f"the eval artifact says composition_root="
                       f"{front.get('composition_root')!r}, the confirmed transition artifact "
                       f"resolves to {resulting_composition!r}")}

    # A reproducible frontier root is not yet an installable state. Follow the complete one-shape
    # schema-v4 graph now: composition, all three profile manifests, and the direct module bytes
    # each one binds. The target profile's composition binding must name the exact candidate code
    # the evaluator scored. Missing bytes are retryable publication backlog; malformed,
    # substituted, schema-v3, wrapper-2, or split miner/adapter bytes are a permanent refusal.
    resulting_manifest = patch_artifact.get("resulting_frontier_manifest")
    if not isinstance(resulting_manifest, Mapping):
        return artifact, {
            "outcome": "FAIL", "code": "RELEASE_STATE_INVALID",
            "reason": "the transition artifact carries no resulting frontier manifest"}
    target_profile = str(candidate.get("target_profile", ""))
    candidate_hash = candidate.get("candidate_hash")
    expected_candidates = ({target_profile: candidate_hash}
                           if target_profile in fr.PROFILE_IDS
                           and isinstance(candidate_hash, str) else {})
    try:
        materialized = rg.verify_materializable_release_state(
            releases=resulting_manifest.get("profiles", {}),
            composition_root=resulting_composition,
            expected_candidate_hashes=expected_candidates,
            store=store)
    except pub.ObjectNotFoundError as exc:
        return artifact, {
            "outcome": "BACKLOG", "code": "RELEASE_STATE_UNAVAILABLE",
            "reason": f"resulting schema-v4 release graph is not fully published: {exc}"}
    except (pub.PublicationError, rg.ReleaseGraphError, fr.FrontierError) as exc:
        return artifact, {
            "outcome": "FAIL", "code": "RELEASE_STATE_INVALID", "reason": str(exc)}

    # Existing deterministic evaluator replay consumes the evaluator's one-profile projection.
    # That projection is safe only after the generalized transition above has replayed in full and
    # the two artifacts have been explicitly joined by release and composition roots.
    try:
        transition_bytes = fr.canonical_bytes(front["transition"])
    except (KeyError, TypeError, fr.FrontierError) as exc:
        return artifact, {
            "outcome": "FAIL", "code": "MALFORMED_ARTIFACT",
            "reason": f"the eval artifact's frontier.transition is unusable: {exc}"}

    projected = dp.FrontierAdvanced(
        epoch=selected.advance.epoch,
        transition_index=selected.advance.transition_index,
        miner=selected.advance.miner,
        parent_frontier_root=selected.advance.parent_state_root,
        new_frontier_root=selected.advance.new_state_root,
        candidate_release_root=str(selected.receipt["artifactHash"]),
        composition_root=str(front.get("composition_root")),
        eval_report_hash=selected.advance.eval_report_hash,
        benchmark_law_root=str(front.get("benchmark_law_root")),
        runtime_abi_root=str(front.get("runtime_abi_root")),
        transition_bytes=transition_bytes,
        provenance=selected.advance.provenance)
    pins = dp.pins_from_mapping({selected.advance.epoch: dp.EpochPins(
        epoch=selected.advance.epoch,
        runtime_abi_root=str(epoch_context["runtime_abi_root"]),
        benchmark_law_root=str(epoch_context["benchmark_law_root"]),
        counter_resource_law_root=str(epoch_context["counter_resource_law_root"]),
        entropy_commitment=law.entropy_commitment,
        revealed_secret=law.revealed_secret)})
    # WIRE THE REAL ADMISSION WHEN THE TREES ARE THERE, and say so when they are not.
    #
    # `replay_advance` defaults both of these to ABSENT, which yields a BACKLOG at their stages —
    # the honest outcome for a host that cannot run them. Now that the six code trees are
    # published, a host that has configured them can run the pinned networkless sandbox and the
    # real G6b screen, and this is where that happens. Neither is defaulted ON: an operator opts
    # in by pointing at the trees, so "the admission ran" is always traceable to a decision.
    sandbox = rp.default_sandbox()
    screen = rp.default_oracle_screen()
    admission_trees = {"benchmark_v2_dir": sandbox.bench_v2_dir,
                       "coretex_memory_dir": sandbox.coretex_dir,
                       "sandbox_available": sandbox.available(),
                       "screen_available": screen.available()}
    result = rp.replay_advance(projected, store=store, pins=pins,
                               sandbox=sandbox if sandbox.available() else None,
                               screen=screen if screen.available() else None,
                               allow_test_doubles=allow_test_doubles)
    # OMIT, NEVER null: `code` is None on a PASS and `stage` may be absent. Fixed at source as
    # well as swept at the export boundary — the guard exists so a miss is cheap, not so misses
    # are acceptable.
    report: Dict[str, Any] = {"outcome": str(result.outcome), "reason": result.reason,
                              "checks": list(result.checks),
                              "transition_descriptor": descriptor.as_dict(),
                              "materialized_release_profiles": sorted(
                                  materialized["releases"]),
                              "admission_trees": admission_trees}
    if result.code is not None:
        report["code"] = result.code
    if getattr(result, "stage", None) is not None:
        report["stage"] = result.stage
    return artifact, report
