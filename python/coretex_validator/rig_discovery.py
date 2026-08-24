# SPDX-License-Identifier: Apache-2.0
"""Live-lane discovery for ``replay-latest`` / ``replay-advance``: ONE decoding authority.

WHY THIS MODULE EXISTS
======================
``replay-latest --rpc https://mainnet.base.org`` used to scan the entire production history — 600k
blocks, 200,885 logs from the three addresses the canonical release itself pins — and report
``events: 0``, ``selected: null``, exit 2, "the feed carries no confirmed advance". The chain was
at epoch 185 and the cutover was epoch 171, so fourteen epochs of confirmed advances sat inside
that range, including the one at block 50357019 the run's own window covered.

Nothing was wrong with the window, the addresses or the confirmation depth. Discovery ran through
``sync.sync_logs`` -> ``dispatch.decode``, and ``dispatch`` knows two event tables, NEITHER of
which a deployed contract emits:

* ``V5_TOPICS`` — the ``CoreTexMemory*`` memory-frontier lane, which the coordinator's own kit
  manifest publishes under ``retired_reference_do_not_build_against``;
* ``PROTOCOL_RIG`` / ``RIG_STATE_ADVANCED_TOPIC0`` (``7ae8ca47…``) — the STAGED rig set, about
  which :mod:`rig_events` says, in its first paragraph, "**No deployed contract emits any of
  them.**"

The live registry emits ``CoreTexStateAdvanced(uint64,uint64,address,bytes32 x6,uint256,uint16,
bytes)`` -> topic0 ``f2b42259…``. ``sync_logs``'s fail-soft "an unknown topic must never brick a
field validator" policy — correct in isolation — then turned a TOTAL LANE MISMATCH into a silent
empty feed, which reads exactly like an idle deployment. ``reproduce`` was unaffected the whole
time, because its scan goes through :mod:`rig_events`.

THE DESIGN DECISION: ONE LIVE DECODING AUTHORITY, AND IT IS :mod:`rig_events`
============================================================================
The alternative was to repair ``dispatch``'s rig table to the live signatures. That was rejected:
it would have produced a SECOND live decoder for the same three contracts, and the day the two
disagreed about a malformed log only one of them would be right — which is the exact argument
:mod:`rig_events` already makes for delegating its word/topic readers to :mod:`dispatch` instead
of reimplementing them.

So :mod:`rig_events` decodes, here as in ``reproduce``. This module adds only what a decoder does
not own: confirmation depth, chain ordering, per-epoch contiguity, and the projection into the
:class:`dispatch.FrontierAdvanced` shape :func:`replay.replay_advance` consumes. :mod:`sync` and
``dispatch``'s tables stay exactly where they are — as the retired lane's decoders, exercised by
the regression fixtures that document what the pre-rig protocol looked like — and no live command
consults them for discovery any more.

THE PROJECTION, AND WHAT IT DOES **NOT** CLAIM
==============================================
``replay_advance`` consumes the memory lane's event shape. Three of its fields — ``composition_root``,
``benchmark_law_root``, ``runtime_abi_root`` — are not on the rig advance, and one,
``candidate_release_root``, is on the rig lane only inside the signed receipt carried in the
transaction's CALLDATA. :func:`project_advance` reads the first three out of the eval artifact
FETCHED BY THE HASH THE CONFIRMED ADVANCE NAMES and re-hashed on arrival, which is exactly the
argument ``pipeline._admit`` makes for the same projection: those values are the chain's
transitively, and nothing the artifact merely asserts about itself is promoted.

``candidate_release_root`` is the honest gap. ``reproduce`` joins the advance to the signed
receipt from calldata and refuses unless ``candidate.release_root`` equals the signed
``artifactHash``; that join needs an archive RPC and a transaction fetch per advance, which is
``reproduce``'s job and not this command's. Here the value comes from the artifact and is
cross-checked against the artifact's own ``frontier.transition.new_release_root``, and the report
says so under ``binding`` rather than implying a check that did not run.
"""
from __future__ import annotations

from collections import abc
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import dispatch as dp
from . import frontier as fr
from . import historical_law as hl
from . import publication as pub
from . import rig_events as rig
from . import sync as sy

#: Named in every report this module produces, so "which decoder saw the chain" is never a
#: question an operator has to answer by reading source.
LIVE_DECODER = "coretex_validator.rig_events"
DECODER_NOTE = (
    f"{LIVE_DECODER} — the descriptor-v3 events the deployed registry/mining/verifier actually "
    "emit, the same decoding `reproduce` uses. `dispatch`/`sync` carry the retired memory-lane "
    "and staged-rig tables and are not consulted for live discovery")

#: What this command checks, and what it deliberately leaves to ``reproduce``. Emitted verbatim.
BINDING_NOTE = {
    "chain_bound": ("epoch, transitionIndex, miner, parentStateRoot, newStateRoot, "
                    "evalReportHash and epochContextRoot come from the confirmed log; the eval "
                    "artifact is fetched BY evalReportHash and re-hashed, so the fields taken "
                    "from it are the chain's transitively"),
    "not_checked_here": ("the signed rig receipt in the transaction calldata is not fetched, so "
                         "`candidate_release_root` is the artifact's rather than the signed "
                         "`artifactHash`. `coretex-validator reproduce` performs that join"),
}


class ProjectionError(Exception):
    """A rig advance that cannot be turned into a replayable event.

    ``outcome`` is the vocabulary the caller must preserve: ``BACKLOG`` means "I found the advance
    and could not check it", ``FAIL`` means the confirmed event and the published bytes disagree.
    Collapsing the two is the reporting fault D-3/D-4 flagged elsewhere in this client, and it is
    kept apart here at the point the distinction is actually known.
    """

    def __init__(self, message: str, *, code: str, outcome: str, stage: str = "projection") -> None:
        super().__init__(message)
        self.code = code
        self.outcome = outcome
        self.stage = stage


# --------------------------------------------------------------------------- #
# 1. confirmation, ordering, selection
# --------------------------------------------------------------------------- #
def _key(advance: rig.StateAdvanced) -> Tuple[int, int]:
    return (advance.epoch, advance.transition_index)


def _same_payload(a: rig.StateAdvanced, b: rig.StateAdvanced) -> bool:
    return (a.miner == b.miner and a.parent_state_root == b.parent_state_root
            and a.new_state_root == b.new_state_root and a.patch_hash == b.patch_hash
            and a.eval_report_hash == b.eval_report_hash
            and a.core_version_hash == b.core_version_hash
            and a.epoch_context_root == b.epoch_context_root
            and a.compact_patch_bytes == b.compact_patch_bytes)


@dataclass
class RigFeed:
    """One discovery pass over the LIVE lane. Every count in :meth:`summary` is a fact, not a
    default: an unknown administrative topic is ``ignored`` (a new event must never brick a field
    validator), a log that names one of our events but is malformed is ``undecodable``, and an
    advance above the confirmed head is ``pending`` — "not yet", never "does not exist"."""

    decoded: rig.DecodedLogs
    advances: List[rig.StateAdvanced] = field(default_factory=list)
    pending: List[rig.StateAdvanced] = field(default_factory=list)
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    gaps: List[sy.Gap] = field(default_factory=list)
    anomalies: List[sy.Anomaly] = field(default_factory=list)
    undecodable: List[Dict[str, Any]] = field(default_factory=list)
    confirmed_head: Optional[int] = None

    @property
    def contiguous(self) -> bool:
        return not self.gaps and not self.conflicts

    @property
    def epochs(self) -> Tuple[int, ...]:
        return tuple(sorted({a.epoch for a in self.advances}))

    def newest(self) -> Optional[rig.StateAdvanced]:
        """THE ONE DECISION: the chain's order, last element. Never the feed's order.

        ``transitionIndex`` restarts at 0 every epoch, so the last log in a block-ordered feed is
        routinely not the head advance.
        """
        return self.advances[-1] if self.advances else None

    def credit_for(self, advance: rig.StateAdvanced) -> Optional[rig.CoreTexCreditAccepted]:
        """The CoreTex credit minted in the SAME transaction. Matched on transaction hash — the
        mining contract calls the verifier and emits inside one call."""
        tx = advance.provenance.transaction_hash
        if tx is None:
            return None
        for credit in self.decoded.coretex_credits:
            if credit.provenance.transaction_hash == tx:
                return credit
        return None

    def summary(self) -> Dict[str, Any]:
        return {
            "decoder": DECODER_NOTE,
            "confirmed_head": self.confirmed_head,
            # `events` is kept as the documented name for "confirmed advances in this feed", so a
            # caller reading `feed.events` sees the number it always meant to see.
            "events": len(self.advances),
            "advances": len(self.advances),
            "pending": len(self.pending),
            "epochs": list(self.epochs),
            "contiguous": self.contiguous,
            "gaps": [g.as_dict() for g in self.gaps],
            "conflicts": len(self.conflicts),
            "duplicates": len(self.duplicates),
            "ignored": self.decoded.ignored,
            "undecodable": len(self.undecodable),
            "anomalies": [a.as_dict() for a in self.anomalies],
            "contexts": len(self.decoded.contexts),
            "commits": len(self.decoded.commits),
            "reveals": len(self.decoded.reveals),
            "finalizations": len(self.decoded.finalizations),
            "coretex_credits": len(self.decoded.coretex_credits),
            "standard_credits": len(self.decoded.standard_credits),
            "policies": len(self.decoded.policies),
        }


def sync_rig_logs(logs: Iterable[Mapping[str, Any]], *, deployment: rig.RigDeployment,
                  latest_block: Optional[int] = None,
                  confirmation_depth: int = sy.DEFAULT_CONFIRMATION_DEPTH,
                  start_index: Optional[Mapping[int, int]] = None) -> RigFeed:
    """Decode, confirm, order and check one batch of logs against the LIVE lane. Pure: no I/O.

    ``latest_block=None`` means the caller already applied its own confirmation policy (an archive
    dump, a fixture); every decoded advance is then treated as confirmed and ``confirmed_head`` is
    reported as ``None`` so the two situations stay distinguishable.
    """
    head = None if latest_block is None else sy.confirmed_head(latest_block, confirmation_depth)
    undecodable: List[Dict[str, Any]] = []
    kept: List[Mapping[str, Any]] = []
    for log in logs:
        try:
            rig.decode(log, deployment)
        except (dp.DispatchError, rig.RigEventError) as exc:
            undecodable.append({"reason": str(exc),
                                "topic0": (log.get("topics") or [None])[0],
                                "address": log.get("address")})
            continue
        kept.append(log)
    decoded = rig.scan(kept, deployment)

    confirmed: List[rig.StateAdvanced] = []
    pending: List[rig.StateAdvanced] = []
    for advance in decoded.advances:
        block = advance.provenance.block_number
        if head is not None and (block is None or block > head):
            pending.append(advance)
        else:
            confirmed.append(advance)

    ordered = sorted(confirmed, key=lambda a: (a.epoch, a.transition_index,
                                               a.provenance.position))
    unique: List[rig.StateAdvanced] = []
    duplicates: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    seen: Dict[Tuple[int, int], rig.StateAdvanced] = {}
    for advance in ordered:
        prior = seen.get(_key(advance))
        if prior is None:
            seen[_key(advance)] = advance
            unique.append(advance)
        elif _same_payload(prior, advance):
            duplicates.append({"epoch": advance.epoch,
                               "transition_index": advance.transition_index,
                               "detail": "identical payload observed twice in the feed"})
        else:
            conflicts.append({
                "epoch": advance.epoch, "transition_index": advance.transition_index,
                "detail": "two DIFFERENT payloads claim one (epoch, transitionIndex); exactly one "
                          "can be canonical and this layer will not choose"})
    if conflicts:
        conflicted = {(c["epoch"], c["transition_index"]) for c in conflicts}
        unique = [a for a in unique if _key(a) not in conflicted]

    gaps = _contiguity(unique, start_index=start_index)
    anomalies = [sy.Anomaly(code="reorg_removed_log", epoch=a.epoch,
                            detail=f"epoch {a.epoch} index {a.transition_index} is flagged "
                                   "removed=true by the feed; it was reorged out and must not be "
                                   "replayed")
                 for a in unique if a.provenance.removed]
    anomalies += [sy.Anomaly(code="conflicting_transition_index", epoch=c["epoch"],
                             detail=c["detail"]) for c in conflicts]
    return RigFeed(decoded=decoded, advances=unique, pending=sorted(
        pending, key=lambda a: (a.epoch, a.transition_index)), duplicates=duplicates,
        conflicts=conflicts, gaps=gaps, anomalies=anomalies, undecodable=undecodable,
        confirmed_head=head)


def _contiguity(advances: Sequence[rig.StateAdvanced], *,
                start_index: Optional[Mapping[int, int]] = None) -> List[sy.Gap]:
    """Per-EPOCH index continuity — ``transitionCount`` is a per-epoch counter, so a global
    expectation silently interleaves epochs."""
    start_index = dict(start_index or {})
    gaps: List[sy.Gap] = []
    expected: Dict[int, int] = {}
    for advance in advances:
        want = expected.get(advance.epoch, start_index.get(advance.epoch, 0))
        if advance.transition_index > want:
            gaps.append(sy.Gap(epoch=advance.epoch, missing_from=want,
                               missing_to=advance.transition_index - 1))
        elif advance.transition_index < want:
            gaps.append(sy.Gap(epoch=advance.epoch, missing_from=advance.transition_index,
                               missing_to=advance.transition_index))
        expected[advance.epoch] = advance.transition_index + 1
    return gaps


# --------------------------------------------------------------------------- #
# 2. the projection into the replayable event shape
# --------------------------------------------------------------------------- #
def _fetch_artifact(root: str, *, store: pub.ContentStore) -> Mapping[str, Any]:
    try:
        return pub.fetch_json(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.PublicationUnavailableError as exc:
        raise ProjectionError(
            f"the eval artifact {root} is not served by this publication surface: {exc}. The "
            "advance was found and identified; what is missing is the off-chain evidence it "
            "addresses, and an artifact that is merely UNAVAILABLE may become available",
            code="missing_artifact", outcome="BACKLOG", stage="artifact") from exc
    except (pub.ReadBackMismatchError, pub.StoreIntegrityError) as exc:
        raise ProjectionError(
            f"the store served bytes at {root} that do not re-hash to that address: {exc}. This "
            "is a SUBSTITUTED artifact, not an outage",
            code="artifact_address_mismatch", outcome="FAIL", stage="artifact") from exc
    except pub.PublicationError as exc:
        raise ProjectionError(f"fetching the eval artifact {root} failed: {exc}",
                              code="artifact_corrupt", outcome="FAIL", stage="artifact") from exc


def project_advance(advance: rig.StateAdvanced, *,
                    store: pub.ContentStore) -> Tuple[dp.FrontierAdvanced, Dict[str, Any]]:
    """Project ONE confirmed rig advance into the shape :func:`replay.replay_advance` consumes.

    See the module docstring for what this projection is entitled to claim. Every value either
    comes from the confirmed log or from bytes fetched by an address the confirmed log names.
    """
    artifact = _fetch_artifact(advance.eval_report_hash, store=store)
    front = artifact.get("frontier") if isinstance(artifact, abc.Mapping) else None
    if not isinstance(front, abc.Mapping):
        raise ProjectionError("the eval artifact carries no frontier block",
                              code="malformed_artifact", outcome="FAIL", stage="artifact")
    for name, from_artifact, from_event in (
            ("parent_frontier_root", front.get("parent_frontier_root"),
             advance.parent_state_root),
            ("new_frontier_root", front.get("new_frontier_root"), advance.new_state_root)):
        if from_artifact != from_event:
            raise ProjectionError(
                f"the fetched artifact says {name}={from_artifact!r}, the confirmed advance says "
                f"{from_event!r}", code="artifact_substitution", outcome="FAIL", stage="artifact")

    candidate = artifact.get("candidate")
    if not isinstance(candidate, abc.Mapping):
        raise ProjectionError("the eval artifact carries no candidate block",
                              code="malformed_artifact", outcome="FAIL", stage="artifact")
    transition = front.get("transition")
    if not isinstance(transition, abc.Mapping):
        raise ProjectionError("the eval artifact carries no frontier.transition",
                              code="malformed_artifact", outcome="FAIL", stage="artifact")
    release_root = str(candidate.get("release_root", ""))
    if release_root != transition.get("new_release_root"):
        raise ProjectionError(
            f"the eval artifact scored release root {release_root!r} but its own transition "
            f"advances to {transition.get('new_release_root')!r}",
            code="artifact_release_root_disagrees", outcome="FAIL", stage="artifact")
    try:
        transition_bytes = fr.canonical_bytes(transition)
    except (TypeError, fr.FrontierError) as exc:
        raise ProjectionError(f"the eval artifact's frontier.transition is unusable: {exc}",
                              code="malformed_artifact", outcome="FAIL",
                              stage="artifact") from exc

    projected = dp.FrontierAdvanced(
        epoch=advance.epoch,
        transition_index=advance.transition_index,
        miner=advance.miner,
        parent_frontier_root=advance.parent_state_root,
        new_frontier_root=advance.new_state_root,
        candidate_release_root=release_root,
        composition_root=str(front.get("composition_root")),
        eval_report_hash=advance.eval_report_hash,
        benchmark_law_root=str(front.get("benchmark_law_root")),
        runtime_abi_root=str(front.get("runtime_abi_root")),
        transition_bytes=transition_bytes,
        provenance=advance.provenance)
    provenance = {
        "decoder": LIVE_DECODER,
        "eval_artifact_root": advance.eval_report_hash,
        "eval_artifact_hash_rule": pub.HASH_RULE_FRONTIER_JSON,
        "from_confirmed_log": ["epoch", "transition_index", "miner", "parent_frontier_root",
                               "new_frontier_root", "eval_report_hash", "epoch_context_root"],
        "from_rehashed_artifact": ["composition_root", "benchmark_law_root", "runtime_abi_root",
                                   "candidate_release_root", "transition_bytes"],
        "binding": dict(BINDING_NOTE),
    }
    return projected, provenance


def pins_for(advance: rig.StateAdvanced, *, feed: RigFeed,
             store: pub.ContentStore) -> Tuple[dp.PinResolver, Dict[str, Any]]:
    """The epoch's law pins, recovered INDEPENDENTLY of the advance's own claim.

    The three law roots live in the epoch-context MANIFEST, which is separately content-addressed.
    Its root is recovered from the VERIFIER's confirmed ``CoreTexEpochContextSet`` — not from the
    advance and not from the eval artifact — and only then is the advance's ``epochContextRoot``
    compared against it. A validator that took the root from the advance would be checking the
    advance against itself.

    A feed window that does not carry the epoch's own context event cannot recover them, and that
    is a BACKLOG: the pins are unknown, not absent.
    """
    try:
        law = hl.law_for_epoch(feed.decoded, advance.epoch)
    except hl.LawError as exc:
        raise ProjectionError(
            f"{exc.message} (epoch {advance.epoch})", code="epoch_law_unavailable",
            outcome="BACKLOG", stage="epoch_law") from exc
    if advance.epoch_context_root != law.epoch_context_root:
        raise ProjectionError(
            f"the advance carries epochContextRoot {advance.epoch_context_root}, but the "
            f"independently recovered epoch law pins {law.epoch_context_root}",
            code=rig.TRANSITION_EPOCH_CONTEXT_MISMATCH, outcome="FAIL", stage="epoch_law")
    try:
        raw = pub.read_back(law.epoch_context_root, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                            store=store)
    except pub.PublicationUnavailableError as exc:
        raise ProjectionError(
            f"the epoch-context manifest {law.epoch_context_root} is not served: {exc}. No "
            "artifact field may substitute for independently verified epoch pins",
            code=rig.EPOCH_CONTEXT_UNAVAILABLE, outcome="BACKLOG", stage="epoch_law") from exc
    except (pub.ReadBackMismatchError, pub.StoreIntegrityError, pub.HashRuleError) as exc:
        raise ProjectionError(
            f"the bytes served for epoch-context root {law.epoch_context_root} are substituted "
            f"or non-canonical: {exc}",
            code=rig.EPOCH_CONTEXT_ADDRESS_MISMATCH, outcome="FAIL", stage="epoch_law") from exc
    except pub.PublicationError as exc:
        raise ProjectionError(f"fetching the epoch context failed: {exc}",
                              code=rig.EPOCH_CONTEXT_MALFORMED, outcome="FAIL",
                              stage="epoch_law") from exc
    try:
        context = rig.verify_epoch_context_bytes(raw, expected_root=law.epoch_context_root)
    except rig.EpochContextError as exc:
        raise ProjectionError(str(exc), code=exc.code, outcome="FAIL",
                              stage="epoch_law") from exc
    if context["epoch"] != advance.epoch:
        raise ProjectionError(
            f"the verified epoch context is for epoch {context['epoch']}, the advance is for "
            f"epoch {advance.epoch}", code=rig.TRANSITION_EPOCH_CONTEXT_MISMATCH, outcome="FAIL",
            stage="epoch_law")
    resolver = dp.pins_from_mapping({advance.epoch: dp.EpochPins(
        epoch=advance.epoch,
        runtime_abi_root=str(context["runtime_abi_root"]),
        benchmark_law_root=str(context["benchmark_law_root"]),
        counter_resource_law_root=str(context["counter_resource_law_root"]),
        entropy_commitment=law.entropy_commitment,
        revealed_secret=law.revealed_secret)})
    return resolver, {"epoch_context_root": law.epoch_context_root,
                      "source": "verifier CoreTexEpochContextSet + the addressed context manifest",
                      "entropy_revealed": law.revealed_secret is not None}


def selected_summary(advance: rig.StateAdvanced) -> Dict[str, Any]:
    """What the report names as the advance it worked on. Field names are the public contract."""
    return {
        "epoch": advance.epoch,
        "transition_index": advance.transition_index,
        "miner": advance.miner,
        "parent_frontier_root": advance.parent_state_root,
        "new_frontier_root": advance.new_state_root,
        "eval_report_hash": advance.eval_report_hash,
        "epoch_context_root": advance.epoch_context_root,
        "patch_hash": advance.patch_hash,
        "block_number": advance.provenance.block_number,
        "transaction_hash": advance.provenance.transaction_hash,
    }
