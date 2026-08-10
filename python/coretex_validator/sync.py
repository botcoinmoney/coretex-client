# SPDX-License-Identifier: UNLICENSED
"""Historical pre-rig frontier sync model retained only for regression fixtures.

This module's genesis-inheritance model is not used by the production descriptor-v3 command.
Production continuity is reconstructed from confirmed verifier epoch-context parents by
``rig_events.context_parent_continuity``.

Frontier event SYNC: confirmation depth, ordering, contiguity, gaps (Cut V5-E, §17.236).

Pure functions over SUPPLIED log dicts. There is no RPC client here and no network call anywhere
in the module: a log source is INJECTED (:class:`LogSource`), which is why every property below is
testable offline and why the same code paths run against a local chain, an archive dump, or a
fixture list.

THE FOUR PROPERTIES THIS LAYER OWNS

1. **Confirmation depth.** ``toBlock`` is capped at ``latest - confirmationDepth`` so replay never
   ingests reorg-prone head blocks. The default (15 blocks ≈ 30s on Base's ~2s blocks) and the
   9500-block page size are the canonical V4 validator's, reused rather than re-picked. Logs above
   the confirmed head are not dropped — they are returned as ``pending``, because "not yet
   confirmed" and "does not exist" are different facts.

2. **Ordering.** Advances sort by ``(epoch, transitionIndex)``. That is the CHAIN's order, not the
   log feed's: ``transitionIndex`` restarts at 0 each epoch, so a naive block-order sort silently
   interleaves epochs. Block position is still checked — a feed whose block order disagrees with
   the chain order is recorded as an ANOMALY, since that means a reorg, a duplicated address, or a
   feed that merged two deployments.

3. **Per-epoch contiguity.** ``transitionCount[epoch]`` is a per-epoch counter, so index continuity
   is tracked PER EPOCH (the exact bug the V4 decoder's ``expectedIdxByEpoch`` map fixes). A
   window that starts mid-epoch declares its resume cursor explicitly; it is never inferred from
   the first index observed, because that would make a missing prefix look like a fresh start.

4. **Gaps.** A missing index is REPORTED as a typed :class:`Gap`, never skipped over. A gap does
   not stop the caller from replaying the events it does have — it stops the caller from claiming
   the epoch was fully verified.

DUPLICATES vs CONFLICTS. Two logs with the same ``(epoch, transitionIndex)`` and byte-identical
payloads are a duplicated feed entry (deduplicated, recorded). Two with the same key and DIFFERENT
payloads are a CONFLICT: exactly one can be canonical and this layer cannot tell which, so both
are quarantined and the epoch is marked unsafe to replay. Silently picking the first would let a
feed choose consensus.

5. **Epoch-head inheritance** (operator ruling §17.237). An epoch does not have a head published
   for it; it INHERITS one lazily at its first transition. :func:`derive_epoch_parents` re-derives
   that inheritance from CONFIRMED ADVANCES ALONE, using exactly the contract's rule —

       parent(N) = new_frontier_root of the last transition of the latest epoch M < N that has
                   any confirmed transition, else the deployment's genesis root

   — and :func:`check_inheritance` compares the derivation against the confirmed
   ``CoreTexMemoryEpochInherited`` events. The derivation is authoritative; the event is a
   cross-check, because a validator that took the head from a publisher would not be deriving it
   from history.

   REORG. If the log that ESTABLISHED an epoch's inheritance (its ``transitionIndex == 0``) is
   flagged ``removed``, the inheritance is INVALIDATED and reported —
   ``reorg_invalidated_epoch_inheritance`` — and the epoch is left with NO derived parent. It is
   never silently re-derived from whichever transition survived: index 1 becoming "the first"
   would manufacture a different, unconfirmed epoch head out of a reorg.

SEAM (ledger §17.238)
---------------------
SEAM:            ``packages/coordinator/src/coretex-memory-frontier-lane.ts`` ->
                 ``resolveConfirmedEpochHead``. This module and that function implement the SAME
                 §17.237 rule; wiring means pointing both at one log feed, not merging them.
PORTS:           ``LogSource`` (injected; the only thing that could touch a network),
                 ``DeploymentSet``, and two plain VALUES — ``genesis_frontier_root`` and
                 ``finalizations``. The epoch head is a derived output of those inputs, never a
                 setting: there is deliberately no way to hand this module a head.
MINIMAL DIFF:    supply an RPC-backed ``LogSource`` and the deployment genesis root inside the
                 lane's guarded block — which is an ADD, not an edit:
                 ``resolveCoreTexMemoryLaneEnv`` exists
                 (``coretex-memory-frontier-lane.ts:346``) and returns ``null`` when unarmed, but
                 nothing calls it yet, so model the new block on the cutover triple
                 (``server.ts:6042`` / ``coretex-cutover-adapters.ts:1038`` / ``:994``). The lane
                 is on branch ``prod-recovery-20412b5-storage-fix`` @ 3a7f24e, NOT an ancestor of
                 ``memory-ir-rc`` HEAD: MERGE first (see ``v5/e2e/SEAM-INVENTORY.md``).
REVENDOR NEEDED: NO. The new/changed V5 topic0 literals live in ``v5/validator/dispatch.py``;
                 the canonical decoder filters to its own two topics and ignores the rest.
ARM:             ``CORETEX_MEMORY_LANE_ARM``. Off => this module is never imported by the server.
REMOVE:          delete the guarded block. No table, no migration, no on-disk format.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


from . import frontier as fr

from . import dispatch as dp

#: Reorg shielding, inherited from ``CORETEX_DEFAULT_CONFIRMATION_DEPTH`` (Base ~2s blocks).
DEFAULT_CONFIRMATION_DEPTH = 15
#: Max blocks per log request, inherited from ``CORETEX_DEFAULT_LOG_CHUNK_BLOCKS``.
DEFAULT_CHUNK_BLOCKS = 9500


class SyncError(Exception):
    """Base of every sync-layer failure."""


class WindowError(SyncError):
    """A block window or confirmation depth is not usable."""


class ConflictingEventError(SyncError):
    """Two different payloads claim the same ``(epoch, transitionIndex)``."""


# --------------------------------------------------------------------------- #
# The injectable log source
# --------------------------------------------------------------------------- #
class LogSource:
    """A source of raw log dicts over a block range.

    One method. An implementation may page an ``eth_getLogs`` RPC, read an archive file, or return
    a fixture list; nothing in this module knows or cares. ``topics0`` is the OR-set of topic0
    values to filter on, ``addresses`` the contract filter — both may be ignored by a source that
    already holds a filtered feed, because every consumer re-filters through
    :func:`dispatch.route` anyway.
    """

    def get_logs(self, from_block: int, to_block: int, *, topics0: Sequence[str] = (),
                 addresses: Sequence[str] = ()) -> List[Mapping[str, Any]]:
        raise NotImplementedError


class ListLogSource(LogSource):
    """A source over a fixed list. The reference implementation and the test double."""

    def __init__(self, logs: Iterable[Mapping[str, Any]]) -> None:
        self._logs = [dict(log) for log in logs]
        self.calls: List[Tuple[int, int]] = []

    def get_logs(self, from_block: int, to_block: int, *, topics0: Sequence[str] = (),
                 addresses: Sequence[str] = ()) -> List[Mapping[str, Any]]:
        self.calls.append((from_block, to_block))
        wanted = {t.lower() for t in topics0}
        addrs = {a.lower() for a in addresses}
        out = []
        for log in self._logs:
            block = log.get("blockNumber")
            if isinstance(block, str):
                block = int(block, 16) if block[:2] in ("0x", "0X") else int(block)
            if block is None or not (from_block <= block <= to_block):
                continue
            if addrs and str(log.get("address", "")).lower() not in addrs:
                continue
            if wanted:
                topics = log.get("topics") or []
                if not topics:
                    continue
                topic0 = str(topics[0]).lower().removeprefix("0x")
                if topic0 not in wanted:
                    continue
            out.append(log)
        return out


# --------------------------------------------------------------------------- #
# Confirmation depth
# --------------------------------------------------------------------------- #
def confirmed_head(latest_block: int, confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH) -> int:
    """The highest block a validator may treat as CONFIRMED. May be negative on a young chain."""
    if not isinstance(latest_block, int) or isinstance(latest_block, bool):
        raise WindowError(f"latest_block must be an int, got {type(latest_block).__name__}")
    if not isinstance(confirmation_depth, int) or isinstance(confirmation_depth, bool) \
            or confirmation_depth < 0:
        raise WindowError(
            f"confirmation_depth must be a non-negative int, got {confirmation_depth!r}")
    return latest_block - confirmation_depth


def block_windows(from_block: int, to_block: int,
                  chunk_blocks: int = DEFAULT_CHUNK_BLOCKS) -> List[Tuple[int, int]]:
    """Page ``[from_block, to_block]`` into inclusive chunks. Empty when the range is empty."""
    if chunk_blocks <= 0:
        raise WindowError("chunk_blocks must be positive")
    if to_block < from_block:
        return []
    out = []
    start = from_block
    while start <= to_block:
        end = min(start + chunk_blocks - 1, to_block)
        out.append((start, end))
        start = end + 1
    return out


def fetch_logs(source: LogSource, *, from_block: int, latest_block: int,
               to_block: Optional[int] = None,
               confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
               chunk_blocks: int = DEFAULT_CHUNK_BLOCKS,
               deployments: Optional[dp.DeploymentSet] = None,
               topics0: Sequence[str] = dp.V5_TOPICS) -> List[Mapping[str, Any]]:
    """Page CONFIRMED logs out of ``source``. Mirrors ``coretexRangeLogs``, minus the RPC."""
    head = confirmed_head(latest_block, confirmation_depth)
    requested_to = latest_block if to_block is None else to_block
    end = min(requested_to, head)
    addresses = deployments.addresses if deployments is not None else ()
    out: List[Mapping[str, Any]] = []
    for lo, hi in block_windows(from_block, end, chunk_blocks):
        out.extend(source.get_logs(lo, hi, topics0=tuple(topics0), addresses=tuple(addresses)))
    return out


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Gap:
    """A ``transitionIndex`` the feed never produced for an epoch."""

    epoch: int
    missing_from: int
    missing_to: int          # inclusive

    @property
    def count(self) -> int:
        return self.missing_to - self.missing_from + 1

    def as_dict(self) -> Dict[str, Any]:
        return {"epoch": self.epoch, "missing_from": self.missing_from,
                "missing_to": self.missing_to, "count": self.count}


@dataclass(frozen=True)
class Anomaly:
    """Something the feed did that a healthy chain feed does not do."""

    code: str
    epoch: Optional[int]
    detail: str

    def as_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "epoch": self.epoch, "detail": self.detail}


@dataclass(frozen=True)
class EpochInheritance:
    """One epoch head, DERIVED from confirmed advances (operator ruling §17.237).

    ``inherited_from_epoch`` is ``None`` iff the epoch inherited the deployment genesis root —
    i.e. it is the first epoch on this deployment that ever mined. ``established_by`` is the
    ``(epoch, transitionIndex)`` key of the transition that lazily initialized the head, which is
    always ``(epoch, 0)``; it is recorded so a reorg of that exact log can invalidate exactly this
    inheritance.
    """

    epoch: int
    inherited_parent_root: str
    inherited_from_epoch: Optional[int]
    established_by: Tuple[int, int]

    @property
    def from_genesis(self) -> bool:
        return self.inherited_from_epoch is None

    def as_dict(self) -> Dict[str, Any]:
        return {"epoch": self.epoch, "inherited_parent_root": self.inherited_parent_root,
                "inherited_from_epoch": self.inherited_from_epoch,
                "from_genesis": self.from_genesis,
                "established_by": list(self.established_by)}


@dataclass
class SyncResult:
    """The ordered, confirmed, gap-annotated view of one sync pass."""

    events: List[dp.FrontierAdvanced] = field(default_factory=list)
    pending: List[dp.FrontierAdvanced] = field(default_factory=list)
    finalizations: List[dp.MemoryEpochFinalized] = field(default_factory=list)
    inheritances: List[dp.EpochInherited] = field(default_factory=list)
    epoch_parents: Dict[int, EpochInheritance] = field(default_factory=dict)
    contexts: List[dp.MemoryEpochContextSet] = field(default_factory=list)
    commits: List[dp.EpochCommitSet] = field(default_factory=list)
    secrets: List[dp.EpochSecretRevealed] = field(default_factory=list)
    credits: List[dp.CreditAccepted] = field(default_factory=list)
    v4_events: List[dp.V4StateAdvanced] = field(default_factory=list)
    ignored: List[Dict[str, Any]] = field(default_factory=list)
    undecodable: List[Dict[str, Any]] = field(default_factory=list)
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    gaps: List[Gap] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    confirmed_head: Optional[int] = None

    @property
    def contiguous(self) -> bool:
        """True iff every epoch present is gap-free AND conflict-free."""
        return not self.gaps and not self.conflicts

    @property
    def epochs(self) -> Tuple[int, ...]:
        return tuple(sorted({e.epoch for e in self.events}))

    def events_for(self, epoch: int) -> List[dp.FrontierAdvanced]:
        return [e for e in self.events if e.epoch == epoch]

    def credit_for(self, event: dp.FrontierAdvanced) -> Optional[dp.CreditAccepted]:
        """The credit event minted in the SAME transaction as ``event``, if the feed carried it.

        Matched on transaction hash — the contract emits both inside one call, so a same-tx match
        is the strongest available join and does not depend on log ordering. Falls back to
        ``(epoch, evalReportHash, newFrontierRoot)`` when the feed carries no transaction hashes.
        """
        tx = event.provenance.transaction_hash
        if tx is not None:
            for credit in self.credits:
                if credit.provenance.transaction_hash == tx:
                    return credit
            return None
        for credit in self.credits:
            if (credit.epoch == event.epoch
                    and credit.eval_report_hash == event.eval_report_hash
                    and credit.new_frontier_root == event.new_frontier_root):
                return credit
        return None

    def pin_resolver(self) -> dp.PinResolver:
        """Per-epoch pins assembled from the context/commit/reveal logs THIS pass observed."""
        contexts = {c.epoch: c for c in self.contexts}
        commits = {c.epoch: c.epoch_commit for c in self.commits}
        secrets = {s.epoch: s.epoch_secret for s in self.secrets}
        table: Dict[int, dp.EpochPins] = {}
        for epoch, ctx in contexts.items():
            commit = commits.get(epoch)
            if commit is None or commit == dp.ZERO_WORD:
                continue
            table[epoch] = dp.EpochPins(
                epoch=epoch,
                runtime_abi_root=ctx.runtime_abi_root,
                benchmark_law_root=ctx.benchmark_law_root,
                counter_resource_law_root=ctx.counter_resource_law_root,
                entropy_commitment=commit, revealed_secret=secrets.get(epoch))
        return dp.pins_from_mapping(table)

    def epoch_parent(self, epoch: int) -> Optional[str]:
        """The DERIVED inherited parent root of ``epoch``, or ``None`` if undetermined."""
        found = self.epoch_parents.get(epoch)
        return None if found is None else found.inherited_parent_root

    def summary(self) -> Dict[str, Any]:
        return {
            "confirmed_head": self.confirmed_head,
            "events": len(self.events), "pending": len(self.pending),
            "epochs": list(self.epochs), "contiguous": self.contiguous,
            "gaps": [g.as_dict() for g in self.gaps],
            "conflicts": len(self.conflicts), "duplicates": len(self.duplicates),
            "ignored": len(self.ignored), "undecodable": len(self.undecodable),
            "anomalies": [a.as_dict() for a in self.anomalies],
            "epoch_parents": {str(e): i.as_dict() for e, i in sorted(self.epoch_parents.items())},
            "epoch_heads_published": len(self.inheritances),
            "v4_events": len(self.v4_events),
        }


# --------------------------------------------------------------------------- #
# Ordering + contiguity, as free functions
# --------------------------------------------------------------------------- #
def order_events(events: Iterable[dp.FrontierAdvanced]) -> List[dp.FrontierAdvanced]:
    """Sort by ``(epoch, transitionIndex)`` — the CHAIN order — then by block position.

    The block-position tiebreak only ever separates entries that already share a key; it never
    reorders across keys, so the chain order is authoritative.
    """
    return sorted(events, key=lambda e: (e.epoch, e.transition_index, e.provenance.position))


def dedupe_events(events: Sequence[dp.FrontierAdvanced]
                  ) -> Tuple[List[dp.FrontierAdvanced], List[Dict[str, Any]],
                             List[Dict[str, Any]]]:
    """Split an ordered stream into ``(unique, duplicates, conflicts)``.

    Identity is the full decoded payload, not the key: same key + same payload = a duplicated feed
    entry; same key + different payload = a CONFLICT that this layer refuses to arbitrate.
    """
    unique: List[dp.FrontierAdvanced] = []
    duplicates: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    seen: Dict[Tuple[int, int], dp.FrontierAdvanced] = {}
    for event in events:
        prior = seen.get(event.key)
        if prior is None:
            seen[event.key] = event
            unique.append(event)
            continue
        if _same_payload(prior, event):
            duplicates.append({"epoch": event.epoch, "transition_index": event.transition_index,
                               "detail": "identical payload observed twice in the feed",
                               "first": prior.summary(), "repeat": event.summary()})
        else:
            conflicts.append({
                "epoch": event.epoch, "transition_index": event.transition_index,
                "detail": "two DIFFERENT payloads claim one (epoch, transitionIndex); exactly one "
                          "can be canonical and this layer will not choose",
                "first": prior.summary(), "other": event.summary()})
    if conflicts:
        conflicted = {(c["epoch"], c["transition_index"]) for c in conflicts}
        unique = [e for e in unique if e.key not in conflicted]
    return unique, duplicates, conflicts


def _same_payload(a: dp.FrontierAdvanced, b: dp.FrontierAdvanced) -> bool:
    return (a.miner == b.miner and a.parent_frontier_root == b.parent_frontier_root
            and a.new_frontier_root == b.new_frontier_root
            and a.candidate_release_root == b.candidate_release_root
            and a.composition_root == b.composition_root
            and a.eval_report_hash == b.eval_report_hash
            and a.benchmark_law_root == b.benchmark_law_root
            and a.runtime_abi_root == b.runtime_abi_root
            and a.transition_bytes == b.transition_bytes)


def check_contiguity(events: Sequence[dp.FrontierAdvanced], *,
                     start_index: Optional[Mapping[int, int]] = None) -> List[Gap]:
    """Per-epoch index continuity. Returns every :class:`Gap`; never raises, never skips one.

    ``start_index[epoch]`` is the RESUME CURSOR for a window that legitimately begins mid-epoch.
    It defaults to 0: an epoch is assumed to be observed from its first advance, so a missing
    prefix shows up as a gap instead of quietly becoming the new beginning.
    """
    start_index = dict(start_index or {})
    gaps: List[Gap] = []
    expected: Dict[int, int] = {}
    for event in order_events(events):
        want = expected.get(event.epoch, start_index.get(event.epoch, 0))
        if event.transition_index > want:
            gaps.append(Gap(epoch=event.epoch, missing_from=want,
                            missing_to=event.transition_index - 1))
        elif event.transition_index < want:
            # ordered input makes this reachable only via a duplicate/conflict key
            gaps.append(Gap(epoch=event.epoch, missing_from=event.transition_index,
                            missing_to=event.transition_index))
        expected[event.epoch] = event.transition_index + 1
    return gaps


def _position_anomalies(events: Sequence[dp.FrontierAdvanced]) -> List[Anomaly]:
    """Chain order and block order must agree within one epoch on one deployment."""
    out: List[Anomaly] = []
    by_epoch: Dict[Tuple[int, Optional[str]], List[dp.FrontierAdvanced]] = {}
    for event in events:
        by_epoch.setdefault((event.epoch, event.provenance.address), []).append(event)
    for (epoch, address), group in sorted(by_epoch.items(), key=lambda kv: (kv[0][0],
                                                                           kv[0][1] or "")):
        ordered = sorted(group, key=lambda e: e.transition_index)
        positions = [e.provenance.position for e in ordered]
        if any(p == (1 << 62, 1 << 62) for p in positions):
            continue                                  # feed carries no block positions: nothing to check
        if positions != sorted(positions):
            out.append(Anomaly(
                code="block_order_disagrees_with_chain_order", epoch=epoch,
                detail=f"epoch {epoch} on {address}: transitionIndex order and (blockNumber, "
                       "logIndex) order disagree — a reorg, a merged feed, or two deployments "
                       "sharing one address"))
    return out


def _removed_anomalies(events: Sequence[dp.FrontierAdvanced]) -> List[Anomaly]:
    return [Anomaly(code="reorg_removed_log", epoch=e.epoch,
                    detail=f"epoch {e.epoch} index {e.transition_index} is flagged removed=true "
                           "by the feed; it was reorged out and must not be replayed")
            for e in events if e.provenance.removed]


# --------------------------------------------------------------------------- #
# Epoch-head inheritance, derived from confirmed history (ruling §17.237)
# --------------------------------------------------------------------------- #
def derive_epoch_parents(events: Sequence[dp.FrontierAdvanced], *,
                         genesis_frontier_root: Optional[str] = None,
                         finalizations: Sequence[dp.MemoryEpochFinalized] = ()
                         ) -> Tuple[Dict[int, EpochInheritance], List[Anomaly]]:
    """Re-derive every epoch head from CONFIRMED CHAIN HISTORY ALONE. Pure; never raises on data.

    This is the validator's copy of ``RigCoreTexStateRegistry.resolveEpochParent`` (``:826``) — the
    LIVE registry; the retired ``CoreTexMemoryRegistry`` declares the same function but is bound to
    no address in the rig lane, and citing it here named the wrong authority. It is
    deliberately written from the same four facts the contract uses — which epochs have
    transitions, which of those are FINALIZED, each finalized epoch's sealed final root, and the
    deployment genesis root — so the two cannot drift into different answers.

    ONLY A CONFIRMED **FINAL** ROOT MAY BE INHERITED (§17.237). If the latest preceding non-empty
    epoch carries no confirmed ``CoreTexMemoryEpochFinalized``, this epoch's head is UNRESOLVED —
    ``preceding_epoch_not_finalized``, the same condition the registry reverts on and the same one
    the coordinator reports as ``EPOCH_HEAD_UNRESOLVED``. An unfinalized epoch's live root can
    still advance, so treating it as inheritable would admit two lawful initializations of the
    next epoch against two different parents.

    ``genesis_frontier_root=None`` means the caller has not supplied one. The first epoch's
    inheritance is then simply NOT derived (it is unknown, not assumed): a validator that guessed
    would be inventing the one head the ruling says is fixed at deployment.

    Returns ``({epoch: EpochInheritance}, [Anomaly])``.

    THE MAP HOLDS WHAT THE RULE DERIVES, NOT WHAT THE EVENT CLAIMED. When an epoch's first
    transition names a parent the rule does not derive — a skipped-history root, an alternate head
    — the DERIVED value is still recorded (so the replayer can use it and the advance fails the
    parent check loudly) and an anomaly is raised alongside it. An epoch is ABSENT from the map
    only when the inheritance genuinely cannot be determined: its establishing transition was
    never observed, or was reorged out, or it is the earliest epoch and no genesis root was given.
    Absent means UNVERIFIED, never "anything goes".
    """
    if genesis_frontier_root is not None:
        fr.check_root(genesis_frontier_root, "genesis_frontier_root")
    out: Dict[int, EpochInheritance] = {}
    anomalies: List[Anomaly] = []
    sealed: Dict[int, dp.MemoryEpochFinalized] = {f.epoch: f for f in finalizations}

    by_epoch: Dict[int, List[dp.FrontierAdvanced]] = {}
    for event in order_events(events):
        by_epoch.setdefault(event.epoch, []).append(event)

    last_non_empty: Optional[int] = None
    last_final_root: Optional[str] = None
    for epoch in sorted(by_epoch):
        group = by_epoch[epoch]
        first = group[0]
        reorged = False
        if first.transition_index != 0:
            # A window that legitimately resumes mid-epoch lands here. The epoch's later
            # transitions are still confirmed truth, so its final root stays usable for the NEXT
            # epoch's derivation; only its own inheritance is unknown.
            anomalies.append(Anomaly(
                code="epoch_inheritance_unobserved", epoch=epoch,
                detail=f"the first advance this feed carries for epoch {epoch} is index "
                       f"{first.transition_index}; the transition that lazily initialized the "
                       "epoch head was never observed, so the inheritance cannot be derived and "
                       "is NOT inferred from the transitions that were"))
        elif first.provenance.removed:
            reorged = True
            anomalies.append(Anomaly(
                code="reorg_invalidated_epoch_inheritance", epoch=epoch,
                detail=f"epoch {epoch}'s FIRST transition (the one that established its head, "
                       f"inheriting {first.parent_frontier_root}) is flagged removed=true. The "
                       "inheritance it created is INVALIDATED. It is NOT re-derived from the "
                       "surviving transitions: promoting index 1 to 'first' would manufacture an "
                       "epoch head no confirmed transition ever named"))
        elif last_non_empty is None:
            if genesis_frontier_root is None:
                anomalies.append(Anomaly(
                    code="genesis_root_unknown", epoch=epoch,
                    detail=f"epoch {epoch} is the earliest epoch with a confirmed transition, so "
                           "it must have inherited the deployment genesis root — but no genesis "
                           "root was supplied, so its inheritance is UNVERIFIED rather than "
                           "assumed"))
            else:
                out[epoch] = EpochInheritance(
                    epoch=epoch, inherited_parent_root=genesis_frontier_root,
                    inherited_from_epoch=None, established_by=first.key)
                if first.parent_frontier_root != genesis_frontier_root:
                    anomalies.append(Anomaly(
                        code="genesis_inheritance_mismatch", epoch=epoch,
                        detail=f"epoch {epoch} is the earliest epoch with a confirmed transition "
                               f"and names parent {first.parent_frontier_root}, but the "
                               f"deployment genesis root is {genesis_frontier_root}"))
        elif last_final_root is None:
            anomalies.append(Anomaly(
                code="epoch_parent_rests_on_an_invalidated_epoch", epoch=epoch,
                detail=f"epoch {epoch} inherits from epoch {last_non_empty}, whose own head was "
                       "invalidated by a reorg; its final root is not confirmed truth, so this "
                       "inheritance is unresolved too rather than being carried through"))
        elif last_non_empty not in sealed:
            # THE FINALIZATION RULE. Same condition the registry reverts on
            # (`PrecedingEpochNotFinalized`) and the coordinator reports as
            # EPOCH_HEAD_UNRESOLVED / preceding_epoch_not_finalized.
            anomalies.append(Anomaly(
                code="preceding_epoch_not_finalized", epoch=epoch,
                detail=f"epoch {epoch} would inherit from epoch {last_non_empty}, but this feed "
                       "carries no confirmed CoreTexMemoryEpochFinalized for it. Only a confirmed "
                       "FINAL root may be inherited: an unfinalized epoch's live root can still "
                       "advance, and a head that can still move is two lawful heads. UNRESOLVED, "
                       "not assumed"))
        else:
            expected = sealed[last_non_empty].final_frontier_root
            if expected != last_final_root:
                anomalies.append(Anomaly(
                    code="final_root_disagrees_with_replay", epoch=last_non_empty,
                    detail=f"epoch {last_non_empty} sealed {expected} but its last confirmed "
                           f"advance produced {last_final_root}; epoch {epoch}'s inheritance rests "
                           "on the SEALED value, so this disagreement is load-bearing"))
            out[epoch] = EpochInheritance(
                epoch=epoch, inherited_parent_root=expected,
                inherited_from_epoch=last_non_empty, established_by=first.key)
            if first.parent_frontier_root != expected:
                anomalies.append(Anomaly(
                    code="epoch_parent_mismatch", epoch=epoch,
                    detail=f"epoch {epoch}'s first transition names parent "
                           f"{first.parent_frontier_root}, but the rule derives "
                           f"{expected} — the confirmed FINAL root of epoch "
                           f"{last_non_empty}, the latest preceding epoch with any transition. "
                           "Naming anything else is a skipped-history or alternate-head advance "
                           "and the registry refuses it"))
        last_non_empty = epoch
        # A reorged epoch head poisons the epoch's final root: the transitions after a removed
        # first transition are not a confirmed chain from anything.
        last_final_root = None if reorged else group[-1].new_frontier_root
    return out, anomalies


def check_inheritance(derived: Mapping[int, EpochInheritance],
                      published: Sequence[dp.EpochInherited]) -> List[Anomaly]:
    """Cross-check the DERIVED epoch heads against the published ``CoreTexMemoryEpochInherited``.

    The derivation wins by construction (rule 6: the parent comes from confirmed history). This
    function exists so a disagreement — a publisher that named a different head, a duplicate
    publication, a head published for an epoch that never mined — is SURFACED rather than
    silently overruled.
    """
    anomalies: List[Anomaly] = []
    seen: Dict[int, dp.EpochInherited] = {}
    for event in published:
        if event.epoch in seen:
            anomalies.append(Anomaly(
                code="duplicate_epoch_head_publication", epoch=event.epoch,
                detail=f"epoch {event.epoch} published a head twice; the registry emits it exactly "
                       "once, inside the epoch's first accepted transition"))
            continue
        seen[event.epoch] = event
    for epoch, event in sorted(seen.items()):
        expected = derived.get(epoch)
        if expected is None:
            anomalies.append(Anomaly(
                code="epoch_head_published_without_derivation", epoch=epoch,
                detail=f"epoch {epoch} published a head ({event.inherited_parent_root}) that this "
                       "feed cannot derive from confirmed advances; it is not accepted on the "
                       "publisher's word"))
            continue
        if event.inherited_parent_root != expected.inherited_parent_root:
            anomalies.append(Anomaly(
                code="epoch_head_disagrees_with_history", epoch=epoch,
                detail=f"epoch {epoch} published inherited parent {event.inherited_parent_root}; "
                       f"confirmed history derives {expected.inherited_parent_root}"))
        if event.from_genesis != expected.from_genesis:
            anomalies.append(Anomaly(
                code="epoch_head_genesis_flag_disagrees", epoch=epoch,
                detail=f"epoch {epoch} published from_genesis={event.from_genesis}; confirmed "
                       f"history derives {expected.from_genesis}"))
        elif not expected.from_genesis and event.inherited_from_epoch != expected.inherited_from_epoch:
            anomalies.append(Anomaly(
                code="epoch_head_source_epoch_disagrees", epoch=epoch,
                detail=f"epoch {epoch} published inheritedFromEpoch="
                       f"{event.inherited_from_epoch}; confirmed history derives "
                       f"{expected.inherited_from_epoch}"))
    for epoch, inheritance in sorted(derived.items()):
        if published and epoch not in seen:
            anomalies.append(Anomaly(
                code="epoch_head_never_published", epoch=epoch,
                detail=f"epoch {epoch} has a derived head ({inheritance.inherited_parent_root}) "
                       "but this feed carries no CoreTexMemoryEpochInherited for it"))
    return anomalies


# --------------------------------------------------------------------------- #
# The sync pass
# --------------------------------------------------------------------------- #
def sync_logs(logs: Iterable[Mapping[str, Any]], *, latest_block: Optional[int] = None,
              confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
              deployments: Optional[dp.DeploymentSet] = None,
              start_index: Optional[Mapping[int, int]] = None,
              genesis_frontier_root: Optional[str] = None) -> SyncResult:
    """Decode, confirm, order and check one batch of logs. Pure: no I/O of any kind.

    ``latest_block=None`` means the caller already applied its own confirmation policy (an archive
    dump, a fixture); every decoded advance is then treated as confirmed and ``confirmed_head`` is
    reported as ``None`` so the caller can tell the two situations apart.

    ``genesis_frontier_root`` is the deployment's immutable genesis root. It is what makes the
    FIRST epoch's inheritance checkable; without it that one epoch's head is reported as
    underived rather than assumed (ruling §17.237 rule 7, first-deployment genesis).
    """
    result = SyncResult()
    head = None
    if latest_block is not None:
        head = confirmed_head(latest_block, confirmation_depth)
    result.confirmed_head = head

    advances: List[dp.FrontierAdvanced] = []
    for log in logs:
        try:
            r, decoded = dp.decode(log, deployments)
        except dp.DispatchError as exc:
            result.undecodable.append({"reason": str(exc),
                                       "topics0": (log.get("topics") or [None])[0],
                                       "address": log.get("address")})
            continue
        if not r.recognised:
            result.ignored.append({"reason": r.reason, "topic0": r.topic0,
                                   "address": log.get("address")})
            continue
        if decoded is None:
            result.ignored.append({"reason": f"{r.event}: recognised, no V5 decoder "
                                             "(owned by the V4 replayer)",
                                   "topic0": r.topic0, "address": log.get("address")})
            continue
        if isinstance(decoded, dp.FrontierAdvanced):
            block = decoded.provenance.block_number
            if head is not None and (block is None or block > head):
                result.pending.append(decoded)
            else:
                advances.append(decoded)
        elif isinstance(decoded, dp.MemoryEpochFinalized):
            result.finalizations.append(decoded)
        elif isinstance(decoded, dp.EpochInherited):
            result.inheritances.append(decoded)
        elif isinstance(decoded, dp.MemoryEpochContextSet):
            result.contexts.append(decoded)
        elif isinstance(decoded, dp.EpochCommitSet):
            result.commits.append(decoded)
        elif isinstance(decoded, dp.EpochSecretRevealed):
            result.secrets.append(decoded)
        elif isinstance(decoded, dp.CreditAccepted):
            result.credits.append(decoded)
        elif isinstance(decoded, dp.V4StateAdvanced):
            result.v4_events.append(decoded)

    ordered = order_events(advances)
    unique, duplicates, conflicts = dedupe_events(ordered)
    result.events = unique
    result.duplicates = duplicates
    result.conflicts = conflicts
    result.gaps = check_contiguity(unique, start_index=start_index)
    result.anomalies = _position_anomalies(unique) + _removed_anomalies(unique)
    for conflict in conflicts:
        result.anomalies.append(Anomaly(code="conflicting_transition_index",
                                        epoch=conflict["epoch"], detail=conflict["detail"]))
    # Epoch heads: derive from confirmed advances, then cross-check the publications.
    result.inheritances.sort(key=lambda i: (i.epoch, i.provenance.position))
    parents, inherit_anomalies = derive_epoch_parents(
        unique, genesis_frontier_root=genesis_frontier_root,
        finalizations=result.finalizations)
    result.epoch_parents = parents
    result.anomalies.extend(inherit_anomalies)
    result.anomalies.extend(check_inheritance(parents, result.inheritances))
    result.pending = order_events(result.pending)
    result.finalizations.sort(key=lambda f: f.epoch)
    result.contexts.sort(key=lambda c: (c.epoch, c.provenance.position))
    result.commits.sort(key=lambda c: (c.epoch, c.provenance.position))
    result.secrets.sort(key=lambda s: (s.epoch, s.provenance.position))
    result.credits.sort(key=lambda c: (c.epoch, c.solve_index, c.provenance.position))
    result.v4_events.sort(key=lambda e: (e.epoch, e.transitionIndex))
    return result


def sync(source: LogSource, *, from_block: int, latest_block: int,
         to_block: Optional[int] = None,
         confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
         chunk_blocks: int = DEFAULT_CHUNK_BLOCKS,
         deployments: Optional[dp.DeploymentSet] = None,
         start_index: Optional[Mapping[int, int]] = None,
         topics0: Sequence[str] = dp.V5_TOPICS,
         genesis_frontier_root: Optional[str] = None) -> SyncResult:
    """:func:`fetch_logs` + :func:`sync_logs`. The only function here that touches the source."""
    logs = fetch_logs(source, from_block=from_block, latest_block=latest_block,
                      to_block=to_block, confirmation_depth=confirmation_depth,
                      chunk_blocks=chunk_blocks, deployments=deployments, topics0=topics0)
    return sync_logs(logs, latest_block=latest_block, confirmation_depth=confirmation_depth,
                     deployments=deployments, start_index=start_index,
                     genesis_frontier_root=genesis_frontier_root)


def check_finalization(result: SyncResult, epoch: int,
                       reproduced_final_root: str) -> Optional[Anomaly]:
    """If the epoch was finalized on-chain, its sealed root must be the reproduced one."""
    fr.check_root(reproduced_final_root, "reproduced_final_root")
    for fin in result.finalizations:
        if fin.epoch != epoch:
            continue
        if fin.final_frontier_root != reproduced_final_root:
            return Anomaly(
                code="final_root_mismatch", epoch=epoch,
                detail=f"CoreTexMemoryEpochFinalized sealed {fin.final_frontier_root} but replay "
                       f"reproduced {reproduced_final_root}")
        count = len(result.events_for(epoch))
        if fin.transitions != count:
            return Anomaly(
                code="final_transition_count_mismatch", epoch=epoch,
                detail=f"epoch {epoch} sealed {fin.transitions} transitions; the feed produced "
                       f"{count}")
    return None
