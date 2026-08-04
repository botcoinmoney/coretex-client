# SPDX-License-Identifier: Apache-2.0
"""Step 3: per-rig receipt continuity — the ``rigNextIndex`` / ``rigLastReceiptHash`` chain.

WHAT THE CHAIN IS AND WHY IT MATTERS. Every accepted receipt for a rig names the hash of that
rig's PREVIOUS receipt (``prevReceiptHash``) and its position (``solveIndex``). ``mining`` refuses
anything that does not continue the chain, so the confirmed sequence for a rig is a hash-linked
list — and replaying it is how a validator proves nothing was dropped, reordered, or inserted.
Without this check, an indexer that missed one receipt would simply have a shorter, entirely
self-consistent-looking history.

**THE CORETEX AND STANDARD LANES SHARE ONE CHAIN.** ``BotcoinMiningRigsV1`` advances the same
``rigNextIndex``/``rigLastReceiptHash`` for ``RigCreditAccepted`` (a standard receipt) as for
``RigCoreTexCreditAccepted``. A replay that consumed only the CoreTex events would see gaps at
every standard receipt and report a break that is not there. Both are consumed here. This is the
single easiest thing to get wrong in this module and it is why :class:`ChainEntry` carries
``coretex`` rather than being two classes.

WHAT IS PROVED, AND WHAT IS ONLY CROSS-CHECKED. The linkage itself is proved from logs alone:
index density, monotonicity, and the recomputed link. The recomputed ``receiptHash`` — the §7.2
step 4 preimage — needs the transaction calldata, so it is done in :mod:`.join` where the calldata
already is, and this module records only whether the events' own ``receiptHash`` values form a
consistent chain against the on-chain head. The final ``rigLastReceiptHash(rigId)`` read at the
observation block is the anchor: if the replayed tail does not equal it, the log set is
incomplete, and that is reported as an incomplete scan rather than a broken chain, because those
are different problems with different fixes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import rig_events as rig

#: What a rig's chain starts from before its first receipt.
ZERO_HASH = "0" * 64


class ReceiptChainError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ChainEntry:
    """One accepted receipt, as the credit event reports it."""

    rig_id: int
    solve_index: int
    receipt_hash: str
    epoch: int
    operator: str
    coretex: bool
    block_number: Optional[int]
    log_index: Optional[int]
    transaction_hash: Optional[str]

    @classmethod
    def from_credit(cls, credit: rig.CoreTexCreditAccepted) -> "ChainEntry":
        provenance = credit.provenance
        return cls(rig_id=credit.rig_id, solve_index=credit.solve_index,
                   receipt_hash=credit.receipt_hash, epoch=credit.epoch,
                   operator=credit.operator, coretex=credit.coretex,
                   block_number=provenance.block_number, log_index=provenance.log_index,
                   transaction_hash=provenance.transaction_hash)


@dataclass
class RigChainResult:
    rig_id: int
    ok: bool
    entries: List[ChainEntry]
    #: The head the replay ends at, and the head the chain reports. Equal on a complete scan.
    replayed_next_index: int
    replayed_last_receipt_hash: str
    chain_next_index: Optional[int]
    chain_last_receipt_hash: Optional[str]
    complete: Optional[bool]
    problems: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rig_id": self.rig_id, "ok": self.ok, "receipts": len(self.entries),
            "coretex_receipts": sum(1 for e in self.entries if e.coretex),
            "standard_receipts": sum(1 for e in self.entries if not e.coretex),
            "replayed_next_index": self.replayed_next_index,
            "replayed_last_receipt_hash": self.replayed_last_receipt_hash,
            "chain_next_index": self.chain_next_index,
            "chain_last_receipt_hash": self.chain_last_receipt_hash,
            "complete": self.complete, "problems": list(self.problems),
        }


def _order_key(entry: ChainEntry) -> Tuple[int, int]:
    """Chain order. Both components are required: two logs in one block are ordered by log index,
    and a scan that sorted on ``solve_index`` would be assuming the very property it is checking."""
    return (entry.block_number if entry.block_number is not None else 0,
            entry.log_index if entry.log_index is not None else 0)


def replay_rig_chain(rig_id: int, credits: Sequence[rig.CoreTexCreditAccepted], *,
                     chain_next_index: Optional[int] = None,
                     chain_last_receipt_hash: Optional[str] = None,
                     start_index: int = 0) -> RigChainResult:
    """Replay one rig's receipt chain from its credit events.

    ``start_index`` is for a partial scan that legitimately begins after the rig's first receipt
    (an operator who only kept logs from some block onward). It makes the density check relative
    rather than silently accepting a hole at the front.
    """
    entries = sorted((ChainEntry.from_credit(c) for c in credits if c.rig_id == int(rig_id)),
                     key=_order_key)
    problems: List[str] = []
    expected = int(start_index)
    last_hash = ZERO_HASH if expected == 0 else ""
    for entry in entries:
        if entry.solve_index != expected:
            problems.append(
                f"solveIndex {entry.solve_index} where {expected} was due (block "
                f"{entry.block_number}, log {entry.log_index}) — the chain is dense and "
                f"zero-based, so this is a missing or duplicated receipt, not a gap in numbering")
            expected = entry.solve_index
        expected += 1
        last_hash = entry.receipt_hash
    replayed_next = expected
    complete: Optional[bool] = None
    if chain_next_index is not None:
        complete = replayed_next == int(chain_next_index)
        if not complete:
            problems.append(
                f"replayed rigNextIndex {replayed_next} != the chain's {chain_next_index}: this "
                "log scan is INCOMPLETE (a missing window), which is a different problem from a "
                "broken chain and needs a wider scan rather than an investigation")
    if chain_last_receipt_hash is not None and last_hash:
        if last_hash != str(chain_last_receipt_hash):
            problems.append(
                f"replayed rigLastReceiptHash {last_hash} != the chain's "
                f"{chain_last_receipt_hash}")
    return RigChainResult(rig_id=int(rig_id), ok=not problems, entries=entries,
                          replayed_next_index=replayed_next,
                          replayed_last_receipt_hash=last_hash or ZERO_HASH,
                          chain_next_index=chain_next_index,
                          chain_last_receipt_hash=chain_last_receipt_hash,
                          complete=complete, problems=problems)


def replay_all(decoded: rig.DecodedLogs, *, views=None,
               start_indices: Optional[Mapping[int, int]] = None) -> Dict[int, RigChainResult]:
    """Every rig that appears in the scan, replayed. ``views`` supplies the on-chain anchors.

    Anchors are optional so the replay still runs against a fixture with no RPC — but a run
    WITHOUT them cannot tell a complete history from a truncated one, and :attr:`RigChainResult
    .complete` is ``None`` to say so rather than defaulting to ``True``.
    """
    everything = list(decoded.coretex_credits) + list(decoded.standard_credits)
    by_rig: Dict[int, List[rig.CoreTexCreditAccepted]] = {}
    for credit in everything:
        by_rig.setdefault(credit.rig_id, []).append(credit)
    starts = dict(start_indices or {})
    out: Dict[int, RigChainResult] = {}
    for rig_id, credits in sorted(by_rig.items()):
        next_index = last_hash = None
        if views is not None:
            next_index = views.rig_next_index(rig_id)
            last_hash = views.rig_last_receipt_hash(rig_id)
        out[rig_id] = replay_rig_chain(rig_id, credits, chain_next_index=next_index,
                                       chain_last_receipt_hash=last_hash,
                                       start_index=starts.get(rig_id, 0))
    return out
