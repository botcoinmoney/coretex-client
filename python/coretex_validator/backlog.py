# SPDX-License-Identifier: UNLICENSED
"""The validator BACKLOG: unresolved work is persisted, never passed and never dropped.

§17.236's V5-E line is "unresolved work persisted as a BACKLOG rather than falsely passing", and
§14.9 of the artifact spec restates it: *a verifier that cannot reproduce a binding records a
backlog entry, never a pass*. This module is that requirement made structural.

THREE OUTCOMES, NOT TWO. :class:`Outcome` has ``PASS``, ``FAIL`` and ``BACKLOG``, and BACKLOG is
neither of the other two:

  * ``PASS``    — every consensus-critical binding was REPRODUCED.
  * ``FAIL``    — a binding was reproduced and DISAGREED. A determination was made.
  * ``BACKLOG`` — a binding could not be reached at all: the artifact is not published yet, the
                  manifest is unfetchable, the pinned sandbox is not on this host, the oracle
                  screen needs the frozen generators. NO determination was made.

A two-valued verdict forces the third case to masquerade as one of the other two, and both
choices are wrong: calling it PASS is the exact "falsely passing" the directive forbids, and
calling it FAIL slanders a mine over the validator's own missing inputs. So it is its own value,
``ok`` is False for it, and :attr:`Outcome.is_pass` is True for PASS alone.

THE TYPED REASONS. The directive names four; they are the first four below. Three more are the
same category — unresolved CONTEXT work the validator could not reach — and are enumerated rather
than folded into a generic "other", because an operator draining a backlog needs to know which
input to go find. Every reason carries a fixed remediation string for exactly that reason.

PERSISTENCE. :class:`FileBacklog` appends one JSON line per state change to a journal and never
rewrites or truncates it. Re-recording a still-unresolved entry bumps ``attempts`` instead of
adding a row; resolving one appends a ``resolved`` record and keeps the original. Reconstruction
replays the journal in order, so the file IS the state and "dropped on restart" is not reachable.
Entries are addressed by :func:`entry_id` — sha256 over the canonical bytes of the identity
subset — so the same unresolved item is the same row across processes and hosts.

SEAM (ledger §17.238)
---------------------
SEAM:            NO EXTERNAL SEAM — this is a library with one plain value as its whole
                 configuration: ``FileBacklog(directory)`` (:337). It has no port, opens no
                 socket, and is constructed by whoever runs :mod:`validator.replay`.
MINIMAL DIFF:    ``backlog = FileBacklog(os.path.join(<validator state dir>, "backlog"))`` and
                 pass its entries along with the replay result. Nothing here is edited.
ADDITIVE DATA ONLY: an append-only JSON-lines journal under a directory the caller owns. It
                 creates no table, alters no existing table, and writes no on-disk format the
                 live stack reads. The file IS the state (the journal is replayed to
                 reconstruct), so there is no migration to run and none to undo.
REVENDOR NEEDED: NO. stdlib + ``v5/frontier.py`` only.
ARM:             none.
REMOVE:          delete the directory. Nothing else references it.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple


from . import frontier as fr

BACKLOG_ENTRY_FORMAT = "coretex.memory-frontier.v1/validator-backlog-entry/v1"
BACKLOG_JOURNAL_FORMAT = "coretex.memory-frontier.v1/validator-backlog-journal/v1"


class BacklogError(Exception):
    """Base of every backlog failure."""


class UnknownReasonError(BacklogError):
    """A backlog entry names a reason outside the closed set."""


class JournalError(BacklogError):
    """The persisted journal is unreadable or inconsistent."""


# --------------------------------------------------------------------------- #
# Outcomes
# --------------------------------------------------------------------------- #
class Outcome(str):
    """A three-valued replay outcome. A ``str`` subclass so it serializes as itself."""

    __slots__ = ()

    @property
    def is_pass(self) -> bool:
        return self == PASS

    @property
    def is_fail(self) -> bool:
        return self == FAIL

    @property
    def is_backlog(self) -> bool:
        return self == BACKLOG

    @property
    def ok(self) -> bool:
        """PASS alone. A BACKLOG is emphatically not ok — it is undetermined."""
        return self == PASS


PASS = Outcome("PASS")
FAIL = Outcome("FAIL")
BACKLOG = Outcome("BACKLOG")
OUTCOMES: Tuple[Outcome, ...] = (PASS, FAIL, BACKLOG)


# --------------------------------------------------------------------------- #
# The closed reason set
# --------------------------------------------------------------------------- #
#: The four §17.236 names.
MISSING_ARTIFACT = "missing_artifact"
UNFETCHABLE_MANIFEST = "unfetchable_manifest"
SANDBOX_UNAVAILABLE = "sandbox_unavailable"
ORACLE_SCREEN_UNAVAILABLE = "oracle_screen_unavailable"
#: Same category, enumerated so an operator knows which input to go find.
RECEIPT_UNAVAILABLE = "receipt_unavailable"
COUNTER_LAW_UNAVAILABLE = "counter_law_unavailable"
EPOCH_PINS_UNAVAILABLE = "epoch_pins_unavailable"

REASONS: Dict[str, str] = {
    MISSING_ARTIFACT:
        "the eval artifact named by the confirmed event's evalReportHash is not published on any "
        "reachable publication surface. Fetch it (or its bytes from the miner/coordinator) and "
        "re-run; the event stays UNVERIFIED until then.",
    UNFETCHABLE_MANIFEST:
        "a frontier manifest (parent, or one addressed by the artifact) could not be fetched from "
        "the publication surface. Republish or mirror it, then re-run.",
    SANDBOX_UNAVAILABLE:
        "the pinned networkless candidate sandbox is not usable on this host (frozen runtime, "
        "generators or candidate bundle absent). Provision the pinned sandbox and re-run; the "
        "candidate's measurements are UNVERIFIED until it executes.",
    ORACLE_SCREEN_UNAVAILABLE:
        "the G6b oracle-cleanliness screen could not run, so selection-skip completeness is "
        "undetermined. The screen needs the frozen generators + runtime. Provision them and "
        "re-run.",
    RECEIPT_UNAVAILABLE:
        "the signed Benchmark-v2 receipt addressed by the artifact's wrapper_root is not "
        "fetchable. The receipt IS the admission law and is never skipped.",
    COUNTER_LAW_UNAVAILABLE:
        "the counter-resource law addressed by counterResourceLawRoot is not fetchable, so the "
        "ppm accounting cannot be recomputed under the pinned law.",
    EPOCH_PINS_UNAVAILABLE:
        "no pins are known for this event's OWN epoch (context/commit events not in the synced "
        "window). Another epoch's pins are never substituted.",
}

#: Identity fields: two entries with the same values are the same unresolved item.
_IDENTITY_FIELDS = ("reason", "epoch", "transition_index", "eval_report_hash", "subject")


def entry_id(reason: str, epoch: Optional[int], transition_index: Optional[int],
             eval_report_hash: Optional[str], subject: Optional[str]) -> str:
    """The stable id of one unresolved item — sha256 over its canonical identity bytes."""
    if reason not in REASONS:
        raise UnknownReasonError(
            f"unknown backlog reason {reason!r}; the set is CLOSED: {sorted(REASONS)}")
    identity = {
        "epoch": -1 if epoch is None else epoch,
        "eval_report_hash": eval_report_hash or "",
        "format": BACKLOG_ENTRY_FORMAT,
        "reason": reason,
        "subject": subject or "",
        "transition_index": -1 if transition_index is None else transition_index,
    }
    return fr.sha256_hex(fr.canonical_bytes(identity))


@dataclass
class BacklogEntry:
    """One piece of unresolved verification work. A distinct outcome from PASS and from FAIL."""

    reason: str
    detail: str
    epoch: Optional[int] = None
    transition_index: Optional[int] = None
    eval_report_hash: Optional[str] = None
    parent_frontier_root: Optional[str] = None
    new_frontier_root: Optional[str] = None
    miner: Optional[str] = None
    address: Optional[str] = None
    #: What could not be reached — a root, a path, a tool name. Part of the identity.
    subject: Optional[str] = None
    stage: str = ""
    attempts: int = 1
    resolved: bool = False
    resolution: Optional[str] = None
    #: Injected by the caller (never ``time.time()``): a validator run must be reproducible.
    observed_at: Optional[int] = None
    last_detail: Optional[str] = None

    def __post_init__(self) -> None:
        if self.reason not in REASONS:
            raise UnknownReasonError(
                f"unknown backlog reason {self.reason!r}; the set is CLOSED: {sorted(REASONS)}")
        if self.epoch is not None:
            fr.check_epoch(self.epoch)
        for name in ("eval_report_hash", "parent_frontier_root", "new_frontier_root"):
            value = getattr(self, name)
            if value is not None:
                fr.check_root(value, name)

    @property
    def id(self) -> str:
        return entry_id(self.reason, self.epoch, self.transition_index, self.eval_report_hash,
                        self.subject)

    @property
    def remediation(self) -> str:
        return REASONS[self.reason]

    def as_dict(self) -> Dict[str, Any]:
        """A canonicalizable record: no nulls, no floats, closed keys (V5-A §2 discipline)."""
        out: Dict[str, Any] = {
            "attempts": self.attempts,
            "detail": self.detail,
            "format": BACKLOG_ENTRY_FORMAT,
            "id": self.id,
            "outcome": str(BACKLOG),
            "reason": self.reason,
            "remediation": self.remediation,
            "resolved": self.resolved,
            "stage": self.stage,
        }
        for name in ("epoch", "transition_index", "eval_report_hash", "parent_frontier_root",
                     "new_frontier_root", "miner", "address", "subject", "resolution",
                     "observed_at", "last_detail"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out

    def to_json(self) -> str:
        return fr.canonical_bytes(self.as_dict()).decode("utf-8")


def _entry_from_dict(record: Mapping[str, Any]) -> BacklogEntry:
    entry = BacklogEntry(
        reason=record["reason"], detail=record["detail"], epoch=record.get("epoch"),
        transition_index=record.get("transition_index"),
        eval_report_hash=record.get("eval_report_hash"),
        parent_frontier_root=record.get("parent_frontier_root"),
        new_frontier_root=record.get("new_frontier_root"), miner=record.get("miner"),
        address=record.get("address"), subject=record.get("subject"),
        stage=record.get("stage", ""), attempts=record.get("attempts", 1),
        resolved=bool(record.get("resolved", False)), resolution=record.get("resolution"),
        observed_at=record.get("observed_at"), last_detail=record.get("last_detail"))
    if record.get("id") and record["id"] != entry.id:
        raise JournalError(
            f"journal record id {record['id']} does not recompute from its identity fields "
            f"({entry.id}) — the journal has been edited")
    return entry


# --------------------------------------------------------------------------- #
# In-memory backlog
# --------------------------------------------------------------------------- #
class Backlog:
    """An append-only set of unresolved items. Nothing is ever deleted, only RESOLVED."""

    def __init__(self) -> None:
        self._entries: Dict[str, BacklogEntry] = {}
        self._order: List[str] = []

    # -- reads ---------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: Any) -> bool:
        return str(key) in self._entries

    def get(self, key: str) -> Optional[BacklogEntry]:
        return self._entries.get(key)

    def all_entries(self) -> List[BacklogEntry]:
        return [self._entries[k] for k in self._order]

    def open_entries(self) -> List[BacklogEntry]:
        return [e for e in self.all_entries() if not e.resolved]

    def resolved_entries(self) -> List[BacklogEntry]:
        return [e for e in self.all_entries() if e.resolved]

    def by_reason(self, reason: str) -> List[BacklogEntry]:
        if reason not in REASONS:
            raise UnknownReasonError(f"unknown backlog reason {reason!r}")
        return [e for e in self.all_entries() if e.reason == reason]

    def snapshot(self) -> Dict[str, Any]:
        return {"format": BACKLOG_JOURNAL_FORMAT,
                "entries": [e.as_dict() for e in self.all_entries()],
                "open": len(self.open_entries()), "total": len(self)}

    # -- writes --------------------------------------------------------------
    def record(self, entry: BacklogEntry) -> BacklogEntry:
        """Record (or re-observe) one unresolved item. Returns the stored entry.

        Re-observing a still-open item bumps ``attempts`` and updates ``last_detail`` rather than
        duplicating the row; the FIRST detail is preserved, because it is the evidence of when the
        gap opened. Re-observing a RESOLVED item re-opens it — a resolution that stops holding is
        a regression, not a permanent absolution.
        """
        if not isinstance(entry, BacklogEntry):
            raise BacklogError(f"record takes a BacklogEntry, got {type(entry).__name__}")
        key = entry.id
        prior = self._entries.get(key)
        if prior is None:
            self._entries[key] = entry
            self._order.append(key)
            self._on_write("record", entry)
            return entry
        prior.attempts += 1
        prior.last_detail = entry.detail
        if prior.resolved:
            prior.resolved = False
            prior.resolution = None
        self._on_write("record", prior)
        return prior

    def resolve(self, key: str, note: str = "") -> BacklogEntry:
        """Mark an item resolved. The row STAYS — a drained backlog is auditable, not empty."""
        entry = self._entries.get(str(key))
        if entry is None:
            raise BacklogError(f"no backlog entry {key!r} to resolve")
        entry.resolved = True
        entry.resolution = note or "resolved"
        self._on_write("resolve", entry)
        return entry

    # -- persistence hook ----------------------------------------------------
    def _on_write(self, action: str, entry: BacklogEntry) -> None:
        """Overridden by :class:`FileBacklog`. A no-op in memory."""


class FileBacklog(Backlog):
    """A :class:`Backlog` journaled to an append-only JSONL file.

    Every state change appends one line; the file is never rewritten and never truncated, so the
    only way to lose an entry is to delete the file. :meth:`load` replays the journal in order,
    which makes the file the authority rather than a cache of memory.
    """

    def __init__(self, path: str, *, load: bool = True) -> None:
        super().__init__()
        self.path = path
        self._replaying = False
        if load and os.path.exists(path):
            self.load()

    def load(self) -> "FileBacklog":
        self._entries.clear()
        self._order.clear()
        self._replaying = True
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = fr.parse_json(line)
                    except fr.FrontierError as exc:
                        raise JournalError(f"{self.path}:{lineno}: {exc}") from exc
                    action = record.get("action")
                    body = record.get("entry")
                    if action not in ("record", "resolve") or not isinstance(body, dict):
                        raise JournalError(
                            f"{self.path}:{lineno}: not a backlog journal record")
                    entry = _entry_from_dict(body)
                    key = entry.id
                    if key in self._entries:
                        self._entries[key] = entry
                    else:
                        self._entries[key] = entry
                        self._order.append(key)
        except OSError as exc:
            raise JournalError(f"cannot read backlog journal {self.path}: {exc}") from exc
        finally:
            self._replaying = False
        return self

    def _on_write(self, action: str, entry: BacklogEntry) -> None:
        if self._replaying:
            return
        record = {"action": action, "entry": entry.as_dict(),
                  "format": BACKLOG_JOURNAL_FORMAT}
        line = fr.canonical_bytes(record).decode("utf-8")
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())


# --------------------------------------------------------------------------- #
# Constructors for the named reasons
# --------------------------------------------------------------------------- #
def _entry(reason: str, detail: str, *, event=None, stage: str = "",
           subject: Optional[str] = None, observed_at: Optional[int] = None) -> BacklogEntry:
    kwargs: Dict[str, Any] = {}
    if event is not None:
        kwargs = {"epoch": event.epoch, "transition_index": event.transition_index,
                  "eval_report_hash": event.eval_report_hash,
                  "parent_frontier_root": event.parent_frontier_root,
                  "new_frontier_root": event.new_frontier_root, "miner": event.miner,
                  "address": event.provenance.address}
    return BacklogEntry(reason=reason, detail=detail, stage=stage, subject=subject,
                        observed_at=observed_at, **kwargs)


def missing_artifact(detail: str, *, event=None, subject: Optional[str] = None,
                     stage: str = "artifact", observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(MISSING_ARTIFACT, detail, event=event, stage=stage,
                  subject=subject or (event.eval_report_hash if event is not None else None),
                  observed_at=observed_at)


def unfetchable_manifest(detail: str, *, event=None, subject: Optional[str] = None,
                         stage: str = "parent_manifest",
                         observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(UNFETCHABLE_MANIFEST, detail, event=event, stage=stage, subject=subject,
                  observed_at=observed_at)


def sandbox_unavailable(detail: str, *, event=None, subject: Optional[str] = None,
                        stage: str = "sandbox",
                        observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(SANDBOX_UNAVAILABLE, detail, event=event, stage=stage, subject=subject,
                  observed_at=observed_at)


def oracle_screen_unavailable(detail: str, *, event=None, subject: Optional[str] = None,
                              stage: str = "selection_completeness",
                              observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(ORACLE_SCREEN_UNAVAILABLE, detail, event=event, stage=stage, subject=subject,
                  observed_at=observed_at)


def receipt_unavailable(detail: str, *, event=None, subject: Optional[str] = None,
                        stage: str = "receipt",
                        observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(RECEIPT_UNAVAILABLE, detail, event=event, stage=stage, subject=subject,
                  observed_at=observed_at)


def counter_law_unavailable(detail: str, *, event=None, subject: Optional[str] = None,
                            stage: str = "counter_resource_law",
                            observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(COUNTER_LAW_UNAVAILABLE, detail, event=event, stage=stage, subject=subject,
                  observed_at=observed_at)


def epoch_pins_unavailable(detail: str, *, event=None, subject: Optional[str] = None,
                           stage: str = "epoch_pins",
                           observed_at: Optional[int] = None) -> BacklogEntry:
    return _entry(EPOCH_PINS_UNAVAILABLE, detail, event=event, stage=stage, subject=subject,
                  observed_at=observed_at)
