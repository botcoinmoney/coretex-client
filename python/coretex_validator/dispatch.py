# SPDX-License-Identifier: Apache-2.0
"""Current RigCoreTex wire decoding and descriptor-v3 transition verification.

The shipping registry contains one protocol and the exact deployed event signatures. Unknown
topic0 values are ignored; known events fail closed on malformed ABI encodings. Product state
transitions use immutable descriptor format version 3. The mining epoch commitment/reveal remains
public chain context, but no secret or opening is part of evaluator dispatch.
"""
from __future__ import annotations

from collections import abc
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import frontier as fr
from .keccak256 import keccak256_hex

# --------------------------------------------------------------------------- #
# Protocol identifiers
# --------------------------------------------------------------------------- #
#: The one deployed CoreTex state protocol.
PROTOCOL_RIG = "coretex.rig-state.v1"

PROTOCOLS: Tuple[str, ...] = (PROTOCOL_RIG,)

# --------------------------------------------------------------------------- #
# Canonical event signatures — param TYPES only, indexed params kept in the list
# --------------------------------------------------------------------------- #
# Exact deployed event signatures. Parameter types and order are consensus wire identity.
RIG_STATE_ADVANCED_SIG = (
    "CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "uint256,uint16,bytes)")
#: ``RigCoreTexRegistry.CoreTexEpochFinalized`` — SEVEN fields: the three pins as they stood
#: plus the two closing evidence roots. The stored ``EpochHeader`` is down to
#: ``{patchSetRoot, scoreRoot}``, but THE EVENT IS NOT THE HEADER (spec §2A.4): a log entry is a
#: snapshot at a block, not a second mutable cell, and it cannot drift from anything, so forcing an
#: indexer to issue three ``eth_call``s to learn what one log line already said would be a
#: regression rather than a de-duplication.
RIG_EPOCH_FINALIZED_SIG = (
    "CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)")
#: ``RigCoreTexVerifier.CoreTexEpochContextSet`` — emitted by the VERIFIER, not the registry, and
#: THE THREE PINS. It DOES carry the epoch's head (``parentStateRoot``, which seeds pin 2): in the
#: delegated design the context is where an epoch's starting head is declared.
RIG_EPOCH_CONTEXT_SET_SIG = "CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32)"
#: The mining contract's public epoch clock. These events remain part of the one current rig
#: protocol; their secret never crosses into an evaluator request.
RIG_EPOCH_COMMIT_SET_SIG = "EpochCommitSet(uint64,bytes32)"
RIG_EPOCH_SECRET_REVEALED_SIG = "EpochSecretRevealed(uint64,bytes32)"
#: ``BotcoinMiningRigsV1.sol:165-174`` — source B of the §7 join, and the ONLY log that carries the
#: rig identity. The registry advance deliberately publishes nothing mining already publishes, so
#: `rigId`, `solveIndex`, `receiptHash`, `challengeId` and `workUnitsBps` are reachable only here.
RIG_CREDIT_ACCEPTED_SIG = (
    "RigCoreTexCreditAccepted(uint64,uint256,address,uint64,bytes32,bytes32,uint256,uint256)")


def event_topic(signature: str) -> str:
    """``keccak256(utf8 signature)`` as bare lowercase hex — the topic0 dispatch key.

    Derived from the literal string exactly as ``coretex-registry.ts::eventTopic`` does, so the
    two implementations cannot drift by construction.
    """
    if not isinstance(signature, str) or not signature:
        raise DispatchTypeError("event signature must be a non-empty string")
    return keccak256_hex(signature.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Committed topic0 literals (belt AND braces)
# --------------------------------------------------------------------------- #
#: Current topic0 literals, committed and re-derived at import.
RIG_STATE_ADVANCED_TOPIC0 = "f2b422592475276aa1bbea8c780acec02e5628df6e59392a7ce6625907ca54e7"
RIG_EPOCH_FINALIZED_TOPIC0 = "212234825d6a82269e63c2bc21582948deb7729436c4dcba0dfdd831351c43b2"
RIG_EPOCH_CONTEXT_SET_TOPIC0 = "024a552750f4344a8386eb7109fcbdfd7c822052efcc0cf8c92d0619a3cec80f"
RIG_CREDIT_ACCEPTED_TOPIC0 = "06bc58aa124f2bc6c480b407c83c0acd7f081295aa5d43ee0a9f1f4d52024cfb"
RIG_EPOCH_COMMIT_SET_TOPIC0 = "59292804aa2c2d886e7b2e3982ee2e6df6e3d52f35220fbcafc233d216f7ddf6"
RIG_EPOCH_SECRET_REVEALED_TOPIC0 = "874024d45050fc7f9a2b883212a09399fe2d44dcff11ef6e75782efd2bc22bb6"

#: Event names in the deployed ABI.
EVENT_RIG_STATE_ADVANCED = "CoreTexStateAdvanced"
EVENT_RIG_EPOCH_FINALIZED = "CoreTexEpochFinalized"
EVENT_RIG_EPOCH_CONTEXT_SET = "CoreTexEpochContextSet"
EVENT_RIG_CREDIT_ACCEPTED = "RigCoreTexCreditAccepted"
EVENT_RIG_EPOCH_COMMIT_SET = "EpochCommitSet"
EVENT_RIG_EPOCH_SECRET_REVEALED = "EpochSecretRevealed"

_SIGNATURES: Dict[str, Tuple[str, str, str]] = {
    # topic0 -> (protocol, event name, signature)
    RIG_STATE_ADVANCED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_STATE_ADVANCED, RIG_STATE_ADVANCED_SIG),
    RIG_EPOCH_FINALIZED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_FINALIZED, RIG_EPOCH_FINALIZED_SIG),
    RIG_EPOCH_CONTEXT_SET_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_CONTEXT_SET,
                                   RIG_EPOCH_CONTEXT_SET_SIG),
    RIG_CREDIT_ACCEPTED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_CREDIT_ACCEPTED, RIG_CREDIT_ACCEPTED_SIG),
    RIG_EPOCH_COMMIT_SET_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_COMMIT_SET,
                                  RIG_EPOCH_COMMIT_SET_SIG),
    RIG_EPOCH_SECRET_REVEALED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_SECRET_REVEALED,
                                       RIG_EPOCH_SECRET_REVEALED_SIG),
}

#: Import-time anti-drift: every committed literal MUST be the hash of its committed signature.
for _topic, (_proto, _name, _sig) in _SIGNATURES.items():
    if event_topic(_sig) != _topic:                             # pragma: no cover - fail closed
        raise RuntimeError(
            f"topic0 drift for {_name}: keccak256({_sig!r}) = {event_topic(_sig)}, the committed "
            f"literal is {_topic}. Parameter TYPES (not names) determine topic0; changing them "
            "without cutting a new event name silently corrupts every decoder in the field.")
def protocols_for_topic0(topic0: str) -> Tuple[str, ...]:
    """Every protocol a topic0 may legitimately be emitted under. Usually exactly one."""
    entry = _SIGNATURES.get(topic0)
    if entry is None:
        return ()
    return (entry[0],)


#: Every current event topic used by the registry, verifier, and mining epoch clock.
RIG_TOPICS: Tuple[str, ...] = tuple(sorted(_SIGNATURES))

#: The keccak of each profile id, as the V5 receipt's ``targetProfileId`` renders it on-chain.
PROFILE_ID_HASHES: Dict[str, str] = {pid: keccak256_hex(pid.encode("utf-8"))
                                     for pid in fr.PROFILE_IDS}
PROFILE_BY_ID_HASH: Dict[str, str] = {v: k for k, v in PROFILE_ID_HASHES.items()}

WORD = 32
ZERO_WORD = "0" * 64


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class DispatchError(Exception):
    """Base of every dispatch/decode failure."""


class DispatchTypeError(DispatchError):
    """A log field is absent or wrongly typed."""


class LogDecodeError(DispatchError):
    """A log carries a known topic0 but is not a well-formed encoding of that event."""


class WrongProtocolError(DispatchError):
    """A decoder was handed a log belonging to a different protocol."""


class UnknownDeploymentError(DispatchError):
    """A log came from an address no configured deployment claims."""


class MissingEpochPinsError(DispatchError):
    """No pins are known for an epoch. NEVER substituted with a global default (see module doc)."""


# --------------------------------------------------------------------------- #
# Hex helpers
# --------------------------------------------------------------------------- #
def from_0x(value: Any, field: str) -> bytes:
    """Decode a ``0x``-prefixed (or bare) hex string to bytes, strictly."""
    if not isinstance(value, str):
        raise DispatchTypeError(f"{field} must be a hex string, got {type(value).__name__}")
    text = value[2:] if value[:2] in ("0x", "0X") else value
    if text == "":
        return b""
    if len(text) % 2:
        raise LogDecodeError(f"{field} has an odd number of hex digits ({len(text)})")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise LogDecodeError(f"{field} is not hex: {exc}") from exc


def to_0x(bare: str) -> str:
    """Render a bare-hex root in the Solidity ``bytes32`` form."""
    return "0x" + bare


def _topic(log: Mapping[str, Any], index: int, field: str) -> bytes:
    topics = log.get("topics")
    if not isinstance(topics, (list, tuple)):
        raise DispatchTypeError("log.topics must be a list")
    if index >= len(topics):
        raise LogDecodeError(f"log has {len(topics)} topics; {field} needs topics[{index}]")
    data = from_0x(topics[index], f"topics[{index}]")
    if len(data) != WORD:
        raise LogDecodeError(f"{field}: topics[{index}] is {len(data)} bytes, not 32")
    return data


def _topic_uint(log: Mapping[str, Any], index: int, field: str, *, bits: int) -> int:
    raw = _topic(log, index, field)
    value = int.from_bytes(raw, "big")
    if value >= (1 << bits):
        raise LogDecodeError(
            f"{field}={value} does not fit uint{bits}; the topic carries dirty high bits, so this "
            "is not the event it claims to be")
    return value


def _topic_address(log: Mapping[str, Any], index: int, field: str) -> str:
    raw = _topic(log, index, field)
    if raw[:12] != b"\x00" * 12:
        raise LogDecodeError(
            f"{field}: an address topic must be left-zero-padded to 32 bytes; the high 12 bytes "
            "are non-zero")
    return "0x" + raw[12:].hex()


def _topic_bytes32(log: Mapping[str, Any], index: int, field: str) -> str:
    return _topic(log, index, field).hex()


def _data(log: Mapping[str, Any]) -> bytes:
    raw = from_0x(log.get("data", "0x"), "data")
    if len(raw) % WORD:
        raise LogDecodeError(
            f"log data is {len(raw)} bytes, not a multiple of {WORD}; ABI-encoded event data is "
            "always word-aligned")
    return raw


def _word(data: bytes, i: int, field: str) -> str:
    if (i + 1) * WORD > len(data):
        raise LogDecodeError(f"{field}: data holds {len(data) // WORD} words, need word {i}")
    return data[i * WORD:(i + 1) * WORD].hex()


def _word_uint(data: bytes, i: int, field: str, *, bits: int = 256) -> int:
    value = int.from_bytes(bytes.fromhex(_word(data, i, field)), "big")
    if value >= (1 << bits):
        raise LogDecodeError(f"{field}={value} does not fit uint{bits}")
    return value


def _word_bool(data: bytes, i: int, field: str) -> bool:
    """Decode one ABI word as a CANONICAL bool — 0 or 1 and nothing else.

    Solidity encodes ``bool`` as a full word, and every honest encoder writes exactly 0 or 1. A
    word holding anything else was not produced by ``abi.encode(bool)``, so it is rejected rather
    than truthiness-tested: ``bool(2)`` is ``True`` in Python and would silently launder a
    malformed log into a confident answer. Shared by every bool field in this module so the three
    call sites cannot drift apart on what "canonical" means.
    """
    flag = _word_uint(data, i, field)
    if flag not in (0, 1):
        raise LogDecodeError(f"{field} is {flag}, not a canonical bool")
    return bool(flag)


def _tail_bytes(data: bytes, offset_word: int, head_words: int, field: str) -> bytes:
    """Read the single dynamic ``bytes`` tail, refusing every malformed encoding."""
    offset = _word_uint(data, offset_word, f"{field} offset", bits=64)
    if offset % WORD:
        raise LogDecodeError(f"{field} offset {offset} is not word-aligned")
    if offset < head_words * WORD:
        raise LogDecodeError(
            f"{field} offset {offset} points back into the static head ({head_words} words)")
    if offset + WORD > len(data):
        raise LogDecodeError(f"{field} offset {offset} is past the end of {len(data)} data bytes")
    length = int.from_bytes(data[offset:offset + WORD], "big")
    start = offset + WORD
    if length > len(data) - start:
        raise LogDecodeError(
            f"{field} declares {length} bytes but only {len(data) - start} remain")
    payload = data[start:start + length]
    padded = (length + WORD - 1) // WORD * WORD
    if len(data) - start != padded:
        raise LogDecodeError(
            f"{field}: {len(data) - start} trailing bytes for a {length}-byte payload; the "
            f"canonical ABI padding is {padded}")
    if data[start + length:] != b"\x00" * (padded - length):
        raise LogDecodeError(f"{field}: tail padding is non-zero")
    return payload


# --------------------------------------------------------------------------- #
# Deployments
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Deployment:
    """One deployed contract this validator recognises.

    ``protocol`` is what its logs route to. ``first_epoch`` / ``last_epoch`` bound the epochs the
    deployment is authoritative for; ``last_epoch=None`` means open-ended. A current topic0 from
    any other address or epoch is unrecognised and ignored, never guessed.
    """

    address: str
    protocol: str
    first_epoch: int = 0
    last_epoch: Optional[int] = None
    label: str = ""

    def __post_init__(self) -> None:
        addr = self.address
        if not isinstance(addr, str) or not addr.startswith("0x") or len(addr) != 42:
            raise DispatchTypeError(
                f"deployment address {addr!r} must be a 0x-prefixed 20-byte hex string")
        object.__setattr__(self, "address", addr.lower())
        if self.protocol not in PROTOCOLS:
            raise DispatchTypeError(
                f"unknown protocol {self.protocol!r}; known: {list(PROTOCOLS)}")
        fr.check_epoch(self.first_epoch, "first_epoch")
        if self.last_epoch is not None:
            fr.check_epoch(self.last_epoch, "last_epoch")
            if self.last_epoch < self.first_epoch:
                raise DispatchTypeError(
                    f"deployment {self.address} has last_epoch {self.last_epoch} < first_epoch "
                    f"{self.first_epoch}")

    def covers(self, epoch: int) -> bool:
        if epoch < self.first_epoch:
            return False
        return self.last_epoch is None or epoch <= self.last_epoch


class DeploymentSet:
    """The addresses a validator recognises, and what protocol each speaks."""

    def __init__(self, deployments: Iterable[Deployment] = ()) -> None:
        self._by_address: Dict[str, List[Deployment]] = {}
        for dep in deployments:
            self._by_address.setdefault(dep.address, []).append(dep)

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_address.values())

    @property
    def addresses(self) -> Tuple[str, ...]:
        return tuple(sorted(self._by_address))

    def addresses_for(self, protocol: str) -> Tuple[str, ...]:
        return tuple(sorted(a for a, deps in self._by_address.items()
                            if any(d.protocol == protocol for d in deps)))

    def resolve(self, address: Any, epoch: Optional[int] = None) -> Optional[Deployment]:
        """The deployment claiming ``address`` (at ``epoch``, when supplied), else ``None``."""
        if not isinstance(address, str):
            return None
        for dep in self._by_address.get(address.lower(), ()):
            if epoch is None or dep.covers(epoch):
                return dep
        return None


# --------------------------------------------------------------------------- #
# Classification / routing
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Route:
    """Where one log goes. ``protocol is None`` means IGNORE — never an error."""

    protocol: Optional[str]
    event: Optional[str]
    topic0: Optional[str]
    reason: str
    deployment: Optional[Deployment] = None

    @property
    def recognised(self) -> bool:
        return self.protocol is not None

def classify(log: Mapping[str, Any]) -> Route:
    """Route by topic0 ALONE. An unknown topic0 yields an IGNORE route, never an exception."""
    if not isinstance(log, abc.Mapping):
        raise DispatchTypeError(f"log must be a mapping, got {type(log).__name__}")
    topics = log.get("topics")
    if not isinstance(topics, (list, tuple)) or not topics:
        return Route(None, None, None, "log carries no topics")
    try:
        topic0 = from_0x(topics[0], "topics[0]").hex()
    except DispatchError as exc:
        return Route(None, None, None, f"topics[0] is not a 32-byte hash: {exc}")
    if len(topic0) != 64:
        return Route(None, None, None, f"topics[0] is {len(topic0) // 2} bytes, not 32")
    entry = _SIGNATURES.get(topic0)
    if entry is None:
        return Route(None, None, topic0,
                     f"topic0 {topic0[:12]}… is not a CoreTex event this validator decodes; "
                     "ignored (a new administrative event must never brick a field validator)")
    protocol, name, _sig = entry
    return Route(protocol, name, topic0, f"{name} ({protocol})")


def route(log: Mapping[str, Any], deployments: Optional[DeploymentSet] = None) -> Route:
    """Classify by topic0 AND confirm the emitting deployment speaks that protocol.

    With no :class:`DeploymentSet` this degrades to :func:`classify` — useful for tests and for a
    single-contract log feed, and stated rather than implied. With one, a log from an address the
    set does not claim is IGNORED, and a log whose topic0 protocol disagrees with its address's
    protocol is IGNORED with an explicit reason (it is emphatically not "close enough").
    """
    base = classify(log)
    if deployments is None or not base.recognised:
        return base
    address = log.get("address")
    epoch = None
    if base.event in (EVENT_RIG_STATE_ADVANCED, EVENT_RIG_EPOCH_FINALIZED,
                      EVENT_RIG_EPOCH_CONTEXT_SET, EVENT_RIG_CREDIT_ACCEPTED,
                      EVENT_RIG_EPOCH_COMMIT_SET, EVENT_RIG_EPOCH_SECRET_REVEALED):
        try:
            epoch = _topic_uint(log, 1, "epoch", bits=64)
        except DispatchError:
            epoch = None
    dep = deployments.resolve(address, epoch)
    if dep is None:
        return Route(None, base.event, base.topic0,
                     f"{base.event} from unrecognised address {address!r}"
                     + (f" at epoch {epoch}" if epoch is not None else "") + "; ignored")
    permitted = protocols_for_topic0(base.topic0 or "")
    if dep.protocol not in permitted:
        return Route(None, base.event, base.topic0,
                     f"{base.event} carries a {base.protocol} topic0 but was emitted by "
                     f"{dep.address} which speaks {dep.protocol}; ignored rather than guessed",
                     deployment=dep)
    return Route(dep.protocol, base.event, base.topic0, base.reason, deployment=dep)


# --------------------------------------------------------------------------- #
# Provenance carried alongside every decoded event
# --------------------------------------------------------------------------- #
def _int_field(log: Mapping[str, Any], key: str) -> Optional[int]:
    value = log.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        raise DispatchTypeError(f"log.{key} is a bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value[:2] in ("0x", "0X") else int(value, 10)
        except ValueError as exc:
            raise LogDecodeError(f"log.{key}={value!r} is not an integer: {exc}") from exc
    raise DispatchTypeError(f"log.{key} must be an int or hex string, got {type(value).__name__}")


@dataclass(frozen=True)
class LogProvenance:
    """Where a decoded event was observed. Ordering and confirmation-depth inputs live here."""

    address: Optional[str] = None
    block_number: Optional[int] = None
    log_index: Optional[int] = None
    transaction_hash: Optional[str] = None
    transaction_index: Optional[int] = None
    removed: bool = False

    @property
    def position(self) -> Tuple[int, int]:
        """``(blockNumber, logIndex)`` with absent values sorting last — never silently 0."""
        big = 1 << 62
        return (self.block_number if self.block_number is not None else big,
                self.log_index if self.log_index is not None else big)


def _provenance(log: Mapping[str, Any]) -> LogProvenance:
    address = log.get("address")
    removed = log.get("removed", False)
    if not isinstance(removed, bool):
        raise DispatchTypeError("log.removed must be a bool")
    return LogProvenance(
        address=address.lower() if isinstance(address, str) else None,
        block_number=_int_field(log, "blockNumber"),
        log_index=_int_field(log, "logIndex"),
        transaction_hash=(log.get("transactionHash").lower()
                          if isinstance(log.get("transactionHash"), str) else None),
        transaction_index=_int_field(log, "transactionIndex"),
        removed=removed,
    )


def _require_topic0(log: Mapping[str, Any], expected: str, name: str) -> None:
    got = classify(log)
    if got.topic0 != expected:
        raise WrongProtocolError(
            f"{name} decoder was handed topic0 {got.topic0}, expected {expected} "
            f"({got.reason})")


# --------------------------------------------------------------------------- #
# V5 decoders
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# PUBLIC log-primitive surface
# --------------------------------------------------------------------------- #
#: The word/topic readers above, re-exported under public names.
#:
#: ADDITIVE ONLY — every alias is the same function object, so nothing here can change what any
#: existing decoder does. They exist because the Phase 6 resolver has to decode two events this
#: module deliberately owns no decoder for (``CoreTexEpochFinalized``, and
#: ``BotcoinMiningRigsV1.RigCoreTexCreditAccepted``, which is a MINING event and not a state-lane
#: one). The alternative was a second private copy of these eleven readers in ``v5/resolver``, and
#: a second copy is a second set of edge-case decisions: ``_word_bool``'s canonical-bool refusal and
#: ``_tail_bytes``'s five malformed-encoding refusals are exactly the kind of rule that drifts when
#: it is written twice. One implementation, two callers.
log_data = _data
log_word = _word
log_word_uint = _word_uint
log_word_bool = _word_bool
log_tail_bytes = _tail_bytes
log_topic = _topic
log_topic_uint = _topic_uint
log_topic_address = _topic_address
log_topic_bytes32 = _topic_bytes32
log_provenance = _provenance
require_topic0 = _require_topic0


@dataclass(frozen=True)
class ReplayAdvance:
    """Current canonical transition projected from a confirmed rig descriptor-v3 advance."""

    epoch: int
    transition_index: int
    miner: str
    parent_frontier_root: str
    new_frontier_root: str
    candidate_release_root: str
    composition_root: str
    eval_report_hash: str
    benchmark_law_root: str
    runtime_abi_root: str
    transition_bytes: bytes
    provenance: LogProvenance = LogProvenance()

    @property
    def key(self) -> Tuple[int, int]:
        return (self.epoch, self.transition_index)

    def summary(self) -> Dict[str, Any]:
        """A JSON-safe identity view — what a backlog entry or a report quotes."""
        return {
            "epoch": self.epoch, "transition_index": self.transition_index, "miner": self.miner,
            "parent_frontier_root": self.parent_frontier_root,
            "new_frontier_root": self.new_frontier_root,
            "eval_report_hash": self.eval_report_hash,
            "candidate_release_root": self.candidate_release_root,
            "composition_root": self.composition_root,
            "address": self.provenance.address,
            "block_number": self.provenance.block_number,
            "log_index": self.provenance.log_index,
        }


#: 7 static ``bytes32`` words then the ``bytes`` tail pointer.
_ADVANCE_HEAD_WORDS = 8


@dataclass(frozen=True)
class EpochCommitSet:
    """The epoch entropy COMMITMENT. Both parameters are indexed, so the data section is empty."""

    epoch: int
    epoch_commit: str
    provenance: LogProvenance = LogProvenance()


def decode_epoch_commit_set(log: Mapping[str, Any]) -> EpochCommitSet:
    _require_topic0(log, RIG_EPOCH_COMMIT_SET_TOPIC0, EVENT_RIG_EPOCH_COMMIT_SET)
    if _data(log):
        raise LogDecodeError("EpochCommitSet carries data; both parameters are indexed")
    return EpochCommitSet(epoch=_topic_uint(log, 1, "epochId", bits=64),
                          epoch_commit=_topic_bytes32(log, 2, "epochCommit"),
                          provenance=_provenance(log))


@dataclass(frozen=True)
class EpochSecretRevealed:
    epoch: int
    epoch_secret: str
    provenance: LogProvenance = LogProvenance()


def decode_epoch_secret_revealed(log: Mapping[str, Any]) -> EpochSecretRevealed:
    _require_topic0(log, RIG_EPOCH_SECRET_REVEALED_TOPIC0, EVENT_RIG_EPOCH_SECRET_REVEALED)
    data = _data(log)
    return EpochSecretRevealed(epoch=_topic_uint(log, 1, "epochId", bits=64),
                               epoch_secret=_word(data, 0, "epochSecret"),
                               provenance=_provenance(log))


# --------------------------------------------------------------------------- #
# The RIG path — the deployed RigCoreTexRegistry / RigCoreTexVerifier lane
# --------------------------------------------------------------------------- #
def _topic_uint256(log: Mapping[str, Any], index: int, field: str) -> int:
    """A full-width ``uint256`` indexed parameter. ``rigId`` uses the whole word."""
    return int.from_bytes(_topic(log, index, field), "big")


# ── The transition descriptor: the deployed fixed 97-byte commitment ──────────────────────────
#
# It is exactly 97 bytes in this order, with no padding, optional field, or length prefix:
#
#     [0]        uint8   version            == 0x21
#     [1..33)    bytes32 patchArtifactHash  != 0, sha256 of the COMPLETE canonical patch artifact
#     [33..65)   bytes32 parentStateRoot    == the receipt's signed parentStateRoot
#     [65..97)   bytes32 newStateRoot       == the receipt's signed newStateRoot
#
# The chain commits and orders the transition; the complete canonical transition artifact lives
# off chain at ``patchArtifactHash`` and is replayed deterministically. Check order mirrors the
# deployed verifier: NON-EMPTY -> VERSION -> EXACT LENGTH -> HASH -> FIELDS.

#: ``RigCoreTexVerifier.TRANSITION_DESCRIPTOR_BYTES``. The length IS the format.
TRANSITION_DESCRIPTOR_BYTES = 97
#: ``RigCoreTexVerifier.TRANSITION_DESCRIPTOR_VERSION``. An OPAQUE enumerated tag compared for
#: EQUALITY — never arithmetic, never a range.
TRANSITION_DESCRIPTOR_VERSION = 0x21

#: Field offsets, stated once. Four same-shaped regions transpose without changing a length.
TRANSITION_DESCRIPTOR_VERSION_OFFSET = 0
TRANSITION_DESCRIPTOR_ARTIFACT_OFFSET = 1
TRANSITION_DESCRIPTOR_PARENT_OFFSET = 33
TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET = 65

#: The improvement rule's bounds, enforced by ``_requireStrictImprovement`` over the SIGNED
#: ``scoreBeforePpm``/``scoreAfterPpm`` and by nothing else. The descriptor no longer carries a
#: delta, so these bound the ARTIFACT's ``score_delta_ppm`` and the receipt's own members; they are
#: no longer a wire-format constraint. Kept under these names because the numbers are the same law.
TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM = 1
TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM = 1_000_000

#: THE LIVE RULE — ``RigCoreTexVerifier._validateDescriptorHash``. The label MOVED with the layout
#: (spec §4.2a): 97 bytes with no ``scoreDeltaPpm`` under a label that named a 105-byte layout would
#: be one domain label addressing two different structures, which is the exact condition domain
#: separation exists to forbid. §7.3 had already pre-committed the answer — a new descriptor version
#: takes a new version byte AND a new domain label, so the version is checked twice, once
#: structurally and once cryptographically.
TRANSITION_DESCRIPTOR_HASH_LABEL = b"coretex-transition-descriptor-v3"

TRANSITION_DESCRIPTOR_HASH_RULE = (
    'keccak256(abi.encodePacked("coretex-transition-descriptor-v3", compactPatchBytes))')

#: The canonical patch artifact's family (spec §5.1). It is addressed by
#: ``sha256(canonical_bytes(artifact))`` under the repo's ONE canonical-JSON law, IMPORTED from
#: ``frontier`` and never restated here.
#:
#: THE FAMILY MOVED TO ``v3`` ALONGSIDE THE DESCRIPTOR, and it moved for three reasons at once
#: (spec §5.1): it gains §5.5's sorted dependency-closure declaration
#: (``affected_profiles`` / ``shared_components``), it gains ``epoch_context_root`` — the epoch's
#: pin 3 — and it gains ``byte_length``, which §5.5.4 places in the artifact and NEVER on chain.
#: Its ``score_delta_ppm`` clause now binds the SIGNED receipt members rather than a descriptor
#: field that no longer exists. Three changes to what the document must contain is a format change,
#: and a format change takes a version: a ``coretex.transition-artifact/v2`` document lacks the
#: declaration entirely and is REFUSED here rather than read with defaults.
TRANSITION_ARTIFACT_FORMAT = "coretex.transition-artifact/v3"
#: CLOSED schema. An unknown field is an error, exactly as every other closed family in this repo.
TRANSITION_ARTIFACT_FIELDS: Tuple[str, ...] = (
    "affected_profiles", "availability", "byte_length", "derived_state", "epoch",
    "epoch_context_root", "format", "new_state_root", "parent_state_root", "profile_releases",
    "resulting_composition_root", "resulting_frontier_manifest", "score_delta_ppm",
    "shared_components")
#: The two SORTED, STRICTLY INCREASING declaration lists (spec §5.5.1). BOTH are mandatory: an
#: empty list is written ``[]`` and means "none", and OMISSION IS NOT PERMITTED, because "absent"
#: and "empty" would then be two spellings of one fact — which is precisely what the canonical-JSON
#: law forbids when it rejects ``null``.
TRANSITION_ARTIFACT_CLOSURE_FIELDS: Tuple[str, ...] = ("affected_profiles", "shared_components")
#: One ``profile_releases`` entry (spec §5.1). CLOSED.
TRANSITION_ARTIFACT_RELEASE_FIELDS: Tuple[str, ...] = (
    "expected_prior_release_root", "hooks", "new_release_root")
#: The SIX slot ids a release manifest's ``hooks`` block may name (spec §8, slot layer M1–M6), in
#: write-path-then-read-path order. An absent export gets the reference behaviour, so a miner may
#: improve exactly one slot and still submit — which is why the set is closed but never required.
TRANSITION_ARTIFACT_HOOKS: Tuple[str, ...] = (
    "m1_ingest_transform", "m2_organize", "m3_consolidate",
    "m4_candidates", "m5_rank", "m6_pack")
#: The law pins EVERY mined transition carries forward unchanged (spec §8, T-6). Moving one moves
#: ``coreVersionHash``, which the epoch context pins and the registry equality-checks, so it is an
#: EPOCH-CONTEXT operation performed by ``CORETEX_CONTEXT_OPERATOR`` — never a mined transition, and
#: no descriptor can express it.
TRANSITION_ARTIFACT_LAW_PINS: Tuple[str, ...] = (
    "benchmark_law_root", "runtime_abi_root")


class TransitionDescriptorError(LogDecodeError):
    """A transition descriptor the deployed verifier would have reverted on.

    ``code`` IS THE CONTRACT and is frozen: a negative control that only asserts "something threw"
    passes just as happily when the decoder refuses for the wrong reason.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class TransitionArtifactError(DispatchError):
    """An OFF-CHAIN refusal about the canonical patch artifact the descriptor addresses.

    A separate class from :class:`TransitionDescriptorError` because the two answer different
    questions. A descriptor refusal says "the chain would not have accepted these bytes"; an
    artifact refusal says "the chain accepted the commitment and the thing it commits to is
    unavailable, substituted, non-canonical or does not replay". The chain adjudicates neither of
    the latter — §6.3 names where each is enforced, and REFUSE-DO-NOT-DEGRADE is the rule: "the
    artifact did not mention it" MUST NOT become a way to avoid publishing it, and "we could not
    fetch it" MUST NOT become a way to accept it.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


# ── Descriptor refusal codes — one per ``RigCoreTexVerifier`` revert, in check order ───────────
#: ``InvalidTransitionDescriptor`` — the payload is EMPTY on an outcome that requires a descriptor.
#: Its own code because it is the one thing checked BEFORE the version byte: byte 0 cannot be read
#: at all until there is a byte 0, and "you sent no descriptor" is a different sentence from "you
#: sent the wrong length".
DESCRIPTOR_EMPTY = "DESCRIPTOR_EMPTY"
#: One generic refusal for every version other than the immutable deployed descriptor-v3 wire.
DESCRIPTOR_VERSION_UNSUPPORTED = "DESCRIPTOR_VERSION_UNSUPPORTED"
#: ``InvalidTransitionDescriptor`` — the length is not exactly 97. Checked AFTER the version byte.
DESCRIPTOR_LENGTH_INVALID = "DESCRIPTOR_LENGTH_INVALID"
#: ``TransitionDescriptorHashMismatch`` — these bytes are not a malformed descriptor, they are a
#: DIFFERENT descriptor.
DESCRIPTOR_HASH_MISMATCH = "DESCRIPTOR_HASH_MISMATCH"
#: ``InvalidTransitionDescriptor`` — ``patchArtifactHash == 0``: committed to nothing.
DESCRIPTOR_ARTIFACT_HASH_ZERO = "DESCRIPTOR_ARTIFACT_HASH_ZERO"
#: ``TransitionDescriptorParentMismatch``.
DESCRIPTOR_PARENT_MISMATCH = "DESCRIPTOR_PARENT_MISMATCH"
#: ``TransitionDescriptorNewRootMismatch`` — the committed transition output differs.
DESCRIPTOR_NEW_ROOT_MISMATCH = "DESCRIPTOR_NEW_ROOT_MISMATCH"
#: ``TransitionDescriptorVersionMismatch`` — the SIGNED ``transitionFormatVersion`` (a ``uint16``
#: whose upper byte MUST be zero) is not the descriptor's version byte. The descriptor byte is the
#: authority; the signed member is the binding.
DESCRIPTOR_FORMAT_VERSION_MISMATCH = "DESCRIPTOR_FORMAT_VERSION_MISMATCH"
#: A screener pass advances no state, so it must carry an empty descriptor and zero scores.
DESCRIPTOR_UNEXPECTED = "DESCRIPTOR_UNEXPECTED"
#: A screener pass signs a zero ``patchHash`` because it credits no transition.
SCREENER_PATCH_HASH_NONZERO = "SCREENER_PATCH_HASH_NONZERO"
#: The outcome-2 mirror: a state advance's ``patchHash`` is a keccak output compared for equality
#: against the descriptor, so zero can never match — but ``RigCoreTexVerifier`` states it anyway
#: (``_validateStateAdvanceReceipt``: ``if (r.patchHash == bytes32(0)) revert InvalidCoreTexRoot``)
#: because the earliest true statement about a zero word is "it names no transition", not "the
#: hash did not match".
ADVANCE_PATCH_HASH_ZERO = "ADVANCE_PATCH_HASH_ZERO"

#: The one word that names no transition. A screener signs exactly this; an advance never may.
DESCRIPTOR_ZERO_PATCH_HASH = "00" * 32
DESCRIPTOR_REFUSALS: Tuple[str, ...] = (
    DESCRIPTOR_EMPTY, DESCRIPTOR_VERSION_UNSUPPORTED,
    DESCRIPTOR_LENGTH_INVALID, DESCRIPTOR_HASH_MISMATCH,
    DESCRIPTOR_ARTIFACT_HASH_ZERO, DESCRIPTOR_PARENT_MISMATCH, DESCRIPTOR_NEW_ROOT_MISMATCH,
    DESCRIPTOR_FORMAT_VERSION_MISMATCH, DESCRIPTOR_UNEXPECTED,
    SCREENER_PATCH_HASH_NONZERO, ADVANCE_PATCH_HASH_ZERO)

# ── The SEVEN off-chain refusal codes (spec §6.3), spelled exactly as the spec tables them ─────
TRANSITION_ARTIFACT_UNAVAILABLE = "TRANSITION_ARTIFACT_UNAVAILABLE"
TRANSITION_ARTIFACT_ADDRESS_MISMATCH = "TRANSITION_ARTIFACT_ADDRESS_MISMATCH"
TRANSITION_ARTIFACT_NOT_CANONICAL = "TRANSITION_ARTIFACT_NOT_CANONICAL"
TRANSITION_PARENT_MISMATCH = "TRANSITION_PARENT_MISMATCH"
TRANSITION_REPLAY_ROOT_MISMATCH = "TRANSITION_REPLAY_ROOT_MISMATCH"
TRANSITION_SCORE_DELTA_MISMATCH = "TRANSITION_SCORE_DELTA_MISMATCH"
TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED = "TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED"

#: The seven §6.3 codes, IN THE SPEC'S TABLE ORDER. A validator refuses with one of these and
#: NEVER degrades.
OFFCHAIN_TRANSITION_REFUSALS: Tuple[str, ...] = (
    TRANSITION_ARTIFACT_UNAVAILABLE, TRANSITION_ARTIFACT_ADDRESS_MISMATCH,
    TRANSITION_ARTIFACT_NOT_CANONICAL, TRANSITION_PARENT_MISMATCH,
    TRANSITION_REPLAY_ROOT_MISMATCH, TRANSITION_SCORE_DELTA_MISMATCH,
    TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED)

# ── Three artifact refusals the spec's table does not name, kept typed rather than folded ──────
#: The artifact document is not a well-formed member of its family (wrong ``format``, an absent or
#: unknown closed-schema field, a wrongly-typed value). Distinct from NOT_CANONICAL, which is about
#: the SERIALIZATION of a document that does parse.
TRANSITION_ARTIFACT_MALFORMED = "TRANSITION_ARTIFACT_MALFORMED"
#: A ``profile_releases`` entry's ``expected_prior_release_root`` is not what the parent manifest
#: holds — the candidate was built against another frontier. Its own code because "stale
#: parent" and "replay produced another root" are different facts for an operator.
TRANSITION_RELEASE_PRIOR_MISMATCH = "TRANSITION_RELEASE_PRIOR_MISMATCH"
#: Spec §8 T-6, made enforceable: a law pin moved. That is an EPOCH-CONTEXT operation, not a mined
#: transition, and no descriptor can express it — so it is refused HERE by name rather than
#: surfacing later as an unattributable replay mismatch.
TRANSITION_LAW_PIN_CHANGE = "TRANSITION_LAW_PIN_CHANGE"
#: ``newStateRoot == parentStateRoot``: the artifact expresses no state change and the registry
#: would revert ``NoOpAdvance``.
#:
#: A derived-state-only improvement is
#: STRUCTURALLY expressible but COMMITS NOTHING. ``derived_state`` is carried by the artifact, and
#: the resulting manifest's ``parent_frontier_root`` advances to the parent's root, so the state
#: root does move and this refusal does not fire. But the resulting state is a
#: ``coretex.memory-frontier.v1`` manifest whose schema is CLOSED and has no derived-state field,
#: so two artifacts with completely different ``derived_state`` produce the SAME ``newStateRoot``
#: and replay cannot refute a substituted derived state. Closing that is a FRONTIER-LAW change (a
#: new manifest field plus a version), which is outside this descriptor format.
TRANSITION_NO_OP = "TRANSITION_NO_OP"
#: The artifact's ``epoch_context_root`` is not the epoch's pin 3 (spec §5.1). Its own code because
#: "this artifact was written for a different epoch's admission law" is a different fact from "the
#: parent is wrong" and from "the replay produced another root".
TRANSITION_EPOCH_CONTEXT_MISMATCH = "TRANSITION_EPOCH_CONTEXT_MISMATCH"

# ── The FOUR dependency-closure refusals (spec §5.5.2), one per row of its table ────────────────
#: Either list is absent, is not an array, is not all strings, or is not STRICTLY INCREASING by
#: Unicode code point. A non-increasing list is a REFUSAL and is NEVER sorted on receipt: sorting on
#: receipt would let two byte strings address one artifact, and the artifact is content-addressed.
TRANSITION_CLOSURE_MALFORMED = "TRANSITION_CLOSURE_MALFORMED"
#: ``affected_profiles`` omits a profile the artifact's OWN ``profile_releases`` / composition move
#: touches. The DIRECT half of the rule, derivable from the artifact alone.
TRANSITION_CLOSURE_UNDERDECLARED = "TRANSITION_CLOSURE_UNDERDECLARED"
#: The validator's INDEPENDENTLY-DERIVED closure is not contained in what the coordinator declared.
#: The TRANSITIVE half: a shared-component change implies every profile that references it is
#: re-evaluated, and that fan-out is computed against the PARENT STATE, never taken from the
#: coordinator.
TRANSITION_CLOSURE_MISMATCH = "TRANSITION_CLOSURE_MISMATCH"
#: A declared id is not a profile / component of the parent state. Distinct from MALFORMED because
#: a well-formed list of ids that do not exist is a different defect from a list that is not a list.
TRANSITION_CLOSURE_UNKNOWN_ID = "TRANSITION_CLOSURE_UNKNOWN_ID"

#: The four closure refusals, in the spec's table order.
TRANSITION_CLOSURE_REFUSALS: Tuple[str, ...] = (
    TRANSITION_CLOSURE_MALFORMED, TRANSITION_CLOSURE_UNDERDECLARED, TRANSITION_CLOSURE_MISMATCH,
    TRANSITION_CLOSURE_UNKNOWN_ID)

#: Every artifact-level refusal this module can raise.
TRANSITION_ARTIFACT_REFUSALS: Tuple[str, ...] = OFFCHAIN_TRANSITION_REFUSALS + (
    TRANSITION_ARTIFACT_MALFORMED, TRANSITION_RELEASE_PRIOR_MISMATCH, TRANSITION_LAW_PIN_CHANGE,
    TRANSITION_NO_OP, TRANSITION_EPOCH_CONTEXT_MISMATCH) + TRANSITION_CLOSURE_REFUSALS


def transition_descriptor_hash(descriptor_bytes: bytes) -> str:
    """``patchHash`` — the LABELLED rule the verifier enforces, as bare lowercase hex.

    §4.4 NAMING LAW. ``patchHash`` names EXCLUSIVELY this domain,
    ``keccak256(abi.encodePacked("coretex-transition-descriptor-v3", descriptorBytes))``. The BARE,
    undomained ``keccak256(descriptorBytes)`` is a DIFFERENT value for every input and its name is
    :func:`descriptor_wire_hash` — never ``patchHash``. Two hash domains must never share a name:
    both are 32 bytes, both are "the hash of the patch", and the confusion is silent at the type
    level and surfaces as a hash mismatch three layers away.
    """
    return keccak256_hex(TRANSITION_DESCRIPTOR_HASH_LABEL + bytes(descriptor_bytes))


def descriptor_wire_hash(descriptor_bytes: bytes) -> str:
    """``keccak256(descriptorBytes)`` — BARE, undomained, and NEVER ``patchHash`` (spec §4.4).

    Computed by no production path on this lane. It exists as a NEGATIVE CONTROL and as a diagnosis:
    it is the value a naive reimplementation reaches for first, so naming it lets
    :func:`decode_transition_descriptor` say "you used the undomained rule" instead of "these bytes
    are wrong". The §4.4 rename target is mechanical — any field anywhere that holds this value is
    called ``descriptor_wire_hash`` / ``descriptorWireHash``.
    """
    return keccak256_hex(bytes(descriptor_bytes))


def _hash_mismatch_hint(data: bytes, expected: str) -> str:
    """Diagnose the one common domain error without recognizing another wire format."""
    if descriptor_wire_hash(data) == expected:
        return (" (it matches PLAIN undomained keccak256 of the same bytes — the domain whose name "
                "is `descriptorWireHash`, NEVER `patchHash` (spec §4.4). It is a different value "
                "and belongs to nothing)")
    return ""


@dataclass(frozen=True)
class TransitionDescriptor:
    """A decoded 97-byte transition descriptor. Roots are bare lowercase hex.

    There is no ``score_delta_ppm`` member. The authoritative delta is the signed
    ``scoreAfterPpm - scoreBeforePpm`` and the transition artifact is cross-checked against the
    evaluation artifact.
    """

    version: int
    #: sha256 content address of the COMPLETE canonical patch artifact. Never the eval artifact:
    #: ``artifactHash`` addresses what proves the SCORE, this addresses what defines the STATE
    #: CHANGE, and forcing them equal would forbid separating the two (spec §3.3).
    patch_artifact_hash: str
    parent_state_root: str
    new_state_root: str
    raw: bytes

    def as_dict(self) -> Dict[str, Any]:
        return {"version": self.version,
                "patch_artifact_hash": self.patch_artifact_hash,
                "parent_state_root": self.parent_state_root,
                "new_state_root": self.new_state_root,
                "bytes": len(self.raw)}


def encode_transition_descriptor(*, patch_artifact_hash: str, parent_state_root: str,
                                 new_state_root: str) -> bytes:
    """Build ``compactPatchBytes`` exactly as ``_validateTransitionDescriptor`` reads them back.

    THE ENCODER IS NOT A CONVENIENCE. A coordinator that signs a ``patchHash`` over bytes the
    verifier will not parse mints a receipt that reverts after a miner has already paid to send it,
    and the failure surfaces on chain rather than at pre-sign. Everything written here is re-read by
    :func:`decode_transition_descriptor` before it is returned, so the encoder cannot emit a
    descriptor this module would refuse.

    There is deliberately NO ``version`` parameter. One deployed verifier accepts exactly one
    version (spec §7.2); an encoder that could emit another would be the parser branch that format
    confusion lives in. Adversarial fixtures build a wrong version by MUTATING byte 0, which is what
    a one-field-at-a-time negative control should do anyway.

    THE ``score_delta_ppm`` PARAMETER IS GONE, not defaulted. A caller that still passes one gets a
    ``TypeError`` at the call site, which is the loud failure a silently-ignored keyword would not
    be. The improvement rule is enforced from the signed score members and the artifact carries the
    delta; neither needs the encoder.
    """
    try:
        artifact = fr.check_root(patch_artifact_hash, "patch_artifact_hash")
        parent = fr.check_root(parent_state_root, "parent_state_root")
        new_root = fr.check_root(new_state_root, "new_state_root")
    except fr.FrontierError as exc:
        raise TransitionDescriptorError(DESCRIPTOR_LENGTH_INVALID, str(exc)) from exc
    if artifact == ZERO_WORD:
        raise TransitionDescriptorError(
            DESCRIPTOR_ARTIFACT_HASH_ZERO,
            "patchArtifactHash is zero. A descriptor committing to nothing would be structurally "
            "valid and would advance the head to a root with no addressable derivation — the exact "
            "permanent-replay-failure state the pre-sign gate exists to prevent")
    raw = (bytes([TRANSITION_DESCRIPTOR_VERSION]) + bytes.fromhex(artifact)
           + bytes.fromhex(parent) + bytes.fromhex(new_root))
    decode_transition_descriptor(raw, parent_state_root=parent, new_state_root=new_root)
    return raw


def decode_transition_descriptor(raw: bytes, *, parent_state_root: Optional[str] = None,
                                 new_state_root: Optional[str] = None,
                                 expected_patch_hash: Optional[str] = None,
                                 transition_format_version: Optional[int] = None
                                 ) -> TransitionDescriptor:
    """Decode ``compactPatchBytes`` exactly as ``RigCoreTexVerifier`` validates them.

    The optional arguments are the cross-checks the contract performs against the SIGNED receipt.
    Re-doing them is how a validator confirms the descriptor belongs to THIS advance rather than
    merely being well-formed — including the transition's output root.

    CHECKS RUN IN THE CONTRACT'S ORDER (spec §6.1 rows 4-12), each failure the earliest true
    statement about what is wrong:

        non-empty -> VERSION BYTE -> exact length -> hash -> patchArtifactHash != 0 ->
        parent -> new root -> signed transitionFormatVersion.

    The version byte outranks length and hash so an unsupported format is refused generically
    before its shape is interpreted.
    """
    data = bytes(raw)
    # 4. NON-EMPTY. Byte 0 cannot be read until there is one, and this is the only guard the
    #    version read needs — every read after the exact-length check is in bounds by arithmetic.
    if not data:
        raise TransitionDescriptorError(
            DESCRIPTOR_EMPTY,
            "the descriptor is empty. An EMPTY compactPatchBytes is the SCREENER's invariant "
            "(outcome 1, checked by `check_screener_descriptor`); on a state advance it names no "
            "edge at all and the verifier reverts InvalidTransitionDescriptor")
    # 5-6. THE VERSION BYTE, before the length and before the hash (spec §6.1a).
    version = data[TRANSITION_DESCRIPTOR_VERSION_OFFSET]
    if version != TRANSITION_DESCRIPTOR_VERSION:
        raise TransitionDescriptorError(
            DESCRIPTOR_VERSION_UNSUPPORTED,
            f"descriptor version 0x{version:02x} is not 0x{TRANSITION_DESCRIPTOR_VERSION:02x} — "
            "the deployed verifier accepts exactly one wire format")
    # 7. THE EXACT LENGTH. One legal length and no padding, no optional field and no length prefix.
    if len(data) != TRANSITION_DESCRIPTOR_BYTES:
        raise TransitionDescriptorError(
            DESCRIPTOR_LENGTH_INVALID,
            f"a transition descriptor is EXACTLY {TRANSITION_DESCRIPTOR_BYTES} bytes; this one is "
            f"{len(data)}. The length is the format: there is no padding, no optional field and no "
            "length prefix, so a longer or shorter payload is unsupported")
    # 8. the hash rule. Bytes that do not hash to the signed patchHash are not a malformed
    #    descriptor — they are a DIFFERENT descriptor, and a field-level complaint about them would
    #    describe the wrong object.
    if expected_patch_hash is not None:
        computed = transition_descriptor_hash(data)
        expected = str(expected_patch_hash).lower().removeprefix("0x")
        # 8a. THE OUTCOME-2 MIRROR OF THE SCREENER RULE. A zero `patchHash` can never equal a
        #     keccak output, so this is redundant with the equality below and is stated anyway —
        #     exactly as `_validateStateAdvanceReceipt` states it — because "this word names no
        #     transition" is the earliest TRUE statement about a zero, and a hash-mismatch message
        #     would describe the wrong defect. Zero is the SCREENER's value; on an advance it is a
        #     receipt that credits an edge while committing to none.
        if expected == DESCRIPTOR_ZERO_PATCH_HASH:
            raise TransitionDescriptorError(
                ADVANCE_PATCH_HASH_ZERO,
                f"the receipt signs patchHash bytes32(0) alongside a "
                f"{TRANSITION_DESCRIPTOR_BYTES}-byte descriptor. Zero is the SCREENER value — the "
                "one word that names no transition — and a state advance must name the descriptor "
                "it credits; the verifier reverts InvalidCoreTexRoot")
        if computed != expected:
            raise TransitionDescriptorError(
                DESCRIPTOR_HASH_MISMATCH,
                f"{TRANSITION_DESCRIPTOR_HASH_RULE} is {computed}, the confirmed advance says "
                f"{expected}{_hash_mismatch_hint(data, expected)}")
    # 9. the artifact address must be non-zero.
    artifact_hash = data[TRANSITION_DESCRIPTOR_ARTIFACT_OFFSET:
                         TRANSITION_DESCRIPTOR_PARENT_OFFSET].hex()
    if artifact_hash == ZERO_WORD:
        raise TransitionDescriptorError(
            DESCRIPTOR_ARTIFACT_HASH_ZERO,
            "patchArtifactHash is zero: the descriptor commits to no artifact, so the head would "
            "advance to a root with no addressable derivation")
    parent = data[TRANSITION_DESCRIPTOR_PARENT_OFFSET:TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET].hex()
    new_root = data[TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET:].hex()
    # 10. parent, 11. new root — one at a time, each with its own revert.
    if parent_state_root is not None:
        expected_parent = str(parent_state_root).lower().removeprefix("0x")
        if parent != expected_parent:
            raise TransitionDescriptorError(
                DESCRIPTOR_PARENT_MISMATCH,
                f"the descriptor's parentStateRoot {parent} is not the receipt's {expected_parent}")
    if new_state_root is not None:
        expected_new = str(new_state_root).lower().removeprefix("0x")
        if new_root != expected_new:
            raise TransitionDescriptorError(
                DESCRIPTOR_NEW_ROOT_MISMATCH,
                f"the descriptor's newStateRoot {new_root} is not the receipt's {expected_new}")
    # 12. the SIGNED uint16 must be the zero-extension of the version byte.
    if transition_format_version is not None and int(transition_format_version) != version:
        raise TransitionDescriptorError(
            DESCRIPTOR_FORMAT_VERSION_MISMATCH,
            f"the receipt signs transitionFormatVersion={int(transition_format_version)} but the "
            f"descriptor's version byte is 0x{version:02x}. The descriptor byte is the AUTHORITY; "
            "the signed member is the binding, and its upper byte MUST be zero")
    return TransitionDescriptor(version=version, patch_artifact_hash=artifact_hash,
                                parent_state_root=parent, new_state_root=new_root, raw=data)


def check_screener_descriptor(raw: bytes, *, transition_format_version: Optional[int] = None,
                              score_before_ppm: Optional[int] = None,
                              score_after_ppm: Optional[int] = None,
                              patch_hash: Optional[str] = None) -> None:
    """Outcome 1 carries no descriptor, no patch hash, and zero scores."""
    data = bytes(raw or b"")
    if data:
        raise TransitionDescriptorError(
            DESCRIPTOR_UNEXPECTED,
            f"a screener pass carries {len(data)} descriptor byte(s); outcome 1 advances no state, "
            "so it MUST carry an EMPTY compactPatchBytes")
    for name, value in (("transitionFormatVersion", transition_format_version),
                        ("scoreBeforePpm", score_before_ppm), ("scoreAfterPpm", score_after_ppm)):
        if value is not None and int(value) != 0:
            raise TransitionDescriptorError(
                DESCRIPTOR_UNEXPECTED,
                f"a screener pass signs {name}={int(value)}; outcome 1 requires "
                "transitionFormatVersion, scoreBeforePpm and scoreAfterPpm to all be zero")
    if patch_hash is not None:
        got = str(patch_hash).lower().removeprefix("0x")
        if got != DESCRIPTOR_ZERO_PATCH_HASH:
            raise TransitionDescriptorError(
                SCREENER_PATCH_HASH_NONZERO,
                f"a screener pass signs patchHash 0x{got}; outcome 1 credits NO transition, so it "
                "MUST sign bytes32(0) — the one word that names no transition. The verifier reverts "
                "UnexpectedTransitionDescriptor")


# ── The epochContext MANIFEST (spec §2A) — what pin 3 addresses ────────────────────────────────
#
# ``epochContextRoot`` is pin 3 of the THREE canonical pins, and it is a CONTENT ADDRESS:
# ``sha256(canonical_bytes(manifest))``, rendered as ``bytes32``. It replaced a five-cell epoch
# context whose three pinned values were each pinned THREE separate times — context cell, receipt
# member, registry check, three copies of one fact with no adjudicator between them — and whose
# law roots become chain facts through the same address.
#
# ONE CONTENT ADDRESS FIXES BOTH. A manifest is extensible without a redeployment; a chain cell is
# not, which is exactly why the three law roots never got one.
#
# WHO NEEDS IT. A CONSUMER needs pins 1 and 2 (``coreVersionHash``, ``liveStateRoot``) and nothing
# else — that asymmetry is the reason the pins are three words and not one. A VALIDATOR needs all
# three, because pin 3 is what the epoch ADMITS against.
#
# THE FAIL-CLOSED RULE, spelled here because it is the whole point of the pin:
#
#     A validator that cannot fetch the epochContext manifest MUST REFUSE. It NEVER proceeds on the
#     pin alone.
#
# The pin is 32 bytes; the admission law is the document. "We could not fetch it" must not become a
# way to accept it — the same discipline, and the same read-back, the transition artifact gets at
# §6.3. :func:`verify_epoch_context_bytes` is that rule executed over BYTES SOMEONE SERVED.
#
# WHAT IS DELIBERATELY NOT IN IT (spec §2A.3): the epoch's hidden-seed COMMITMENT WORD. That stays
# at ``mining.epochCommit(epochId)``, set AFTER the context. The ordering is the security property —
# a context authored after the seed commitment could be tuned to a seed its author already knows —
# so the manifest declares the commitment SCHEME and its BINDING RULE, and the word is minted later
# in its own cell. A manifest that carried the word would invert the ordering, so the closed schema
# below has no field for it.
#
# Nor does it repeat selected admission rules as threshold aliases. ``selection_law_root`` binds
# the complete fixed-cap law. Quality may spend more resources than its exact parent inside C,
# while efficiency need not improve utility, so aliases named ``maximum_resource_regression_ppm``
# and ``minimum_utility_improvement_ppm`` would be false public descriptions and a second law
# surface capable of contradicting the addressed law.
#: The epochContext manifest's family. Content-addressed under the repo's ONE canonical-JSON law
#: (``frontier.canonical_bytes``, IMPORTED and never restated), so floats and ``null`` are refused,
#: keys sort by code point, arrays keep their order, and roots are bare lowercase 64-hex.
EPOCH_CONTEXT_FORMAT = "coretex.epoch-context/v1"

#: State inputs carried by the content-addressed epoch context.
EPOCH_CONTEXT_STATE_ROOTS: Tuple[str, ...] = (
    "corpus_root", "active_frontier_root", "baseline_manifest_hash")
#: Law roots carried by that same content-addressed epoch context.
EPOCH_CONTEXT_LAW_ROOTS: Tuple[str, ...] = (
    "benchmark_law_root", "runtime_abi_root", "counter_resource_law_root")
#: Every REQUIRED, NON-ZERO 32-byte root the manifest carries, in one place so the checker walks
#: one list. ``selection_law_root`` is a content address too, not an inline policy object.
EPOCH_CONTEXT_ROOT_FIELDS: Tuple[str, ...] = (
    EPOCH_CONTEXT_STATE_ROOTS + EPOCH_CONTEXT_LAW_ROOTS
    + ("selection_law_root",))

#: CLOSED schema, exactly like every other hashed family here: an unknown field is an error, and a
#: missing one is too. ``[]``-vs-absent ambiguities are what the canonical-JSON law exists to
#: forbid, so nothing below is optional.
#:
#: The complete v1 schema. The producer and validator use these exact names or the root cannot
#: reproduce. ``selection_law_root`` binds the complete admission law; duplicating selected
#: thresholds here would create a second, potentially contradictory public description of that
#: law. ``seed_commitment`` carries the SCHEME and its source, never the epoch's commitment word —
#: see §2A.3 above.
EPOCH_CONTEXT_FIELDS: Tuple[str, ...] = (
    "format", "epoch", "corpus_root", "active_frontier_root", "baseline_manifest_hash",
    "benchmark_law_root", "runtime_abi_root", "counter_resource_law_root",
    "selection_law_root", "seed_commitment")
#: ``seed_commitment``'s exact closed shape: WHAT the scheme is, HOW it binds, and WHERE the later
#: commitment word lives. All three are strings; the word itself has no field in hashed state.
EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS: Tuple[str, ...] = (
    "scheme", "binding_rule", "commitment_source")

#: The manifest is unavailable, unparseable, non-canonical, or does not re-hash to the pin. ONE
#: code, because every one of them ends the same way: the validator does not know what this epoch
#: admits against, and MUST NOT proceed on the pin alone.
EPOCH_CONTEXT_UNAVAILABLE = "EPOCH_CONTEXT_UNAVAILABLE"
#: The bytes ARE at the pin and are canonical, and the document is not a well-formed member of its
#: family (wrong ``format``, an absent or unknown closed-schema field, a wrongly-typed value).
EPOCH_CONTEXT_MALFORMED = "EPOCH_CONTEXT_MALFORMED"
#: The served bytes re-hash to an address other than the epoch's pin 3.
EPOCH_CONTEXT_ADDRESS_MISMATCH = "EPOCH_CONTEXT_ADDRESS_MISMATCH"

EPOCH_CONTEXT_REFUSALS: Tuple[str, ...] = (
    EPOCH_CONTEXT_UNAVAILABLE, EPOCH_CONTEXT_ADDRESS_MISMATCH, EPOCH_CONTEXT_MALFORMED)


class EpochContextError(DispatchError):
    """A refusal about the document at ``epochContextRoot``. ``code`` IS THE CONTRACT.

    Separate from :class:`TransitionArtifactError` because the two answer different questions. A
    transition-artifact refusal says "the edge this advance claims is unavailable or does not
    replay"; an epoch-context refusal says "this validator does not know what the EPOCH admits
    against", which invalidates every advance in the epoch rather than one of them.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def epoch_context_bytes(manifest: Mapping[str, Any]) -> bytes:
    """The canonical bytes an ``epochContextRoot`` addresses. The repo's ONE canonical-JSON law."""
    try:
        return fr.canonical_bytes(manifest)
    except fr.FrontierError as exc:
        raise EpochContextError(
            EPOCH_CONTEXT_UNAVAILABLE,
            f"the epoch context does not canonicalize under the repo's canonical-JSON law: {exc}"
        ) from exc


def epoch_context_root(manifest: Mapping[str, Any]) -> str:
    """``sha256(canonical_bytes(manifest))`` — pin 3, as bare lowercase hex.

    sha256 and not keccak, for the same reason ``patchArtifactHash`` is sha256 (spec §4.3): this is
    how the object is FETCHED, and every object in this system is addressed by sha256. The ``0x``
    form exists only at the Solidity boundary.
    """
    # A malformed document does not acquire legitimacy merely because sha256 is total over bytes.
    # Validate before addressing, matching the coordinator's ``epochContextManifestRoot`` helper.
    return fr.sha256_hex(epoch_context_bytes(validate_epoch_context(manifest)))


def _epoch_context_require(condition: Any, code: str, message: str) -> None:
    if not condition:
        raise EpochContextError(code, message)


def validate_epoch_context(manifest: Any) -> Dict[str, Any]:
    """Structural validation of one ``coretex.epoch-context/v1`` document. CLOSED schema."""
    _epoch_context_require(isinstance(manifest, Mapping), EPOCH_CONTEXT_MALFORMED,
                           f"an epoch context must be an object, got {type(manifest).__name__}")
    _epoch_context_require(
        manifest.get("format") == EPOCH_CONTEXT_FORMAT, EPOCH_CONTEXT_MALFORMED,
        f"format {manifest.get('format')!r} is not {EPOCH_CONTEXT_FORMAT!r}")
    unknown = sorted(set(manifest) - set(EPOCH_CONTEXT_FIELDS))
    _epoch_context_require(not unknown, EPOCH_CONTEXT_MALFORMED,
                           f"unknown field(s) {unknown} — the schema is CLOSED. In particular the "
                           "epoch's hidden-seed COMMITMENT WORD has no field here: it is minted "
                           "AFTER the context at mining.epochCommit(epochId), and folding it in "
                           "would invert the ordering that makes it a security property")
    missing = sorted(set(EPOCH_CONTEXT_FIELDS) - set(manifest))
    _epoch_context_require(not missing, EPOCH_CONTEXT_MALFORMED,
                           f"required field(s) {missing} are absent. Nothing here is optional: an "
                           "epoch admitting against an unstated corpus, law or baseline has no "
                           "closed evaluation identity")
    try:
        fr.check_epoch(manifest["epoch"], "epoch_context.epoch")
        for field in EPOCH_CONTEXT_ROOT_FIELDS:
            root = fr.check_root(manifest[field], f"epoch_context.{field}")
            _epoch_context_require(
                root != "0" * 64, EPOCH_CONTEXT_MALFORMED,
                f"epoch_context.{field} is the all-zero root; every required root must address "
                "a concrete corpus, manifest, or law")
    except fr.FrontierError as exc:
        raise EpochContextError(EPOCH_CONTEXT_MALFORMED, str(exc)) from exc

    seed = manifest["seed_commitment"]
    _epoch_context_require(isinstance(seed, Mapping), EPOCH_CONTEXT_MALFORMED,
                           f"epoch_context.seed_commitment must be an object, got "
                           f"{type(seed).__name__}")
    seed_unknown = sorted(set(seed) - set(EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS))
    _epoch_context_require(not seed_unknown, EPOCH_CONTEXT_MALFORMED,
                           f"epoch_context.seed_commitment has unknown field(s) {seed_unknown}; it "
                           "declares the SCHEME and its BINDING RULE and never the epoch's word")
    seed_missing = sorted(set(EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS) - set(seed))
    _epoch_context_require(not seed_missing, EPOCH_CONTEXT_MALFORMED,
                           f"epoch_context.seed_commitment is missing {seed_missing}")
    for field in EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS:
        _epoch_context_require(isinstance(seed[field], str) and len(seed[field]) > 0,
                               EPOCH_CONTEXT_MALFORMED,
                               f"epoch_context.seed_commitment.{field} must be a non-empty string")
    epoch_context_bytes(manifest)          # fail closed before anyone addresses it
    return dict(manifest)


def verify_epoch_context_bytes(served: bytes, *, expected_root: str) -> Dict[str, Any]:
    """The §2A fail-closed rule over BYTES SOMEONE SERVED. REFUSE, NEVER PROCEED ON THE PIN ALONE.

    ``served`` MUST be what a fetch returned. Rehashing a copy still in local memory proves nothing
    about what a validator will be served — the same reason step 4 of the §6.3 publish discipline is
    the load-bearing one, applied to the other content-addressed document an epoch depends on.

    Returns the validated manifest. Every failure raises :class:`EpochContextError` with one of
    :data:`EPOCH_CONTEXT_REFUSALS`; there is no degraded path that returns the pin.
    """
    try:
        pin = fr.check_root(expected_root, "epoch_context_root")
    except fr.FrontierError as exc:
        raise EpochContextError(EPOCH_CONTEXT_MALFORMED, str(exc)) from exc
    data = bytes(served)
    _epoch_context_require(
        data, EPOCH_CONTEXT_UNAVAILABLE,
        f"nothing is served at epochContextRoot {pin}. The pin is 32 bytes and the admission law "
        "is the document: a validator that cannot fetch it does not know what this epoch admits "
        "against, and MUST refuse rather than proceed on the pin alone")
    served_root = fr.sha256_hex(data)
    _epoch_context_require(
        served_root == pin, EPOCH_CONTEXT_ADDRESS_MISMATCH,
        f"the served bytes re-hash to {served_root}, the epoch pins {pin}")
    try:
        document = fr.parse_json(data.decode("utf-8"))
    except (UnicodeDecodeError, fr.FrontierError) as exc:
        raise EpochContextError(
            EPOCH_CONTEXT_UNAVAILABLE,
            f"the served epoch context is not parseable canonical JSON: {exc}") from exc
    document = validate_epoch_context(document)
    _epoch_context_require(
        epoch_context_bytes(document) == data, EPOCH_CONTEXT_UNAVAILABLE,
        "the served epoch context decodes but RE-SERIALIZES differently; they are not the "
        "canonical byte string this root names")
    return document


# ── The canonical patch artifact (spec §5) ─────────────────────────────────────────────────────
#
# ONE DOCUMENT — the miner's COMPLETE output for one improvement. Not chunked, not truncated, and
# not bounded in size by anything in the specification: the descriptor stays 97 bytes whether the
# artifact is 400 bytes or 40 MB, which is the whole point of addressing it instead of carrying it.
#
# ``canonical_bytes`` is IMPORTED from ``frontier``, never restated: UTF-8 JSON, keys sorted
# ascending by code point, separators ``(",", ":")``, ``ensure_ascii=True``, arrays keep their order
# (order is data), floats REJECTED, ``null`` REJECTED, duplicate keys REJECTED on parse. Roots
# render as BARE lowercase 64-hex — uppercase and ``0x`` are REJECTED, never normalized, because
# normalizing lets two byte strings address one root.
def transition_artifact_bytes(artifact: Mapping[str, Any]) -> bytes:
    """The canonical bytes a ``patchArtifactHash`` addresses. The repo's ONE canonical-JSON law."""
    try:
        return fr.canonical_bytes(artifact)
    except fr.FrontierError as exc:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_NOT_CANONICAL,
            f"the artifact does not canonicalize under the repo's canonical-JSON law: {exc}"
        ) from exc


def transition_artifact_root(artifact: Mapping[str, Any]) -> str:
    """``sha256(canonical_bytes(artifact))`` — the content address, as bare lowercase hex.

    sha256 and NOT keccak, on purpose (spec §4.3): ``patchHash`` is keccak because a Solidity
    verifier compares it as a ``bytes32``; ``patchArtifactHash`` is sha256 because it is how the
    object is FETCHED, and every object in this system is addressed by sha256.
    """
    return fr.sha256_hex(transition_artifact_bytes(artifact))


def _artifact_require(condition: Any, code: str, message: str) -> None:
    if not condition:
        raise TransitionArtifactError(code, message)


def _artifact_root(document: Mapping[str, Any], field: str, where: str) -> str:
    try:
        return fr.check_root(document[field], f"{where}.{field}")
    except KeyError:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED, f"{where}.{field} is absent") from None
    except fr.FrontierError as exc:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED, str(exc)) from exc


def _check_sorted_id_list(artifact: Mapping[str, Any], field: str) -> Tuple[str, ...]:
    """One §5.5.1 declaration list: present, an array of strings, STRICTLY INCREASING.

    Strictly increasing by Unicode code point, which makes duplicates structurally impossible. A
    list that is not is a REFUSAL and is NEVER sorted on receipt: the artifact is content-addressed
    and array order is DATA (§5.2 — arrays keep their order), so sorting on receipt would let two
    byte strings address one artifact. Two miners who declare the same closure must produce the same
    bytes, or the same transition has two addresses.

    Absence is a refusal too, and separately: ``[]`` means "none", and if omission were also legal
    then "absent" and "empty" would be two spellings of one fact — the thing the canonical-JSON law
    already forbids when it rejects ``null``.
    """
    if field not in artifact:
        raise TransitionArtifactError(
            TRANSITION_CLOSURE_MALFORMED,
            f"artifact.{field} is absent. BOTH declaration lists are MANDATORY: an empty list is "
            "written [] and means 'none', and omission is NOT permitted because absent and empty "
            "would then be two spellings of one fact")
    value = artifact[field]
    if not isinstance(value, list):
        raise TransitionArtifactError(
            TRANSITION_CLOSURE_MALFORMED,
            f"artifact.{field} must be an array, got {type(value).__name__}")
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise TransitionArtifactError(
                TRANSITION_CLOSURE_MALFORMED,
                f"artifact.{field}[{index}]={item!r} must be a non-empty string id")
    for index in range(1, len(value)):
        if value[index] <= value[index - 1]:
            raise TransitionArtifactError(
                TRANSITION_CLOSURE_MALFORMED,
                f"artifact.{field} is not STRICTLY INCREASING at index {index}: "
                f"{value[index - 1]!r} then {value[index]!r}. Sorted ascending by Unicode code "
                "point, strictly, so duplicates are structurally impossible — and it is REFUSED "
                "rather than sorted here, because sorting on receipt would let two byte strings "
                "address one artifact")
    return tuple(value)


def validate_transition_artifact(artifact: Any) -> Dict[str, Any]:
    """Structural validation of one ``coretex.transition-artifact/v3`` document. CLOSED schema."""
    _artifact_require(isinstance(artifact, Mapping), TRANSITION_ARTIFACT_MALFORMED,
                      f"a transition artifact must be an object, got "
                      f"{type(artifact).__name__}")
    _artifact_require(artifact.get("format") == TRANSITION_ARTIFACT_FORMAT,
                      TRANSITION_ARTIFACT_MALFORMED,
                      f"format {artifact.get('format')!r} is not {TRANSITION_ARTIFACT_FORMAT!r}. "
                      "A coretex.transition-artifact/v2 document lacks §5.5's dependency-closure "
                      "declaration, epoch_context_root and byte_length entirely; it is REFUSED "
                      "here rather than read with defaults, because defaulting an absent "
                      "declaration is exactly the under-declaration §5.5 exists to catch")
    unknown = sorted(set(artifact) - set(TRANSITION_ARTIFACT_FIELDS))
    _artifact_require(not unknown, TRANSITION_ARTIFACT_MALFORMED,
                      f"unknown field(s) {unknown} — the schema is CLOSED")
    # THE TWO DECLARATION LISTS GET THEIR OWN CODE, AND THEY GET IT FIRST. Folding them into the
    # generic missing-field complaint below would report `TRANSITION_ARTIFACT_MALFORMED` for a
    # condition §5.5.2 gives `TRANSITION_CLOSURE_MALFORMED`, and a negative control asserting the
    # SPECIFIC refusal would then pass on the wrong one.
    for field in TRANSITION_ARTIFACT_CLOSURE_FIELDS:
        _check_sorted_id_list(artifact, field)
    missing = sorted(set(TRANSITION_ARTIFACT_FIELDS) - set(artifact))
    _artifact_require(not missing, TRANSITION_ARTIFACT_MALFORMED,
                      f"required field(s) {missing} are absent")

    _artifact_root(artifact, "parent_state_root", "artifact")
    _artifact_root(artifact, "new_state_root", "artifact")
    _artifact_root(artifact, "resulting_composition_root", "artifact")
    # PIN 3, RESTATED BY THE ARTIFACT. Checked for SHAPE here and for VALUE against the epoch's own
    # pin wherever that pin is in scope (:func:`check_transition_epoch_context`): this function
    # takes no epoch, so it can only refuse a malformed root, never a wrong one.
    _artifact_root(artifact, "epoch_context_root", "artifact")
    # §5.5.4 — the artifact's byte length lives HERE, in the artifact/transition manifest, beside
    # the availability record that already carries {"bytes": N, ...}. It is NEVER a descriptor field
    # and NEVER a chain cell: the chain cannot verify a length it never sees, so a lying length on
    # chain would be a SIGNED assertion with no authority behind it. Here it can be checked against
    # the bytes it describes, which is the only place a length can be checked at all.
    byte_length = artifact["byte_length"]
    _artifact_require(isinstance(byte_length, int) and not isinstance(byte_length, bool)
                      and byte_length > 0,
                      TRANSITION_ARTIFACT_MALFORMED,
                      f"byte_length {byte_length!r} must be a positive int — the length of this "
                      "artifact's own canonical bytes (§5.5.4)")
    delta = artifact["score_delta_ppm"]
    _artifact_require(isinstance(delta, int) and not isinstance(delta, bool)
                      and TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM <= delta
                      <= TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM,
                      TRANSITION_ARTIFACT_MALFORMED,
                      f"score_delta_ppm {delta!r} must be an int in "
                      f"{TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM}.."
                      f"{TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM}")
    try:
        fr.check_epoch(artifact["epoch"], "artifact.epoch")
    except fr.FrontierError as exc:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED, str(exc)) from exc

    releases = artifact["profile_releases"]
    _artifact_require(isinstance(releases, Mapping), TRANSITION_ARTIFACT_MALFORMED,
                      f"profile_releases must be an object, got {type(releases).__name__}")
    # Zero or more entries. Empty is a composition-only change (spec §8, T-4).
    for pid, move in releases.items():
        _artifact_require(pid in fr.PROFILE_IDS, TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}] is not one of {list(fr.PROFILE_IDS)}")
        _artifact_require(isinstance(move, Mapping), TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}] must be an object")
        move_unknown = sorted(set(move) - set(TRANSITION_ARTIFACT_RELEASE_FIELDS))
        _artifact_require(not move_unknown, TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}] has unknown field(s) {move_unknown}")
        move_missing = sorted(set(TRANSITION_ARTIFACT_RELEASE_FIELDS) - set(move))
        _artifact_require(not move_missing, TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}] is missing {move_missing}")
        _artifact_root(move, "expected_prior_release_root", f"profile_releases[{pid!r}]")
        _artifact_root(move, "new_release_root", f"profile_releases[{pid!r}]")
        hooks = move["hooks"]
        _artifact_require(isinstance(hooks, list) and hooks, TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}].hooks must be a non-empty array")
        unknown_hooks = [h for h in hooks if h not in TRANSITION_ARTIFACT_HOOKS]
        _artifact_require(not unknown_hooks, TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}].hooks names {unknown_hooks}, which are not "
                          f"slots; the closed set is {list(TRANSITION_ARTIFACT_HOOKS)}")
        _artifact_require(len(set(hooks)) == len(hooks), TRANSITION_ARTIFACT_MALFORMED,
                          f"profile_releases[{pid!r}].hooks repeats a slot")

    manifest = artifact["resulting_frontier_manifest"]
    try:
        fr.validate_manifest(manifest)
    except fr.FrontierError as exc:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            f"resulting_frontier_manifest is not a valid frontier manifest: {exc}") from exc
    for name in ("derived_state", "availability"):
        _artifact_require(isinstance(artifact[name], Mapping), TRANSITION_ARTIFACT_MALFORMED,
                          f"{name} must be an object, got {type(artifact[name]).__name__}")
    transition_artifact_bytes(artifact)      # fail closed before anyone addresses it
    return dict(artifact)


# ── §5.5.4: the artifact's own byte length, which is a FIXED POINT ─────────────────────────────
#
# ``byte_length`` states the length of the artifact's own canonical bytes, and it is INSIDE those
# bytes, so writing it changes the number it states. That is a fixed point, not a circularity: the
# canonical rendering of an integer has one spelling, so the length is ``C + digits(n)`` for a
# constant ``C``, and iterating converges in one or two steps.
#
# It is solved rather than avoided because the alternative — omitting the field, or letting it mean
# something other than what §5.5.4 says — would put a number in a signed, content-addressed document
# that nobody can check against the thing it describes. A fetcher that bounds a download by this
# value must be able to trust it, and the only place a length CAN be checked is beside the bytes.
#
# THE ONE DEGENERATE CASE IS NAMED AND REFUSED. If ``C`` sits exactly on a power-of-ten boundary the
# equation can have two solutions (e.g. ``C = 9995`` admits both ``9999`` and ``10000``), and two
# solutions means two byte strings for one artifact. :func:`finalize_transition_artifact_byte_length`
# refuses that rather than picking one.
def finalize_transition_artifact_byte_length(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """Return ``artifact`` with ``byte_length`` set to the length of its own canonical bytes.

    The PRODUCER's half of §5.5.4. A validator never calls this — it checks the served bytes against
    the served number (:func:`verify_transition_artifact_bytes`) and refuses a disagreement.
    """
    document = dict(artifact)
    solutions = []
    # Two candidate widths bracket every real case: the length written with the digit count the
    # previous iterate had, and the one it grows into. Both are TRIED, so an ambiguity is DETECTED
    # rather than resolved by iteration order.
    document["byte_length"] = 1
    seed = len(fr.canonical_bytes(document)) - 1              # the constant C
    for digits in range(1, 21):
        candidate = seed + digits
        if len(str(candidate)) != digits:
            continue
        document["byte_length"] = candidate
        if len(fr.canonical_bytes(document)) == candidate:
            solutions.append(candidate)
    if len(solutions) != 1:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            f"byte_length has {len(solutions)} fixed point(s) {solutions} for this artifact. "
            "§5.5.4's length is stated INSIDE the bytes it measures, so it is a fixed point; zero "
            "solutions or two would mean this document has no canonical spelling or two of them, "
            "and it is refused rather than resolved by picking one")
    document["byte_length"] = solutions[0]
    return document


# ── §5.5: the profile / dependency-closure declaration ──────────────────────────────────────────
#
# THE RULE: *a shared component change implies every profile that references it is re-evaluated.*
#
# ``affected_profiles`` is the DECLARATION; the CLOSURE is
# ``affected_profiles ∪ { p : p references some c ∈ shared_components }``, computed against the
# PARENT STATE's composition. The coordinator derives it; the validator derives it AGAIN, from the
# parent state and the artifact, and NEVER from the coordinator.
#
# SUPERSET CHECK, NOT EQUALITY, IN ONE DIRECTION ONLY: the declaration must CONTAIN the derived
# closure. Over-declaring a profile is legal — it costs the miner evaluation, not correctness —
# and under-declaring is fatal. The failure this exists to catch is a shared-component change that
# quietly skips re-evaluating a profile that depends on it, and there is no honest reason to
# under-declare. (Spec §5.5.2 tables this row as "the validator's derived closure ⊅ the
# coordinator's"; the direction implemented here is the one its own prose states twice — *"superset
# check, not equality... over-declaring is legal, under-declaring is fatal"* — i.e. DECLARED ⊇
# DERIVED. Read the other way the row could never fire, because the closure contains the
# declaration by construction.)
#
# WHAT THE CHAIN DOES ABOUT ANY OF THIS: NOTHING, ON PURPOSE (§5.5.3). No parameter, no event field,
# no storage, and explicitly NO on-chain bitmap — a chain-legible scope tag the chain cannot
# corroborate against the artifact is a claim, not a check. The receipt already commits the artifact
# hash, so a substituted declaration is caught by address.
#
# THE COMPONENT VOCABULARY IS NOT DERIVABLE FROM THIS REPO'S PARENT STATE — recorded, not worked
# around. A parent state here is a ``coretex.memory-frontier.v1`` manifest, whose schema is CLOSED
# and carries a ``profiles`` map and NO component registry and NO profile→component reference
# relation. So the profile half of the closure is fully derivable and the SHARED-COMPONENT half is
# not, and adding one would be a FRONTIER-LAW change (a new manifest field plus a version), which
# is outside this descriptor format.
#
# It is therefore FAIL-CLOSED rather than assumed: ``component_references`` is an explicit argument,
# and when a caller has no independent statement of the relation it passes ``None``, which makes the
# component vocabulary EMPTY. An empty ``shared_components`` proceeds (it asserts nothing about a
# vocabulary); a NON-EMPTY one is refused ``TRANSITION_CLOSURE_UNKNOWN_ID`` — never silently
# accepted with an empty fan-out, which would be the under-declaration this rule exists to catch,
# committed by the validator itself.
def derive_transition_closure(parent_manifest: Mapping[str, Any], artifact: Mapping[str, Any], *,
                              component_references: Optional[Mapping[str, Any]] = None
                              ) -> Dict[str, Any]:
    """Derive the dependency closure INDEPENDENTLY, from the parent state and the artifact.

    ``component_references`` maps a shared-component id to the profile ids that reference it, as the
    PARENT state composes them. ``None`` means "this caller has no independent statement of the
    relation", which is not the same as "no component references anything": see the section note
    above for why the difference is a refusal rather than an empty set.

    Returns ``{"direct": frozenset, "closure": frozenset, "components": frozenset}`` — ``direct`` is
    the artifact-only half (what §5.5.2 calls under-declaration when it is omitted), ``closure`` is
    ``direct`` plus the shared-component fan-out.
    """
    profiles = parent_manifest.get("profiles")
    if not isinstance(profiles, Mapping):
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            "the parent manifest carries no `profiles` map, so no closure can be derived against it")
    releases = artifact.get("profile_releases") or {}
    # THE DIRECT HALF, from the artifact alone: one entry per `profile_releases` key.
    #
    # "plus any profile whose composition entry moves" (§5.5.1) is the SAME SET under this repo's
    # frontier law rather than a second one: `frontier.apply_transition` requires
    # `resulting_composition_root != default_composition_root` whenever a release moves, so a
    # release move and a composition-entry move are one event with one profile. The case the law
    # does NOT resolve is T-4 — a composition-only advance with zero `profile_releases`, where the
    # two composition ROOTS differ and nothing in either root says WHICH entries moved. That half
    # is not derivable here and is recorded rather than guessed at; see the section note.
    direct = frozenset(str(pid) for pid in releases)
    components = frozenset(artifact.get("shared_components") or ())
    fanout: set = set()
    if components:
        table = component_references or {}
        for component in sorted(components):
            referencing = table.get(component)
            if referencing is None:
                continue
            fanout.update(str(pid) for pid in referencing)
    return {"direct": direct, "closure": direct | frozenset(fanout), "components": components}


def check_transition_closure(parent_manifest: Mapping[str, Any], artifact: Mapping[str, Any], *,
                             component_references: Optional[Mapping[str, Any]] = None
                             ) -> Dict[str, Any]:
    """The four §5.5.2 refusals, in the spec's table order. Superset check, not equality.

    ``TRANSITION_CLOSURE_MALFORMED`` is already raised by :func:`validate_transition_artifact` — the
    lists have to be well-formed before anything can be derived from them — so this function owns
    the other three.
    """
    declared = tuple(artifact["affected_profiles"])
    components = tuple(artifact["shared_components"])
    known_profiles = frozenset(parent_manifest.get("profiles") or {})
    known_components = frozenset(component_references or {})

    for pid in declared:
        if pid not in known_profiles:
            raise TransitionArtifactError(
                TRANSITION_CLOSURE_UNKNOWN_ID,
                f"affected_profiles names {pid!r}, which is not a profile of the parent state "
                f"({sorted(known_profiles)}). A declaration is checked against the state it claims "
                "to be about, never against a vocabulary it supplies itself")
    for cid in components:
        if cid not in known_components:
            raise TransitionArtifactError(
                TRANSITION_CLOSURE_UNKNOWN_ID,
                f"shared_components names {cid!r}, which is not a component of the parent state "
                f"({sorted(known_components)})."
                + ("" if component_references is not None else
                   " This caller supplied NO component-reference table, so the parent state's "
                   "component vocabulary here is EMPTY: a coretex.memory-frontier.v1 manifest has "
                   "a `profiles` map and no component registry, so the profile→component reference "
                   "relation §5.5.2 computes the fan-out from is not derivable from it. Refusing "
                   "is the fail-closed answer — accepting with an empty fan-out would let a "
                   "shared-component change skip every profile that depends on it, which is "
                   "exactly the under-declaration this rule exists to catch."))

    derived = derive_transition_closure(parent_manifest, artifact,
                                        component_references=component_references)
    declared_set = frozenset(declared)
    # UNDER-DECLARATION first: the DIRECT half is derivable from the artifact alone, so "you did not
    # name a profile your own profile_releases moves" is the earliest true statement and gets the
    # more specific code. It is a subset of the MISMATCH condition below and is checked first for
    # exactly that reason.
    missing_direct = sorted(derived["direct"] - declared_set)
    if missing_direct:
        raise TransitionArtifactError(
            TRANSITION_CLOSURE_UNDERDECLARED,
            f"affected_profiles omits {missing_direct}, which this artifact's own profile_releases "
            f"move. Declared: {list(declared)}")
    missing_closure = sorted(derived["closure"] - declared_set)
    if missing_closure:
        raise TransitionArtifactError(
            TRANSITION_CLOSURE_MISMATCH,
            f"the independently-derived closure is not contained in the declaration: "
            f"{missing_closure} reference a shared component this transition changes "
            f"({list(components)}) and are not declared. A shared-component change implies every "
            "profile that references it is re-evaluated; over-declaring is legal, under-declaring "
            "is fatal")
    return {"declared": declared, "shared_components": components,
            "derived_closure": tuple(sorted(derived["closure"])),
            "over_declared": tuple(sorted(declared_set - derived["closure"]))}


def check_transition_epoch_context(artifact: Mapping[str, Any], *, epoch_context_root_: str) -> str:
    """``artifact.epoch_context_root`` MUST equal the epoch's pin 3 (spec §5.1).

    Its own refusal because "this artifact was written against a different epoch's admission law" is
    a different fact for an operator from a parent mismatch or a replay mismatch, and only one of
    the three is fixed by re-mining against the current head.
    """
    try:
        pin = fr.check_root(epoch_context_root_, "epoch_context_root")
    except fr.FrontierError as exc:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED, str(exc)) from exc
    stated = artifact["epoch_context_root"]
    _artifact_require(stated == pin, TRANSITION_EPOCH_CONTEXT_MISMATCH,
                      f"the artifact states epoch_context_root {stated}, the epoch pins {pin}. Pin "
                      "3 names the corpus, the selection law, the baseline and the thresholds this "
                      "epoch admits against; an artifact naming another one was scored under "
                      "another epoch's law")
    return pin


def check_transition_artifact_self_consistency(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate + check every binding the artifact can check WITHOUT the parent state.

    ``newStateRoot`` is the frontier root of the resulting manifest (spec §5.3), so "deterministic
    replay" is a closed statement rather than an aspiration: the artifact CONTAINS the resulting
    manifest, the root is a pure function of it, and the descriptor commits to the root.
    """
    document = validate_transition_artifact(artifact)
    manifest = document["resulting_frontier_manifest"]
    _artifact_require(manifest["parent_frontier_root"] == document["parent_state_root"],
                      TRANSITION_PARENT_MISMATCH,
                      f"resulting_frontier_manifest.parent_frontier_root "
                      f"{manifest['parent_frontier_root']} is not the artifact's parent_state_root "
                      f"{document['parent_state_root']}")
    _artifact_require(manifest["epoch"] == document["epoch"], TRANSITION_ARTIFACT_MALFORMED,
                      f"resulting_frontier_manifest.epoch {manifest['epoch']} is not the "
                      f"artifact's epoch {document['epoch']}")
    _artifact_require(manifest["default_composition_root"] == document[
                          "resulting_composition_root"],
                      TRANSITION_ARTIFACT_MALFORMED,
                      "resulting_frontier_manifest.default_composition_root disagrees with "
                      "resulting_composition_root; they are one fact published twice")
    _artifact_require(document["new_state_root"] != document["parent_state_root"], TRANSITION_NO_OP,
                      "the artifact's new_state_root equals its parent_state_root, so it expresses "
                      "no state change and the registry would revert NoOpAdvance")
    derived = fr.frontier_root(manifest)
    _artifact_require(derived == document["new_state_root"], TRANSITION_REPLAY_ROOT_MISMATCH,
                      f"the resulting manifest hashes to {derived}, the artifact claims "
                      f"new_state_root {document['new_state_root']}")
    return document


def replay_transition_artifact(parent_manifest: Mapping[str, Any],
                               artifact: Mapping[str, Any], *,
                               component_references: Optional[Mapping[str, Any]] = None,
                               epoch_pins: Optional[Mapping[str, Any]] = None
                               ) -> Dict[str, Any]:
    """DETERMINISTIC REPLAY: ``(parentStateRoot, artifact) -> exactly one resulting manifest``.

    THE ARTIFACT PLUS THE PARENT STATE IS THE AUTHORITY; THE CHAIN IS THE CLOCK (spec §5.4). This
    is a PURE FUNCTION. It takes no input from the transaction, the block, the miner's identity, the
    wall clock or any unpinned network resource, so two honest validators replaying the same pair
    MUST agree — and disagreeing with the descriptor's ``newStateRoot`` is a PUBLICLY PROVABLE
    refutation requiring nothing but chain data and the addressed bytes.

    ``epoch_pins`` is the independently resolved current epoch context. When supplied it must name
    this artifact's exact epoch and
    ``epoch_context_root`` as well as both frontier law pins.  That lets the first advance of a new
    epoch adopt a law already committed by ``CORETEX_CONTEXT_OPERATOR`` without giving a mined
    transition any authority to choose that law.  A parent from the same epoch may never differ
    from those pins, and every field the epoch context does not own remains immutable.

    Breadth is UNBOUNDED and safe without a ceiling (spec §8.1). What constrains the edge is not a
    size limit: the parent must be the exact current head (registry CAS), the resulting root must be
    reproducible from that head and the addressed artifact, and the score delta must be attested by
    the evaluation artifact. A broad transition is neither more likely to be accepted than a narrow
    one nor less refutable.
    """
    document = check_transition_artifact_self_consistency(artifact)
    try:
        fr.validate_manifest(parent_manifest)
        parent_root = fr.frontier_root(parent_manifest)
    except fr.FrontierError as exc:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            f"the parent manifest is not a valid frontier manifest: {exc}") from exc
    _artifact_require(parent_root == document["parent_state_root"], TRANSITION_PARENT_MISMATCH,
                      f"the supplied parent manifest hashes to {parent_root}, the artifact commits "
                      f"to parent_state_root {document['parent_state_root']}")

    pinned: Optional[Dict[str, Any]] = None
    if epoch_pins is not None:
        _artifact_require(isinstance(epoch_pins, Mapping), TRANSITION_ARTIFACT_MALFORMED,
                          "epoch_pins must be an independently resolved epoch-context mapping")
        try:
            pinned_epoch = fr.check_epoch(epoch_pins.get("epoch"), "epoch_pins.epoch")
            pinned_context_root = fr.check_root(
                epoch_pins.get("epoch_context_root"), "epoch_pins.epoch_context_root")
            pinned = {
                "epoch": pinned_epoch,
                "epoch_context_root": pinned_context_root,
                **{
                    field: fr.check_root(epoch_pins.get(field), f"epoch_pins.{field}")
                    for field in fr.EPOCH_PINNED_MANIFEST_FIELDS
                },
            }
        except fr.FrontierError as exc:
            raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED, str(exc)) from exc
        _artifact_require(
            pinned["epoch"] == document["epoch"], TRANSITION_EPOCH_CONTEXT_MISMATCH,
            f"the resolved epoch context is for epoch {pinned['epoch']}, the artifact is for "
            f"epoch {document['epoch']}")
        _artifact_require(
            pinned["epoch_context_root"] == document["epoch_context_root"],
            TRANSITION_EPOCH_CONTEXT_MISMATCH,
            f"the resolved epoch context root is {pinned['epoch_context_root']}, the artifact "
            f"binds {document['epoch_context_root']}")

    # §5.5 — THE CLOSURE IS DERIVED HERE, because here is the first point the PARENT STATE is in
    # scope, and the parent state is what the closure is computed against. A validator reaching this
    # line has fetched the artifact by address and the parent by root; it derives the closure again
    # from those two and never from the coordinator that wrote the declaration.
    check_transition_closure(parent_manifest, document,
                             component_references=component_references)

    profiles = dict(parent_manifest["profiles"])
    for pid, move in document["profile_releases"].items():
        _artifact_require(profiles[pid] == move["expected_prior_release_root"],
                          TRANSITION_RELEASE_PRIOR_MISMATCH,
                          f"profile_releases[{pid!r}].expected_prior_release_root "
                          f"{move['expected_prior_release_root']} is not the parent's "
                          f"{profiles[pid]}; the candidate was built against a different frontier")
        profiles[pid] = move["new_release_root"]

    replayed = dict(parent_manifest)
    replayed["epoch"] = document["epoch"]
    replayed["parent_frontier_root"] = parent_root
    replayed["profiles"] = profiles
    replayed["default_composition_root"] = document["resulting_composition_root"]

    # A parent from an EARLIER epoch is the lazily inherited head. It may carry the prior epoch's
    # pins, but the child must adopt the CURRENT pins supplied above. A same-epoch parent is already
    # under the current context, so a mismatch there is always a mined law change and remains T-6.
    # This mirrors frontier.apply_transition(epoch_pins=...) exactly.
    stated = document["resulting_frontier_manifest"]
    inherited = document["epoch"] > parent_manifest["epoch"]
    _artifact_require(document["epoch"] >= parent_manifest["epoch"],
                      TRANSITION_ARTIFACT_MALFORMED,
                      f"the artifact regresses epoch {parent_manifest['epoch']} to "
                      f"{document['epoch']}")
    if pinned is not None:
        for pin in fr.EPOCH_PINNED_MANIFEST_FIELDS:
            expected = pinned[pin]
            parent_value = parent_manifest.get(pin)
            _artifact_require(
                stated.get(pin) == expected, TRANSITION_LAW_PIN_CHANGE,
                f"the artifact's resulting manifest states law pin {pin!r}="
                f"{stated.get(pin)!r}, but the independently resolved epoch context pins "
                f"{expected!r}. A transition may adopt the epoch's law; it may not choose one "
                "(spec §8, T-6)")
            _artifact_require(
                parent_value == expected or inherited, TRANSITION_LAW_PIN_CHANGE,
                f"the same-epoch parent states law pin {pin!r}={parent_value!r}, while the epoch "
                f"pins {expected!r}. Only an inherited head from an EARLIER epoch may differ; "
                "otherwise this is a mined law change (spec §8, T-6)")
            replayed[pin] = expected

    else:
        # A pure same-format replay without a separately resolved context carries both public state
        # pins forward. Shipped chain replay supplies the confirmed epoch context above.
        for pin in TRANSITION_ARTIFACT_LAW_PINS:
            if pin in replayed or pin in stated:
                _artifact_require(
                    stated.get(pin) == replayed.get(pin), TRANSITION_LAW_PIN_CHANGE,
                    f"the artifact's resulting manifest moves the law pin {pin!r} from "
                    f"{replayed.get(pin)!r} to {stated.get(pin)!r}. No independently resolved "
                    "epoch pins authorize this edge, so law pins must be carried forward "
                    "unchanged (spec §8, T-6)")

    replayed_root = fr.frontier_root(replayed)
    _artifact_require(replayed_root == document["new_state_root"], TRANSITION_REPLAY_ROOT_MISMATCH,
                      f"replaying (parentStateRoot {parent_root}, artifact) produces "
                      f"{replayed_root}; the descriptor commits to {document['new_state_root']}. "
                      "The chain does not adjudicate this — a disagreement here is a publicly "
                      "provable refutation")
    # The edge-level no-op was already refused by `check_transition_artifact_self_consistency`
    # above. Re-checked here as a fail-closed statement rather than an assumption: a replay that
    # reproduced the parent root would mean the manifest hashed to a value it contains, which is
    # not reachable, and "not reachable" is exactly the kind of claim that should be checked.
    _artifact_require(replayed_root != parent_root, TRANSITION_NO_OP,  # pragma: no cover
                      "the replay reproduces the parent root exactly")
    return replayed


def verify_transition_artifact_bytes(served: bytes, *, descriptor: TransitionDescriptor,
                                     score_delta_ppm: Optional[int] = None,
                                     epoch_context_root_: Optional[str] = None) -> Dict[str, Any]:
    """The §6.3 validator rule over BYTES SOMEONE SERVED, in the spec's table order.

    ``served`` MUST be what a fetch returned. Rehashing a copy still in local memory proves nothing
    about what a validator will be served, which is the entire reason step 4 of the publish
    discipline is load-bearing.

    ``score_delta_ppm`` IS NOW THE ONLY SOURCE OF THE DELTA CROSS-CHECK, and that is the change. The
    descriptor used to carry a copy and the artifact was compared to it; that copy is gone (spec
    §3.1a), so the comparison is against what the caller supplies — the SIGNED
    ``scoreAfterPpm - scoreBeforePpm``, or the evaluation artifact's attested delta. Nothing was
    lost: the descriptor's copy was unsigned and could only ever disagree with the signed members,
    while ``TRANSITION_SCORE_DELTA_MISMATCH`` still binds the artifact to the evidence.

    ``epoch_context_root_`` is the epoch's pin 3. It is optional in the SIGNATURE only: a validator
    that has resolved the epoch's context passes it, and one that has not cannot claim to have
    checked §5.1's ``epoch_context_root`` clause.
    """
    if descriptor.version != TRANSITION_DESCRIPTOR_VERSION:      # pragma: no cover - fail closed
        raise TransitionArtifactError(
            TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED,
            f"descriptor version 0x{descriptor.version:02x} is not one this validator implements "
            f"(0x{TRANSITION_DESCRIPTOR_VERSION:02x})")
    data = bytes(served)
    _artifact_require(data, TRANSITION_ARTIFACT_UNAVAILABLE,
                      f"nothing is served at patchArtifactHash {descriptor.patch_artifact_hash}")
    served_root = fr.sha256_hex(data)
    _artifact_require(served_root == descriptor.patch_artifact_hash,
                      TRANSITION_ARTIFACT_ADDRESS_MISMATCH,
                      f"the served bytes re-hash to {served_root}, the descriptor addresses "
                      f"{descriptor.patch_artifact_hash}")
    try:
        document = fr.parse_json(data.decode("utf-8"))
    except (UnicodeDecodeError, fr.FrontierError) as exc:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_NOT_CANONICAL,
            f"the served bytes are not parseable canonical JSON: {exc}") from exc
    document = validate_transition_artifact(document)
    _artifact_require(transition_artifact_bytes(document) == data,
                      TRANSITION_ARTIFACT_NOT_CANONICAL,
                      "the served bytes decode but RE-SERIALIZE differently; they are not the "
                      "canonical byte string this root names")
    # §5.5.4 — the declared length against THE BYTES THAT WERE SERVED. This is the only place the
    # two can be compared, which is precisely why the length belongs here and never on chain: the
    # chain never sees the artifact, so a length there would be a signed assertion with nothing
    # behind it.
    _artifact_require(document["byte_length"] == len(data), TRANSITION_ARTIFACT_MALFORMED,
                      f"artifact.byte_length {document['byte_length']} is not the served length "
                      f"{len(data)}")
    _artifact_require(document["parent_state_root"] == descriptor.parent_state_root,
                      TRANSITION_PARENT_MISMATCH,
                      f"artifact.parent_state_root {document['parent_state_root']} is not the "
                      f"descriptor's {descriptor.parent_state_root}")
    _artifact_require(document["new_state_root"] == descriptor.new_state_root,
                      TRANSITION_REPLAY_ROOT_MISMATCH,
                      f"artifact.new_state_root {document['new_state_root']} is not the "
                      f"descriptor's {descriptor.new_state_root}")
    if score_delta_ppm is not None:
        _artifact_require(document["score_delta_ppm"] == int(score_delta_ppm),
                          TRANSITION_SCORE_DELTA_MISMATCH,
                          f"artifact.score_delta_ppm {document['score_delta_ppm']} is not the "
                          f"{int(score_delta_ppm)} ppm the evaluation attests. The descriptor no "
                          "longer carries a copy to compare against (spec §3.1a); the SIGNED score "
                          "members and the evaluation artifact are the authority, and this is the "
                          "off-chain check that was never on chain to lose")
    if epoch_context_root_ is not None:
        check_transition_epoch_context(document, epoch_context_root_=epoch_context_root_)
    check_transition_artifact_self_consistency(document)
    return document


# ── A. the registry's confirmed state advance ─────────────────────────────────
#: The ONLY route a deployed rig advance can have. See :attr:`RigStateAdvanced.route`.
RIG_ROUTE_TYPED = "typed-submitStateAdvance"


@dataclass(frozen=True)
class RigStateAdvanced:
    """A confirmed rig ``CoreTexStateAdvanced`` — TWELVE fields. Roots are bare lowercase hex.

    Values absent from this event are resolved from their actual authorities:

      * ``rigId`` — on ``RigCoreTexCreditAccepted`` (:class:`RigCreditAccepted`), same transaction.
      * ``artifactHash`` — signed member 14 of the receipt, and not reconstructible from this log.
        The descriptor's ``patchArtifactHash`` addresses the canonical patch artifact; release
        roots are read from that fetched artifact.
      * ``workPolicyHash`` — signed member 17; enforced by the VERIFIER against its scheduled
        policy, never by the registry.
      * ``corpusRoot`` / ``activeFrontierRoot`` — NOT chain values at all any more. They are fields
        of the epochContext MANIFEST addressed by ``epoch_context_root``, and a validator reads them
        from that document (:func:`verify_epoch_context_bytes`) rather than from a log.

    It DOES carry ``compactPatchBytes`` verbatim — the ABI member keeps its name and position for
    tuple compatibility while its CONTENT is now the 97-byte transition descriptor. The registry
    pays that gas so the commitment is readable from logs alone, with no archive node, which is what
    makes the ``patchHash`` self-check possible without calldata. It does NOT make the EDIT readable
    from logs alone: that lives off chain, at ``patchArtifactHash``, by design.

    ``transition_format_version`` is the event's ``uint16`` descriptor discriminator.
    """

    epoch: int
    transition_index: int
    miner: str
    parent_state_root: str
    new_state_root: str
    patch_hash: str
    eval_report_hash: str
    core_version_hash: str
    epoch_context_root: str
    improvement_credits: int
    transition_format_version: int
    compact_patch_bytes: bytes
    provenance: LogProvenance = LogProvenance()

    @property
    def route(self) -> str:
        """The registry's sole typed advance entry point."""
        return RIG_ROUTE_TYPED

    @property
    def key(self) -> Tuple[int, int]:
        """The ORDINAL key. Unique within an epoch because the registry assigns the index."""
        return (self.epoch, self.transition_index)

    @property
    def primary_key(self) -> Tuple[int, str, str]:
        """Design §7.4's primary key: ``(epoch, parentStateRoot, patchHash)`` — all three.

        ``(epoch, parentStateRoot)`` is NOT unique: the only self-referential rule on the advance
        path is ``newStateRoot != parentStateRoot``, so a head may legally CYCLE (``P -> A -> P ->
        C``) and ``P`` occurs as a parent twice. Uniqueness comes entirely from the verifier's
        ``coreTexPatchCredited[epoch][parent][patchHash]`` guard.
        """
        return (self.epoch, self.parent_state_root, self.patch_hash)

    def descriptor(self) -> TransitionDescriptor:
        """The decoded descriptor, cross-checked against this event's OWN four published facts.

        Self-verifying, and now over the whole edge: the log carries the bytes, their hash, BOTH
        roots and the format version, so parent, new root and version are all re-checked here
        against values the same log published. The score delta is not — no advance log carries the
        receipt's score members — so it is checked where they exist, against the signed receipt and
        the evaluation artifact.
        """
        return decode_transition_descriptor(
            self.compact_patch_bytes,
            parent_state_root=self.parent_state_root,
            new_state_root=self.new_state_root,
            expected_patch_hash=self.patch_hash,
            transition_format_version=self.transition_format_version)

    def summary(self) -> Dict[str, Any]:
        """A JSON-safe identity view. Wide integers render as STRINGS."""
        return {
            "epoch": self.epoch, "transition_index": self.transition_index,
            "miner": self.miner,
            "parent_state_root": self.parent_state_root,
            "new_state_root": self.new_state_root,
            "eval_report_hash": self.eval_report_hash,
            "patch_hash": self.patch_hash,
            "core_version_hash": self.core_version_hash,
            "epoch_context_root": self.epoch_context_root,
            "improvement_credits": str(self.improvement_credits),
            "transition_format_version": self.transition_format_version,
            "route": self.route,
            "compact_patch_bytes": "0x" + self.compact_patch_bytes.hex(),
            "address": self.provenance.address,
            "block_number": self.provenance.block_number,
            "log_index": self.provenance.log_index,
        }


#: The rig advance's static head: 6 ``bytes32`` + ``improvementCredits`` (uint256) +
#: ``transitionFormatVersion`` (uint16), then the ``bytes`` tail pointer = words 0..8.
#:
_RIG_ADVANCE_HEAD_WORDS = 9


def decode_rig_state_advanced(log: Mapping[str, Any]) -> RigStateAdvanced:
    """Decode the deployed rig advance word layout."""
    _require_topic0(log, RIG_STATE_ADVANCED_TOPIC0, EVENT_RIG_STATE_ADVANCED)
    data = _data(log)
    return RigStateAdvanced(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        transition_index=_topic_uint(log, 2, "transitionIndex", bits=64),
        miner=_topic_address(log, 3, "miner"),
        parent_state_root=_word(data, 0, "parentStateRoot"),
        new_state_root=_word(data, 1, "newStateRoot"),
        patch_hash=_word(data, 2, "patchHash"),
        eval_report_hash=_word(data, 3, "evalReportHash"),
        core_version_hash=_word(data, 4, "coreVersionHash"),
        epoch_context_root=_word(data, 5, "epochContextRoot"),
        improvement_credits=_word_uint(data, 6, "improvementCredits"),
        transition_format_version=_word_uint(data, 7, "transitionFormatVersion", bits=16),
        compact_patch_bytes=_tail_bytes(data, 8, _RIG_ADVANCE_HEAD_WORDS, "compactPatchBytes"),
        provenance=_provenance(log),
    )


# ── B. the mining contract's credit acceptance ────────────────────────────────
@dataclass(frozen=True)
class RigCreditAccepted:
    """One confirmed ``RigCoreTexCreditAccepted`` — the ONLY log carrying the rig identity.

    The registry advance deliberately publishes nothing mining already publishes (design §7.3), so
    a validator that wants ``rigId`` joins these two by transaction. ``receipt_hash`` is the
    load-bearing one: it is the hash a resolver recomputes from calldata to prove that calldata IS
    this receipt.
    """

    epoch: int
    rig_id: int
    operator: str
    solve_index: int
    receipt_hash: str
    challenge_id: str
    work_units_bps: int
    credits_earned: int
    provenance: LogProvenance = LogProvenance()

    def summary(self) -> Dict[str, Any]:
        return {"epoch": self.epoch, "rig_id": str(self.rig_id), "operator": self.operator,
                "solve_index": self.solve_index, "receipt_hash": self.receipt_hash,
                "challenge_id": self.challenge_id,
                "work_units_bps": str(self.work_units_bps),
                "credits_earned": str(self.credits_earned)}


def decode_rig_credit_accepted(log: Mapping[str, Any]) -> RigCreditAccepted:
    """Three indexed topics (epochId, rigId, operator), four static data words."""
    _require_topic0(log, RIG_CREDIT_ACCEPTED_TOPIC0, EVENT_RIG_CREDIT_ACCEPTED)
    data = _data(log)
    return RigCreditAccepted(
        epoch=_topic_uint(log, 1, "epochId", bits=64),
        rig_id=_topic_uint256(log, 2, "rigId"),
        operator=_topic_address(log, 3, "operator"),
        solve_index=_word_uint(data, 0, "solveIndex", bits=64),
        receipt_hash=_word(data, 1, "receiptHash"),
        challenge_id=_word(data, 2, "challengeId"),
        work_units_bps=_word_uint(data, 3, "workUnitsBps"),
        credits_earned=_word_uint(data, 4, "creditsEarned"),
        provenance=_provenance(log),
    )


# ── C. the verifier's epoch context ───────────────────────────────────────────
#: The rig epoch context's THREE words, in ``IRigCoreTexVerifier.CoreTexEpochContext``'s DECLARED
#: order. Same-typed words transpose without changing a selector or a topic0, so the order is
#: stated ONCE and consumed by the context decoder, the finalization decoder and the pin set.
#:
#: THREE, NOT FIVE (spec §2A). ``corpus_root``, ``active_frontier_root`` and
#: ``baseline_manifest_hash`` left this struct: they are FIELDS OF THE MANIFEST at
#: ``epoch_context_root`` now, not chain cells. Each of the three used to be pinned three separate
#: times — context cell, receipt member, registry check — three copies of one fact with no
#: adjudicator between them; one content address replaces all nine copies, and it carries the three
#: LAW roots that had no chain slot at all besides.
#:
#: ``parent_state_root`` IS a pin here, which reverses the memory lane's §17.237 rule rather than
#: forgetting it. In the delegated design the CONTEXT is where an epoch's starting head is
#: declared — the registry has no context struct of its own and derives nothing — so the head is
#: exactly as public and as frozen as the law pins, and the resolver's off-chain continuity walk
#: (design §11 gap 1) is what checks that the operator declared the right one. It SEEDS pin 2
#: (``liveStateRoot``) and is not itself pin 2: the registry's CAS advances the live root away from
#: it after the epoch's first transition.
#:
#: ``work_policy_hash`` and ``hidden_seed_commit`` were pins on the STAGED registry's six-member
#: context and are NOT here, because the deployed context event does not carry them: the work
#: policy is scheduled on the verifier (``CoreTexPolicyScheduled``) and re-checked per receipt, and
#: the hidden seed is the mining contract's ``EpochCommitSet`` (carried separately as
#: ``entropy_commitment``). The hidden seed's ABSENCE is now load-bearing rather than incidental:
#: it is set AFTER the context, and §2A.3 keeps it out of the manifest for the same reason — a
#: context authored after the seed commitment could be tuned to a seed its author already knows.
RIG_EPOCH_CONTEXT_PINS: Tuple[str, ...] = (
    "parent_state_root", "epoch_context_root", "core_version_hash")


@dataclass(frozen=True)
class RigEpochContextSet:
    """The verifier's epoch context: the THREE canonical pins, published together.

    ``epoch_context_root`` is pin 3 and is a CONTENT ADDRESS, not a value: the corpus root, the
    active frontier root, the baseline manifest hash and the three law roots are inside the document
    it names (:func:`verify_epoch_context_bytes`). A consumer needs pins 1 and 2 and can ignore this
    one; a VALIDATOR needs all three and MUST fetch the manifest rather than proceed on the pin.
    """

    epoch: int
    parent_state_root: str
    epoch_context_root: str
    core_version_hash: str
    provenance: LogProvenance = LogProvenance()

    def pins(self) -> Dict[str, str]:
        return {name: getattr(self, name) for name in RIG_EPOCH_CONTEXT_PINS}


def decode_rig_epoch_context_set(log: Mapping[str, Any]) -> RigEpochContextSet:
    """Decode the verifier's ``CoreTexEpochContextSet``. Three static ``bytes32``; nothing dynamic."""
    _require_topic0(log, RIG_EPOCH_CONTEXT_SET_TOPIC0, EVENT_RIG_EPOCH_CONTEXT_SET)
    data = _data(log)
    values = {name: _word(data, index, name)
              for index, name in enumerate(RIG_EPOCH_CONTEXT_PINS)}
    return RigEpochContextSet(epoch=_topic_uint(log, 1, "epochId", bits=64),
                              provenance=_provenance(log), **values)


# ── D. the registry's seal ────────────────────────────────────────────────────
#: ``CoreTexEpochFinalized``'s SIX ``bytes32``, in the REGISTRY's declared order — which is NOT the
#: context's order and is not a superset of it either. ``patch_set_root`` and ``score_root`` are
#: RECORDED at seal time and checked against nothing; the other four are checks, not records.
#:
#: SIX, NOT EIGHT. ``corpus_root``, ``active_frontier_root`` and ``baseline_manifest_hash`` left
#: with the pin consolidation and ``epoch_context_root`` arrived, so the event went from nine
#: fields to seven and its topic0 moved. The stored ``EpochHeader`` shrank further, to
#: ``{patchSetRoot, scoreRoot}`` — every other cell was a second copy of a value the same contract
#: already returns — but THE EVENT IS NOT THE HEADER: a log is a snapshot at a block, cannot drift,
#: and stating the epoch's closing facts in one line is what keeps an indexer from issuing three
#: ``eth_call``s to learn what the line already said.
RIG_EPOCH_SEAL_WORDS: Tuple[str, ...] = (
    "parent_state_root", "final_state_root", "core_version_hash", "epoch_context_root",
    "patch_set_root", "score_root")


@dataclass(frozen=True)
class RigEpochFinalized:
    """A SEALED rig epoch: its inherited parent, its final root, its three pins, its closing roots.

    There is no transition count on this event; ``transitionCount(epoch)`` is a state read.

    ``final_state_root`` is a CHECK on chain and not a record: ``finalizeEpoch`` requires the
    submitted value to equal ``liveStateRoot(epoch)``, which cannot move again once the epoch is
    finalized, so the header stopped storing it and ``retireAtEpoch`` reads the live root instead.
    Restating the epoch you mean to close turns a mis-aimed finalization into a revert instead of a
    frozen wrong epoch, which is why the parameter survived the cell's deletion.
    """

    epoch: int
    parent_state_root: str
    final_state_root: str
    core_version_hash: str
    epoch_context_root: str
    patch_set_root: str
    score_root: str
    provenance: LogProvenance = LogProvenance()

    def pins(self) -> Dict[str, str]:
        """The THREE context pins this seal re-states, keyed exactly as the context publishes them.

        ``patch_set_root``/``score_root`` are excluded: they are seal-only records with no context
        counterpart, so including them would make this dict incomparable with a context's.
        ``final_state_root`` is excluded for the opposite reason — the context declares the epoch's
        STARTING head under ``parent_state_root``, and the seal's final root is a different fact.
        """
        return {name: getattr(self, name) for name in RIG_EPOCH_CONTEXT_PINS}


def decode_rig_epoch_finalized(log: Mapping[str, Any]) -> RigEpochFinalized:
    """Decode the registry's ``CoreTexEpochFinalized``: six ``bytes32``, one indexed epoch."""
    _require_topic0(log, RIG_EPOCH_FINALIZED_TOPIC0, EVENT_RIG_EPOCH_FINALIZED)
    data = _data(log)
    values = {name: _word(data, index, name)
              for index, name in enumerate(RIG_EPOCH_SEAL_WORDS)}
    return RigEpochFinalized(epoch=_topic_uint(log, 1, "epoch", bits=64),
                             provenance=_provenance(log), **values)


#: The decoder each recognised event name routes to.
DECODERS: Dict[str, Callable[[Mapping[str, Any]], Any]] = {
    EVENT_RIG_STATE_ADVANCED: decode_rig_state_advanced,
    EVENT_RIG_EPOCH_FINALIZED: decode_rig_epoch_finalized,
    EVENT_RIG_EPOCH_COMMIT_SET: decode_epoch_commit_set,
    EVENT_RIG_EPOCH_SECRET_REVEALED: decode_epoch_secret_revealed,
    EVENT_RIG_EPOCH_CONTEXT_SET: decode_rig_epoch_context_set,
    EVENT_RIG_CREDIT_ACCEPTED: decode_rig_credit_accepted,
}

def decode(log: Mapping[str, Any], deployments: Optional[DeploymentSet] = None):
    """Route + decode in one call. Returns ``(Route, decoded_or_None)``.

    An IGNORE route yields ``(route, None)`` — an unknown topic0 is never an exception. A
    A recognised topic with no registered decoder also yields ``None`` with its route preserved.
    """
    r = route(log, deployments)
    if not r.recognised:
        return r, None
    decoder = DECODERS.get(r.event or "")
    if decoder is None:
        return r, None
    return r, decoder(log)


# --------------------------------------------------------------------------- #
# Evaluation replay pins resolved from the current epoch context
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ReplayPins:
    """Law roots resolved from the current rig epoch-context artifact for deterministic replay.

    Mining commit/reveal state remains in :class:`RigEpochPins`; it is deliberately absent here
    because fixed-suite evaluation does not select an exam from it.
    """

    epoch: int
    runtime_abi_root: str
    benchmark_law_root: str
    counter_resource_law_root: str

    def __post_init__(self) -> None:
        fr.check_epoch(self.epoch)
        for field in ("runtime_abi_root", "benchmark_law_root", "counter_resource_law_root"):
            fr.check_root(getattr(self, field), field)

    def as_dict(self) -> Dict[str, Any]:
        out = {"epoch": self.epoch,
               "runtime_abi_root": self.runtime_abi_root,
               "benchmark_law_root": self.benchmark_law_root,
               "counter_resource_law_root": self.counter_resource_law_root}
        return out


#: A resolver maps ONE epoch to ITS pins, or ``None``. There is deliberately no flat/global form.
ReplayPinResolver = Callable[[int], Optional[ReplayPins]]


def resolve_replay_pins(resolver: Optional[ReplayPinResolver], epoch: int) -> ReplayPins:
    """Resolve ``epoch``'s pins or raise. Never falls back to another epoch's values."""
    fr.check_epoch(epoch)
    if resolver is None:
        raise MissingEpochPinsError(
            f"no per-epoch pin resolver supplied; epoch {epoch} cannot be checked against ITS OWN "
            "pins and a global assumption is refused by design")
    pins = resolver(epoch)
    if pins is None:
        raise MissingEpochPinsError(
            f"no pins known for epoch {epoch}. Older epochs legitimately carry older pins, so a "
            "flat expected set cannot substitute — this is unresolved CONTEXT work, not a pass")
    if not isinstance(pins, ReplayPins):
        raise DispatchTypeError(
            f"pin resolver returned {type(pins).__name__}, expected ReplayPins")
    if pins.epoch != epoch:
        raise MissingEpochPinsError(
            f"pin resolver returned pins for epoch {pins.epoch} when asked for {epoch}")
    return pins


def replay_pins_from_mapping(pins: Mapping[int, ReplayPins]) -> ReplayPinResolver:
    """A resolver over a pre-read ``{epoch: EpochPins}`` map."""
    table = dict(pins)
    return lambda epoch: table.get(epoch)


# --------------------------------------------------------------------------- #
# Per-epoch pins, RIG lane
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RigEpochPins:
    """Everything the RIG lane's epoch pins, from that epoch's own confirmed context + commit.

    This chain-facing type pins the three canonical words its verifier context declares. The three
    law roots are FIELDS OF THE MANIFEST at ``epoch_context_root`` rather than cells of their own —
    which is how they became chain FACTS at all, having previously had no chain slot anywhere. The
    this is intentionally separate from :class:`ReplayPins`.

    THREE, NOT FIVE (spec §2A). ``corpus_root``, ``active_frontier_root`` and
    ``baseline_manifest_hash`` are gone from here because they are gone from the chain: they are
    inside the epochContext manifest now, and a validator reads them by FETCHING it.

    ``parent_state_root`` IS here — see :data:`RIG_EPOCH_CONTEXT_PINS` for why the delegated design
    makes the head a published context value rather than a derived one.

    ``entropy_commitment`` comes from the MINING contract's ``EpochCommitSet`` — the commit point,
    and the event that freezes these pins (``setCoreTexEpochContext`` reverts
    ``EpochCommitAlreadySet`` once it is set). ``revealed_secret`` is optional because the reveal
    necessarily happens after the epoch's advances (the mining contract refuses it until the epoch
    has ENDED).
    """

    epoch: int
    parent_state_root: str
    epoch_context_root: str
    core_version_hash: str
    entropy_commitment: str
    revealed_secret: Optional[str] = None

    def __post_init__(self) -> None:
        fr.check_epoch(self.epoch)
        for field in RIG_EPOCH_CONTEXT_PINS + ("entropy_commitment",):
            fr.check_root(getattr(self, field), field)
        if self.revealed_secret is not None:
            fr.check_root(self.revealed_secret, "revealed_secret")

    def enforced_pins(self) -> Dict[str, str]:
        """The TWO an advance restates and can therefore be equality-checked, by event field name.

        THE THIRD PIN IS ENFORCED, JUST NOT BY EQUALITY HERE. ``submitStateAdvance`` checks all
        three: ``parentStateRoot == liveStateRoot`` (pin 2, a COMPARE-AND-SWAP), ``coreVersionHash``
        (pin 1) and ``epochContextRoot`` (pin 3). Pins 1 and 3 are per-epoch constants, so an
        advance restates them and a validator compares them to a pin it read for itself — that is
        this dict. Pin 2 is not a constant: the CAS moves the live root on every accepted advance,
        so the epoch's context ``parent_state_root`` is only the head at transition 0. Comparing an
        advance's ``parentStateRoot`` to it would refuse every transition after the first, so pin 2
        is checked against the registry's CURRENT ``liveStateRoot`` and the transition index instead
        (``chain_first.validate_rig_chain_first``, ``rig_head_or_history``).

        ``work_policy_hash`` is absent because the deployed context does not pin it: the verifier
        prices each receipt against its scheduled policy, so the receipt's ``workPolicyHash`` is
        checked by the contract and, off chain, through the receipt-hash preimage — never against
        a per-epoch context pin that does not exist.
        """
        return {"epoch_context_root": self.epoch_context_root,
                "core_version_hash": self.core_version_hash}

    def as_dict(self) -> Dict[str, Any]:
        out = {"epoch": self.epoch, "entropy_commitment": self.entropy_commitment}
        out.update({name: getattr(self, name) for name in RIG_EPOCH_CONTEXT_PINS})
        if self.revealed_secret is not None:
            out["revealed_secret"] = self.revealed_secret
        return out


#: A rig resolver maps ONE epoch to ITS rig pins, or ``None``.
RigPinResolver = Callable[[int], Optional["RigEpochPins"]]


def rig_pins_from_mapping(pins: Mapping[int, RigEpochPins]) -> RigPinResolver:
    table = dict(pins)
    return lambda epoch: table.get(epoch)


def resolve_rig_pins(resolver: Optional[RigPinResolver], epoch: int) -> RigEpochPins:
    """Resolve ``epoch``'s rig pins or raise. Never falls back to another epoch's values."""
    fr.check_epoch(epoch)
    if resolver is None:
        raise MissingEpochPinsError(
            f"no per-epoch RIG pin resolver supplied; epoch {epoch} cannot be checked against ITS "
            "OWN pins and a global assumption is refused by design")
    pins = resolver(epoch)
    if pins is None:
        raise MissingEpochPinsError(
            f"no rig pins known for epoch {epoch}. This is unresolved CONTEXT work, not a pass")
    if not isinstance(pins, RigEpochPins):
        raise DispatchTypeError(
            f"rig pin resolver returned {type(pins).__name__}, expected RigEpochPins")
    if pins.epoch != epoch:
        raise MissingEpochPinsError(
            f"rig pin resolver returned pins for epoch {pins.epoch} when asked for {epoch}")
    return pins


def build_rig_pins_from_logs(logs: Iterable[Mapping[str, Any]],
                             deployments: Optional[DeploymentSet] = None
                             ) -> Dict[int, RigEpochPins]:
    """Assemble ``{epoch: RigEpochPins}`` from CONFIRMED rig context/commit/reveal logs alone.

    The rig analogue of :func:`build_pins_from_logs`, and the same claim made executable: the
    VERIFIER's ``CoreTexEpochContextSet`` and the mining contract's ``EpochCommitSet`` are public
    events, so a validator reconstructs every rig epoch pin from the same log feed it replays — no
    coordinator API, no operator file. Note the emitters: the context comes from the verifier and
    the commit from the mining contract, so a :class:`DeploymentSet` that names only the registry
    finds no pins at all.

    An epoch missing EITHER the context or the commit is ABSENT from the result rather than
    partially present: an unarmed epoch's pins are still re-settable, so treating a context-only
    epoch as pinned would let a later ``setEpochContext`` silently change what a replay checked
    against. That is exactly the freeze rule the registry enforces on chain
    (``EpochCommitAlreadySet``), mirrored here.

    Contexts use LAST-WRITE-WINS up to the commit, which is the same reason: before the commit point
    the registry itself permits a correction.
    """
    contexts: Dict[int, RigEpochContextSet] = {}
    commits: Dict[int, str] = {}
    secrets: Dict[int, str] = {}
    for log in logs:
        r, decoded = decode(log, deployments)
        if decoded is None or r.protocol != PROTOCOL_RIG:
            continue
        if isinstance(decoded, RigEpochContextSet):
            contexts[decoded.epoch] = decoded
        elif isinstance(decoded, EpochCommitSet):
            commits[decoded.epoch] = decoded.epoch_commit
        elif isinstance(decoded, EpochSecretRevealed):
            secrets[decoded.epoch] = decoded.epoch_secret
    out: Dict[int, RigEpochPins] = {}
    for epoch, ctx in contexts.items():
        commit = commits.get(epoch)
        if commit is None or commit == ZERO_WORD:
            continue                                   # unarmed epoch: no commit, hence no pins
        out[epoch] = RigEpochPins(epoch=epoch, entropy_commitment=commit,
                                  revealed_secret=secrets.get(epoch), **ctx.pins())
    return out
