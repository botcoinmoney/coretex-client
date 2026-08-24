# SPDX-License-Identifier: Apache-2.0
"""V5 protocol / deployment DETECTION and log decoding (Cut V5-E, ledger §17.236).

This module answers exactly one question per log line: *which protocol does this belong to, and
what does it decode to?* It never replays anything and never fetches anything.

WHY A DISPATCH LAYER EXISTS AT ALL. §17.236 is explicit that "old epochs/deployments stay
immutable and replayable under their existing decoder; V5 gets a NEW deployment address, protocol
identifier and validator dispatch path." The canonical V4 decoder
(``/root/coretex/packages/coretex/src/replay/coretex-registry.ts``) dispatches on a *string
literal* event signature hashed to ``topic0`` and then decodes by FIXED ABI word offsets. That
design is correct and must keep working byte-for-byte, which means:

  * V5 must never emit an event that collides with ``CoreTexStateAdvanced``'s topic0
    (``2f0a8989…``). It does not: ``CoreTexMemoryFrontierAdvanced`` is ``b943265f…``.
  * A validator that sees both must route by topic0 AND by deployment, because a topic0 alone
    says nothing about which contract emitted it.
  * An UNKNOWN topic0 is IGNORED, never an error. A registry that gains a new administrative
    event must not brick every validator in the field.

THE RIG LANE (the V5 rig-keyed integration). ``RigCoreTexStateRegistry`` supersedes the
memory-frontier registry with a RIG-KEYED protocol: ``PROTOCOL_RIG``. Its advance event is
``RigCoreTexStateAdvanced`` (topic0 ``7a35edec…``), whose own source comment states the
requirement — "a NEW event name, so a NEW topic0: it must never collide with the V4 decoder's
hardcoded ``CoreTexStateAdvanced`` topic0, nor with the retired lane's
``CoreTexMemoryFrontierAdvanced``". That requirement is ASSERTED below across all three advance
topic0s rather than left as prose. Every rig topic0 here is COMPUTED from its signature by
:func:`event_topic` and cross-checked against a committed literal by the same import-time loop
that guards the V4 and V5 sets; none was copied from the contract.

The V5 memory-frontier events are RETIRED but NOT removed, for exactly the reason the V4 ones are
kept: a validator still has to decode the confirmed logs those deployments already emitted. Three
protocols therefore coexist in one dispatch table, disambiguated by deployment address.

THE PER-EPOCH PIN RULE (mirrored, not re-invented). The V4 decoder learned this the hard way and
carries ``expectedPinsForEpoch``: older epochs legitimately carried older pins, so a single flat
expected set cannot apply and each advance is checked against ITS OWN epoch's pins. V5 keeps the
per-epoch resolver and DROPS the flat fallback entirely — :class:`EpochPins` is resolved per
epoch or not at all (:class:`MissingEpochPinsError`). There is no "expected root" that applies
globally, because there is no such thing.

WHAT A PUBLIC VALIDATOR CAN BUILD FROM LOGS ALONE. Every pin V5 replay needs is emitted:

  ============================  ==========================================================
  ``CoreTexMemoryEpochContextSet``  runtime-ABI, benchmark-law and counter-resource-law
                                    roots for the epoch — its LAW PINS, and nothing else
  ``EpochCommitSet``                the epoch entropy COMMITMENT (both params indexed)
  ``EpochSecretRevealed``           the opened epoch secret
  ``CoreTexMemoryEpochInherited``   the EPOCH HEAD: what epoch N inherited, from which
                                    epoch, and the root its first transition produced
  ``CoreTexMemoryFrontierAdvanced`` the advance itself, carrying ``transitionBytes``
  ``CoreTexMemoryCreditAccepted``   the miner credit, carrying ``targetProfileId``
  ============================  ==========================================================

:func:`build_pins_from_logs` turns those logs into a per-epoch resolver. No coordinator API, no
secret corpus, no hosted model — §17.236's "validators must never need a hosted API".

THE EPOCH HEAD IS NOT A PIN (operator ruling §17.237). ``CoreTexMemoryEpochContextSet`` used to
carry a coordinator-supplied ``parentFrontierRoot`` and the pin set used to expose it. Both are
gone. An epoch inherits the confirmed final root of the latest preceding epoch that mined, by a
rule the contract evaluates on-chain and :func:`sync.derive_epoch_parents` re-evaluates from
confirmed advances alone. ``CoreTexMemoryEpochInherited`` is a CROSS-CHECK on that derivation, not
its source: a validator that took the head from an event would be trusting a publisher, and rule 6
says the parent must come entirely from confirmed history.

SEAM (ledger §17.238). REVENDOR NEEDED: **NO**, and this is the module where that could have gone
wrong, so it is checked rather than assumed. The canonical V4 decoder
(``/root/coretex/packages/coretex/src/replay/coretex-registry.ts``) (a) filters ``eth_getLogs`` to
``CORETEX_EVENT_TOPICS.CoreTexStateAdvanced`` / ``.CoreTexEpochFinalized`` only, so it never
retrieves a V5 log, and (b) returns ``null`` — not an exception — for any other ``topics[0]``. The
NEW ``CoreTexMemoryEpochInherited`` topic0 (``5be4a923…``) and the RE-CUT
``CoreTexMemoryEpochContextSet`` topic0 (``a619a62b…``, four params now that the head field is
gone) are therefore invisible to it. No entry needs adding to the canonical dispatch table, and no
``/root/coretex``, ``vendor/`` or ``node_modules/`` change is required to arm this lane. The V4
literals in this module (``2f0a8989…``, ``7c882e64…``) and the V4 decode path are byte-for-byte
untouched, and the import-time anti-drift loop below re-proves every literal on every import.

``PROFILE_ID_HASHES`` (``keccak256(utf8(profile_id))`` over the closed 3-profile set) and its
inverse ``PROFILE_BY_ID_HASH`` are likewise untouched: V5-D mirrors that exact convention to read
``targetProfileId`` out of the credit event, and the two must stay identical.

HEX CONVENTIONS (stated because mixing them is a real bug class). Every ``bytes32`` this module
returns is BARE lowercase 64-hex, the V5 house form that ``frontier.check_root`` accepts and that
``0x`` would make illegal. Addresses are returned ``0x``-prefixed lowercase, because an address is
not a root. The canonical TypeScript decoder returns ``0x``-prefixed for both; the BYTES are the
same, only the rendering differs, and :func:`to_0x` / :func:`from_0x` convert.

STRICTNESS, DELIBERATELY ABOVE THE V4 DECODER. The V4 decoder follows the dynamic-tail offset
wherever it points and reads whatever length it finds. V5 decoding refuses a log whose data is
not a multiple of 32, whose tail offset is out of range or unaligned, whose declared length
overruns the data, whose tail padding is non-zero, or whose ``uint64`` / ``address`` topics carry
dirty high bits. A confirmed event is data availability for consensus; "decoded something" is not
the same as "decoded THE event".
"""
from __future__ import annotations

import os
import sys
from collections import abc
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


from . import frontier as fr
from .keccak256 import keccak256_hex

# --------------------------------------------------------------------------- #
# Protocol identifiers
# --------------------------------------------------------------------------- #
#: The V4 parameter-state lane. Its decoder is canonical and frozen; V5 never touches it.
PROTOCOL_V4 = "coretex.state.v4"
#: The V5 memory-frontier lane. RETIRED by the rig cut below, and kept for the same reason
#: ``PROTOCOL_V4`` is: a validator still has to decode the confirmed logs it already emitted.
PROTOCOL_V5 = "coretex.memory-frontier.v1"
#: The RIG-KEYED CoreTex state lane — ``RigCoreTexStateRegistry``. Rig-scoped (``uint256 rigId``,
#: not ``address miner``), and its advance event carries the epoch-context roots the registry
#: enforces plus ``patchHash``/``artifactHash`` in place of ``transitionBytes``.
PROTOCOL_RIG = "coretex.rig-state.v1"

PROTOCOLS: Tuple[str, ...] = (PROTOCOL_V4, PROTOCOL_V5, PROTOCOL_RIG)

# --------------------------------------------------------------------------- #
# Canonical event signatures — param TYPES only, indexed params kept in the list
# --------------------------------------------------------------------------- #
V4_STATE_ADVANCED_SIG = (
    "CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32,uint256,uint16,bytes)")
V4_EPOCH_FINALIZED_SIG = (
    "CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32)")

V5_FRONTIER_ADVANCED_SIG = (
    "CoreTexMemoryFrontierAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32,bytes32,bytes)")
V5_EPOCH_FINALIZED_SIG = (
    "CoreTexMemoryEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,uint64)")
#: The EPOCH-HEAD publication (operator ruling §17.237). Emitted once per epoch, in the same
#: transaction as that epoch's first accepted transition, carrying BOTH the inherited parent and
#: the resulting frontier root.
V5_EPOCH_INHERITED_SIG = "CoreTexMemoryEpochInherited(uint64,uint64,bytes32,bytes32,bool)"
#: NO `parentFrontierRoot` (ruling §17.237): a context pins the epoch's LAW and never its head.
V5_EPOCH_CONTEXT_SET_SIG = "CoreTexMemoryEpochContextSet(uint64,bytes32,bytes32,bytes32)"
V5_EPOCH_COMMIT_SET_SIG = "EpochCommitSet(uint64,bytes32)"
V5_EPOCH_SECRET_REVEALED_SIG = "EpochSecretRevealed(uint64,bytes32)"
V5_CREDIT_ACCEPTED_SIG = (
    "CoreTexMemoryCreditAccepted(uint64,address,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32,bytes32,uint256)")

# ── The RIG lane (RigCoreTexStateRegistry) ─────────────────────────────────
#: THE canonical rig state advance. Indexed ``(uint64 epoch, uint64 transitionIndex,
#: uint256 rigId)``, then eight ``bytes32`` in the DATA section: parent/new state root,
#: ``epochContextRoot``, core/work-policy roots, ``evalReportHash``, ``patchHash``, ``artifactHash``,
#: and a TRAILING ``bool viaLegacyRoute``.
#: It carries NO ``transitionBytes``: the rig lane addresses the candidate by ``artifactHash``
#: and the edit by ``patchHash``, so a replayer FETCHES rather than reads the edit out of the log.
#:
#: THE TRAILING ``bool`` IS FINDING H-11, NOT DECORATION. An advance that arrived through the raw
#: ``0xa2d87e1d`` fallback shim was minted from calldata whose word ORDER is still unverified
#: (Q-2). Before the remediation the two routes were indistinguishable once confirmed, so an
#: operator auditing history could not tell a typed ``submitStateAdvance`` from a shim advance.
#: The flag makes that distinction PERMANENT and public, which is exactly why this decoder surfaces
#: it rather than skipping the extra word.
RIG_STATE_ADVANCED_SIG = (
    "RigCoreTexStateAdvanced(uint64,uint64,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32,bytes32,bytes32,bool)")
#: Priced work that did NOT move the root. Emitted with NO storage write, so a replayer can
#: account for EVERY priced CoreTex receipt and not only the ones that advanced the state. It
#: carries the SAME trailing ``bool viaLegacyRoute`` as the advance, for the same H-11 reason: a
#: screener pass that came through the shim is priced work whose provenance must stay visible.
RIG_SCREENER_PASS_SIG = (
    "RigCoreTexScreenerPassRecorded(uint64,uint256,bytes32,bytes32,bytes32,bytes32,bool)")
#: The rig lane's epoch-head publication. Same role as ``CoreTexMemoryEpochInherited``.
RIG_EPOCH_INHERITED_SIG = "RigCoreTexEpochInherited(uint64,uint64,bytes32,bytes32,bool)"
RIG_EPOCH_FINALIZED_SIG = (
    "RigCoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64)")
#: NO head field, for the same §17.237 reason the V5 context event has none: a context pins the
#: epoch's LAW and never its head.
RIG_EPOCH_CONTEXT_SET_SIG = (
    "RigCoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32,bytes32,bytes32)")


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
#: The V4 advance topic0. COMMITTED as a literal so that a change to the signature string above —
#: which would silently re-route every historical log — fails at import instead of at replay.
V4_STATE_ADVANCED_TOPIC0 = "2f0a89894d44aa2294de109d294ac072f0e206dc834a0c35c6fbf1623ec02dd0"
V4_EPOCH_FINALIZED_TOPIC0 = "7c882e64d34d7e0b82f8004ec182f5b9e942388f7b7b1ea60233306c02821085"

V5_FRONTIER_ADVANCED_TOPIC0 = "b943265f8e11cdfe22be78553db2644986d18ab7f8493ad9cfbc5899ca55994b"
V5_EPOCH_FINALIZED_TOPIC0 = "c9d0c4bc568ce13c06a71e536cefa0a3f41e3678482062c308904b8b41a6b272"
V5_EPOCH_INHERITED_TOPIC0 = "5be4a9236f18509116db6f74372269b140da07adcd89a69be1a429c08b8881c8"
V5_EPOCH_CONTEXT_SET_TOPIC0 = "a619a62b060d4b30c24701ab8f9b3342b2778ac40c01867ea6cf5d8c35a53fd6"
V5_EPOCH_COMMIT_SET_TOPIC0 = "59292804aa2c2d886e7b2e3982ee2e6df6e3d52f35220fbcafc233d216f7ddf6"
V5_EPOCH_SECRET_REVEALED_TOPIC0 = "874024d45050fc7f9a2b883212a09399fe2d44dcff11ef6e75782efd2bc22bb6"
V5_CREDIT_ACCEPTED_TOPIC0 = "040115536fbde89efa2d3fd2903f086f16802696a73119b8733d0e63236acd74"

#: The RIG lane's topic0 set. COMPUTED from the signatures above by :func:`event_topic` and then
#: committed here as literals, exactly as the V4/V5 sets are — the loop below re-hashes every
#: signature at import and refuses to load on any disagreement, so these are a second witness and
#: never a substitute for the derivation.
#:
#: BOTH ADVANCE-CLASS LITERALS MOVED when the H-11 remediation appended ``bool viaLegacyRoute``.
#: ``RigCoreTexStateAdvanced`` was ``e600e236…`` and ``RigCoreTexScreenerPassRecorded`` was
#: ``957e0d0f…``; parameter TYPES determine topic0, so adding a field re-keys the event. The old
#: values are recorded here as history and are NOT registered anywhere: no deployment ever emitted
#: them (the flag landed before any rig deployment), so there is no historical log to keep
#: decoding under them, and a stale pin simply means "this advance matched nothing" — the exact
#: symptom the §10 proof caught at ``verify_atomic_transition``.
RIG_STATE_ADVANCED_TOPIC0 = "7ae8ca47bd3b28315092d66393f84f3aa6558e77044befb9cd84230ba706a1eb"
RIG_SCREENER_PASS_TOPIC0 = "eda3819a2fd3c640e6e7e3896d8f05b75629fb5db3c7108982cd1ff87aa04428"
RIG_EPOCH_INHERITED_TOPIC0 = "837d744f70df7a57a08d1dc2b093b17a502134b4e484acdd9602b1dc4681a00a"
RIG_EPOCH_FINALIZED_TOPIC0 = "48df8d442fe4c3a24fcc7e1dbe1c88635badaaed6aef8a43bca5755927a6e889"
RIG_EPOCH_CONTEXT_SET_TOPIC0 = "bb2b0961e2170827dacf299941bbb8ace1326f3a224bd6cd7b8c23099c7e1f06"

#: Event NAMES, per protocol. The dispatch table is keyed by topic0; this is the reverse map.
EVENT_V4_STATE_ADVANCED = "CoreTexStateAdvanced"
EVENT_V4_EPOCH_FINALIZED = "CoreTexEpochFinalized"
EVENT_V5_FRONTIER_ADVANCED = "CoreTexMemoryFrontierAdvanced"
EVENT_V5_EPOCH_FINALIZED = "CoreTexMemoryEpochFinalized"
EVENT_V5_EPOCH_INHERITED = "CoreTexMemoryEpochInherited"
EVENT_V5_EPOCH_CONTEXT_SET = "CoreTexMemoryEpochContextSet"
EVENT_V5_EPOCH_COMMIT_SET = "EpochCommitSet"
EVENT_V5_EPOCH_SECRET_REVEALED = "EpochSecretRevealed"
EVENT_V5_CREDIT_ACCEPTED = "CoreTexMemoryCreditAccepted"
EVENT_RIG_STATE_ADVANCED = "RigCoreTexStateAdvanced"
EVENT_RIG_SCREENER_PASS = "RigCoreTexScreenerPassRecorded"
EVENT_RIG_EPOCH_INHERITED = "RigCoreTexEpochInherited"
EVENT_RIG_EPOCH_FINALIZED = "RigCoreTexEpochFinalized"
EVENT_RIG_EPOCH_CONTEXT_SET = "RigCoreTexEpochContextSet"

_SIGNATURES: Dict[str, Tuple[str, str, str]] = {
    # topic0 -> (protocol, event name, signature)
    V4_STATE_ADVANCED_TOPIC0: (PROTOCOL_V4, EVENT_V4_STATE_ADVANCED, V4_STATE_ADVANCED_SIG),
    V4_EPOCH_FINALIZED_TOPIC0: (PROTOCOL_V4, EVENT_V4_EPOCH_FINALIZED, V4_EPOCH_FINALIZED_SIG),
    V5_FRONTIER_ADVANCED_TOPIC0: (PROTOCOL_V5, EVENT_V5_FRONTIER_ADVANCED,
                                  V5_FRONTIER_ADVANCED_SIG),
    V5_EPOCH_FINALIZED_TOPIC0: (PROTOCOL_V5, EVENT_V5_EPOCH_FINALIZED, V5_EPOCH_FINALIZED_SIG),
    V5_EPOCH_INHERITED_TOPIC0: (PROTOCOL_V5, EVENT_V5_EPOCH_INHERITED, V5_EPOCH_INHERITED_SIG),
    V5_EPOCH_CONTEXT_SET_TOPIC0: (PROTOCOL_V5, EVENT_V5_EPOCH_CONTEXT_SET,
                                  V5_EPOCH_CONTEXT_SET_SIG),
    V5_EPOCH_COMMIT_SET_TOPIC0: (PROTOCOL_V5, EVENT_V5_EPOCH_COMMIT_SET, V5_EPOCH_COMMIT_SET_SIG),
    V5_EPOCH_SECRET_REVEALED_TOPIC0: (PROTOCOL_V5, EVENT_V5_EPOCH_SECRET_REVEALED,
                                      V5_EPOCH_SECRET_REVEALED_SIG),
    V5_CREDIT_ACCEPTED_TOPIC0: (PROTOCOL_V5, EVENT_V5_CREDIT_ACCEPTED, V5_CREDIT_ACCEPTED_SIG),
    RIG_STATE_ADVANCED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_STATE_ADVANCED, RIG_STATE_ADVANCED_SIG),
    RIG_SCREENER_PASS_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_SCREENER_PASS, RIG_SCREENER_PASS_SIG),
    RIG_EPOCH_INHERITED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_INHERITED, RIG_EPOCH_INHERITED_SIG),
    RIG_EPOCH_FINALIZED_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_FINALIZED, RIG_EPOCH_FINALIZED_SIG),
    RIG_EPOCH_CONTEXT_SET_TOPIC0: (PROTOCOL_RIG, EVENT_RIG_EPOCH_CONTEXT_SET,
                                   RIG_EPOCH_CONTEXT_SET_SIG),
}

#: Import-time anti-drift: every committed literal MUST be the hash of its committed signature.
for _topic, (_proto, _name, _sig) in _SIGNATURES.items():
    if event_topic(_sig) != _topic:                             # pragma: no cover - fail closed
        raise RuntimeError(
            f"topic0 drift for {_name}: keccak256({_sig!r}) = {event_topic(_sig)}, the committed "
            f"literal is {_topic}. Parameter TYPES (not names) determine topic0; changing them "
            "without cutting a new event name silently corrupts every decoder in the field.")
#: The registry's own comment makes non-collision a REQUIREMENT ("a NEW event name, so a NEW
#: topic0: it must never collide with the V4 decoder's hardcoded ``CoreTexStateAdvanced`` topic0,
#: nor with the retired lane's ``CoreTexMemoryFrontierAdvanced``"). A requirement that is only
#: written down is not enforced, so it is asserted here across ALL THREE advance events.
_ADVANCE_TOPIC0S = (V4_STATE_ADVANCED_TOPIC0, V5_FRONTIER_ADVANCED_TOPIC0,
                    RIG_STATE_ADVANCED_TOPIC0)
if len(set(_ADVANCE_TOPIC0S)) != len(_ADVANCE_TOPIC0S):         # pragma: no cover - fail closed
    raise RuntimeError(f"advance events collide on topic0: {_ADVANCE_TOPIC0S}")

#: The topic0 set a V5 validator subscribes to. (``eth_getLogs`` topics[0] is an OR-set.)
V5_TOPICS: Tuple[str, ...] = tuple(
    t for t, (p, _n, _s) in sorted(_SIGNATURES.items()) if p == PROTOCOL_V5)
V4_TOPICS: Tuple[str, ...] = tuple(
    t for t, (p, _n, _s) in sorted(_SIGNATURES.items()) if p == PROTOCOL_V4)
#: TOPIC0S THAT TWO PROTOCOLS LEGITIMATELY SHARE.
#:
#: ``BotcoinMiningRigsV1`` and the retired ``CoreTexMemoryMining`` declare
#: ``EpochCommitSet(uint64 indexed, bytes32 indexed)`` and
#: ``EpochSecretRevealed(uint64 indexed, bytes32)`` with IDENTICAL parameter types and identical
#: indexing, so their topic0s are identical and their encodings are byte-compatible. That is not a
#: collision to route around — it is the same event, emitted by two generations of the same epoch
#: clock, and both decode correctly with one decoder.
#:
#: Recorded EXPLICITLY rather than handled by loosening :func:`route`: without this table a rig
#: deployment's commit log is IGNORED (its address speaks ``PROTOCOL_RIG``, its topic0 is
#: registered under ``PROTOCOL_V5``), and :func:`build_rig_pins_from_logs` then finds no epoch
#: commitment and reports every rig epoch as unpinned. Found while wiring the §10 rig chain-first
#: envelope.
SHARED_TOPIC0_PROTOCOLS: Dict[str, Tuple[str, ...]] = {
    V5_EPOCH_COMMIT_SET_TOPIC0: (PROTOCOL_V5, PROTOCOL_RIG),
    V5_EPOCH_SECRET_REVEALED_TOPIC0: (PROTOCOL_V5, PROTOCOL_RIG),
}


def protocols_for_topic0(topic0: str) -> Tuple[str, ...]:
    """Every protocol a topic0 may legitimately be emitted under. Usually exactly one."""
    entry = _SIGNATURES.get(topic0)
    if entry is None:
        return ()
    return SHARED_TOPIC0_PROTOCOLS.get(topic0, (entry[0],))


#: The topic0 set a RIG validator subscribes to — the rig-native events PLUS the two the rig
#: mining contract shares with the retired lane.
RIG_TOPICS: Tuple[str, ...] = tuple(sorted(
    {t for t, (p, _n, _s) in _SIGNATURES.items() if p == PROTOCOL_RIG}
    | {t for t, protocols in SHARED_TOPIC0_PROTOCOLS.items() if PROTOCOL_RIG in protocols}))

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
    deployment is authoritative for; ``last_epoch=None`` means open-ended. A V5 topic0 emitted
    from a V4 address (or outside the deployment's epoch window) is NOT V5 — it is unrecognised,
    and unrecognised is ignored, never guessed.
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

    @property
    def is_v5_advance(self) -> bool:
        return self.protocol == PROTOCOL_V5 and self.event == EVENT_V5_FRONTIER_ADVANCED

    @property
    def is_v4(self) -> bool:
        return self.protocol == PROTOCOL_V4


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
    if base.event in (EVENT_V5_FRONTIER_ADVANCED, EVENT_V5_EPOCH_FINALIZED,
                      EVENT_V5_EPOCH_INHERITED, EVENT_V5_EPOCH_CONTEXT_SET,
                      EVENT_V5_EPOCH_COMMIT_SET, EVENT_V5_EPOCH_SECRET_REVEALED,
                      EVENT_V5_CREDIT_ACCEPTED, EVENT_V4_STATE_ADVANCED,
                      EVENT_V4_EPOCH_FINALIZED):
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
    # A SHARED topic0 is reported under the EMITTING DEPLOYMENT's protocol, never under the
    # protocol its signature was first registered against: the deployment is the thing that knows
    # which lane the log belongs to.
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
    #: Appended to preserve the positional constructor used by historical fixtures.
    block_hash: Optional[str] = None

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
        block_hash=(log.get("blockHash").lower()
                    if isinstance(log.get("blockHash"), str) else None),
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
@dataclass(frozen=True)
class FrontierAdvanced:
    """A confirmed ``CoreTexMemoryFrontierAdvanced``. Roots are bare lowercase hex."""

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


def decode_frontier_advanced(log: Mapping[str, Any]) -> FrontierAdvanced:
    """Decode one V5 advance log. Raises rather than returning ``None`` on a shape violation.

    (``coretex-registry.ts`` returns ``null`` for a topic mismatch and then decodes leniently;
    here a topic mismatch is a programming error — :func:`route` already filtered — and a
    malformed body is a hard :class:`LogDecodeError`, because a confirmed event IS the data
    availability that replay depends on.)
    """
    _require_topic0(log, V5_FRONTIER_ADVANCED_TOPIC0, EVENT_V5_FRONTIER_ADVANCED)
    data = _data(log)
    return FrontierAdvanced(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        transition_index=_topic_uint(log, 2, "transitionIndex", bits=64),
        miner=_topic_address(log, 3, "miner"),
        parent_frontier_root=_word(data, 0, "parentFrontierRoot"),
        new_frontier_root=_word(data, 1, "newFrontierRoot"),
        candidate_release_root=_word(data, 2, "candidateReleaseRoot"),
        composition_root=_word(data, 3, "compositionRoot"),
        eval_report_hash=_word(data, 4, "evalReportHash"),
        benchmark_law_root=_word(data, 5, "benchmarkRoot"),
        runtime_abi_root=_word(data, 6, "runtimeAbiRoot"),
        transition_bytes=_tail_bytes(data, 7, _ADVANCE_HEAD_WORDS, "transitionBytes"),
        provenance=_provenance(log),
    )


@dataclass(frozen=True)
class MemoryEpochFinalized:
    epoch: int
    parent_frontier_root: str
    final_frontier_root: str
    runtime_abi_root: str
    benchmark_law_root: str
    counter_resource_law_root: str
    transitions: int
    provenance: LogProvenance = LogProvenance()


def decode_memory_epoch_finalized(log: Mapping[str, Any]) -> MemoryEpochFinalized:
    _require_topic0(log, V5_EPOCH_FINALIZED_TOPIC0, EVENT_V5_EPOCH_FINALIZED)
    data = _data(log)
    return MemoryEpochFinalized(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        parent_frontier_root=_word(data, 0, "parentFrontierRoot"),
        final_frontier_root=_word(data, 1, "finalFrontierRoot"),
        runtime_abi_root=_word(data, 2, "runtimeAbiRoot"),
        benchmark_law_root=_word(data, 3, "benchmarkLawRoot"),
        counter_resource_law_root=_word(data, 4, "counterResourceLawRoot"),
        transitions=_word_uint(data, 5, "transitions", bits=64),
        provenance=_provenance(log),
    )


@dataclass(frozen=True)
class EpochInherited:
    """The EPOCH-HEAD publication (operator ruling §17.237 rule 5).

    Emitted exactly once per epoch, in the same transaction as — and immediately BEFORE — that
    epoch's first accepted advance. It carries both halves of the fact a validator needs:
    ``inherited_parent_root`` (what the epoch inherited) and ``new_frontier_root`` (what the first
    transition produced from it).

    A conforming validator does NOT trust this event; it DERIVES the inheritance from confirmed
    advances (``sync.derive_epoch_parents``) and then checks this event agrees
    (``sync.check_inheritance``). The event exists so that a disagreement is visible instead of
    the boundary having to be inferred from absence.
    """

    epoch: int
    inherited_from_epoch: int
    inherited_parent_root: str
    new_frontier_root: str
    from_genesis: bool
    provenance: LogProvenance = LogProvenance()

    def as_dict(self) -> Dict[str, Any]:
        return {"epoch": self.epoch, "inherited_from_epoch": self.inherited_from_epoch,
                "inherited_parent_root": self.inherited_parent_root,
                "new_frontier_root": self.new_frontier_root, "from_genesis": self.from_genesis}


def decode_epoch_inherited(log: Mapping[str, Any]) -> EpochInherited:
    _require_topic0(log, V5_EPOCH_INHERITED_TOPIC0, EVENT_V5_EPOCH_INHERITED)
    data = _data(log)
    flag = _word_uint(data, 2, "fromGenesis")
    if flag > 1:
        raise LogDecodeError(
            f"fromGenesis={flag} is not a canonical ABI bool (0 or 1); this is not the event it "
            "claims to be")
    epoch = _topic_uint(log, 1, "epoch", bits=64)
    from_epoch = _topic_uint(log, 2, "inheritedFromEpoch", bits=64)
    from_genesis = bool(flag)
    # The contract's own invariant, re-checked on decode: fromEpoch == epoch IFF fromGenesis.
    if from_genesis != (from_epoch == epoch):
        raise LogDecodeError(
            f"epoch {epoch} claims inheritedFromEpoch={from_epoch} with fromGenesis={from_genesis}; "
            "an epoch inherits from a STRICTLY earlier epoch, or from genesis (in which case the "
            "two are equal because there is no predecessor) — never anything else")
    if not from_genesis and from_epoch > epoch:
        raise LogDecodeError(
            f"epoch {epoch} claims to inherit from the LATER epoch {from_epoch}")
    return EpochInherited(
        epoch=epoch,
        inherited_from_epoch=from_epoch,
        inherited_parent_root=_word(data, 0, "inheritedParentRoot"),
        new_frontier_root=_word(data, 1, "newFrontierRoot"),
        from_genesis=from_genesis,
        provenance=_provenance(log),
    )


@dataclass(frozen=True)
class MemoryEpochContextSet:
    """The epoch's LAW pins. It does NOT carry a head (ruling §17.237).

    The field was removed rather than left unread. A coordinator-published head that consensus
    ignores is the V4 dead-path defect pattern (see ``replay.V4_DEAD_PATH_DEFECT``): a value in a
    consensus event that looks authoritative and is not.
    """

    epoch: int
    runtime_abi_root: str
    benchmark_law_root: str
    counter_resource_law_root: str
    provenance: LogProvenance = LogProvenance()


def decode_memory_epoch_context_set(log: Mapping[str, Any]) -> MemoryEpochContextSet:
    _require_topic0(log, V5_EPOCH_CONTEXT_SET_TOPIC0, EVENT_V5_EPOCH_CONTEXT_SET)
    data = _data(log)
    return MemoryEpochContextSet(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        runtime_abi_root=_word(data, 0, "runtimeAbiRoot"),
        benchmark_law_root=_word(data, 1, "benchmarkLawRoot"),
        counter_resource_law_root=_word(data, 2, "counterResourceLawRoot"),
        provenance=_provenance(log),
    )


@dataclass(frozen=True)
class EpochCommitSet:
    """The epoch entropy COMMITMENT. Both parameters are indexed, so the data section is empty."""

    epoch: int
    epoch_commit: str
    provenance: LogProvenance = LogProvenance()


def decode_epoch_commit_set(log: Mapping[str, Any]) -> EpochCommitSet:
    _require_topic0(log, V5_EPOCH_COMMIT_SET_TOPIC0, EVENT_V5_EPOCH_COMMIT_SET)
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
    _require_topic0(log, V5_EPOCH_SECRET_REVEALED_TOPIC0, EVENT_V5_EPOCH_SECRET_REVEALED)
    data = _data(log)
    return EpochSecretRevealed(epoch=_topic_uint(log, 1, "epochId", bits=64),
                               epoch_secret=_word(data, 0, "epochSecret"),
                               provenance=_provenance(log))


@dataclass(frozen=True)
class CreditAccepted:
    """The miner-credit event emitted in the SAME transaction as the advance.

    It is the only public place ``targetProfileId`` appears on-chain, so it is what lets a
    validator cross-check the profile named inside ``transitionBytes`` against a chain value.
    """

    epoch: int
    miner: str
    solve_index: int
    receipt_hash: str
    parent_frontier_root: str
    new_frontier_root: str
    target_profile_id: str
    candidate_release_root: str
    composition_root: str
    eval_report_hash: str
    credits_earned: int
    provenance: LogProvenance = LogProvenance()

    @property
    def target_profile(self) -> Optional[str]:
        """The profile id whose keccak is ``target_profile_id``, or ``None`` if it is not one."""
        return PROFILE_BY_ID_HASH.get(self.target_profile_id)


def decode_credit_accepted(log: Mapping[str, Any]) -> CreditAccepted:
    _require_topic0(log, V5_CREDIT_ACCEPTED_TOPIC0, EVENT_V5_CREDIT_ACCEPTED)
    data = _data(log)
    return CreditAccepted(
        epoch=_topic_uint(log, 1, "epochId", bits=64),
        miner=_topic_address(log, 2, "miner"),
        solve_index=_word_uint(data, 0, "solveIndex", bits=64),
        receipt_hash=_word(data, 1, "receiptHash"),
        parent_frontier_root=_word(data, 2, "parentFrontierRoot"),
        new_frontier_root=_word(data, 3, "newFrontierRoot"),
        target_profile_id=_word(data, 4, "targetProfileId"),
        candidate_release_root=_word(data, 5, "candidateReleaseRoot"),
        composition_root=_word(data, 6, "compositionRoot"),
        eval_report_hash=_word(data, 7, "evalReportHash"),
        credits_earned=_word_uint(data, 8, "creditsEarned"),
        provenance=_provenance(log),
    )


# --------------------------------------------------------------------------- #
# The RIG path — the rig-keyed CoreTex state lane
# --------------------------------------------------------------------------- #
def _topic_uint256(log: Mapping[str, Any], index: int, field: str) -> int:
    """A full-width ``uint256`` indexed parameter. ``rigId`` uses the whole word."""
    return int.from_bytes(_topic(log, index, field), "big")


@dataclass(frozen=True)
class RigStateAdvanced:
    """A confirmed ``RigCoreTexStateAdvanced``. Roots are bare lowercase hex.

    Three differences from :class:`FrontierAdvanced` are load-bearing, not cosmetic:

      * the actor is a ``rigId`` (``uint256``), not a ``miner`` address. A rig is the mining unit,
        and its receipt chain is keyed by rig alone;
      * the context and policy roots the registry ENFORCES (``epoch_context_root``,
        ``core_version_hash``, ``work_policy_hash``) ride on the advance
        itself, so a replayer no longer has to join them from a separate context event;
      * there is no ``transition_bytes``. The edit is addressed by ``patch_hash`` and the
        candidate by ``artifact_hash``, so replay FETCHES both instead of reading the edit out of
        the log. A validator that assumed the bytes were inline would silently replay nothing.

    ``via_legacy_route`` IS THE H-11 OBSERVABLE and is deliberately three-valued:

      * ``True``  — the registry minted this advance from the raw ``0xa2d87e1d`` fallback shim,
        whose calldata word ORDER is still unverified (Q-2). Permanent, public, and the one thing
        an operator auditing confirmed history must be able to see.
      * ``False`` — it came through the typed ``submitStateAdvance``.
      * ``None``  — this event was RECONSTRUCTED (from a receipt, a fixture, a projection) rather
        than decoded from a confirmed log, so its route is UNKNOWN. It is not defaulted to
        ``False``: "we did not observe the log" and "the log says typed" are different facts, and
        collapsing them would let a reconstruction quietly vouch for a route nobody read.

    :func:`decode_rig_state_advanced` always sets a real ``bool``; only non-log constructions
    leave it ``None``.
    """

    epoch: int
    transition_index: int
    rig_id: int
    parent_state_root: str
    new_state_root: str
    epoch_context_root: str
    core_version_hash: str
    work_policy_hash: str
    eval_report_hash: str
    patch_hash: str
    artifact_hash: str
    via_legacy_route: Optional[bool] = None
    provenance: LogProvenance = LogProvenance()

    @property
    def route(self) -> str:
        """``"legacy-0xa2d87e1d"`` / ``"typed-submitStateAdvance"`` / ``"unobserved"``.

        A rendering, so every operator-facing surface spells the H-11 fact the same way instead of
        each one inventing its own wording for ``via_legacy_route is None``.
        """
        if self.via_legacy_route is None:
            return "unobserved"
        return "legacy-0xa2d87e1d" if self.via_legacy_route else "typed-submitStateAdvance"

    @property
    def key(self) -> Tuple[int, int]:
        return (self.epoch, self.transition_index)

    def summary(self) -> Dict[str, Any]:
        """A JSON-safe identity view. ``rig_id`` renders as a STRING: a ``uint256`` does not
        survive JSON as a number."""
        return {
            "epoch": self.epoch, "transition_index": self.transition_index,
            "rig_id": str(self.rig_id),
            "parent_state_root": self.parent_state_root,
            "new_state_root": self.new_state_root,
            "eval_report_hash": self.eval_report_hash,
            "patch_hash": self.patch_hash,
            "artifact_hash": self.artifact_hash,
            "via_legacy_route": self.via_legacy_route,
            "route": self.route,
            "address": self.provenance.address,
            "block_number": self.provenance.block_number,
            "log_index": self.provenance.log_index,
        }


def decode_rig_state_advanced(log: Mapping[str, Any]) -> RigStateAdvanced:
    """Decode one rig advance log. Nine ``bytes32`` then one ``bool``; nothing is dynamic."""
    _require_topic0(log, RIG_STATE_ADVANCED_TOPIC0, EVENT_RIG_STATE_ADVANCED)
    data = _data(log)
    return RigStateAdvanced(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        transition_index=_topic_uint(log, 2, "transitionIndex", bits=64),
        rig_id=_topic_uint256(log, 3, "rigId"),
        parent_state_root=_word(data, 0, "parentStateRoot"),
        new_state_root=_word(data, 1, "newStateRoot"),
        epoch_context_root=_word(data, 2, "epochContextRoot"),
        core_version_hash=_word(data, 3, "coreVersionHash"),
        work_policy_hash=_word(data, 4, "workPolicyHash"),
        eval_report_hash=_word(data, 5, "evalReportHash"),
        patch_hash=_word(data, 6, "patchHash"),
        artifact_hash=_word(data, 7, "artifactHash"),
        via_legacy_route=_word_bool(data, 8, "viaLegacyRoute"),
        provenance=_provenance(log),
    )


@dataclass(frozen=True)
class RigScreenerPassRecorded:
    """Priced work that did NOT move the root — emitted with no storage write.

    A validator that decoded only advances would under-count the epoch's priced receipts and
    conclude a rig was paid for work that left no trace. It is the second of the two signable
    outcomes, not an anomaly.

    ``via_legacy_route`` carries the same three-valued H-11 meaning it has on
    :class:`RigStateAdvanced`; see that class for why ``None`` is not ``False``.
    """

    epoch: int
    rig_id: int
    state_root: str
    eval_report_hash: str
    patch_hash: str
    artifact_hash: str
    via_legacy_route: Optional[bool] = None
    provenance: LogProvenance = LogProvenance()

    @property
    def route(self) -> str:
        if self.via_legacy_route is None:
            return "unobserved"
        return "legacy-0xa2d87e1d" if self.via_legacy_route else "typed-submitStateAdvance"


def decode_rig_screener_pass(log: Mapping[str, Any]) -> RigScreenerPassRecorded:
    """Decode one screener pass: four ``bytes32`` then the trailing ``bool viaLegacyRoute``."""
    _require_topic0(log, RIG_SCREENER_PASS_TOPIC0, EVENT_RIG_SCREENER_PASS)
    data = _data(log)
    return RigScreenerPassRecorded(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        rig_id=_topic_uint256(log, 2, "rigId"),
        state_root=_word(data, 0, "stateRoot"),
        eval_report_hash=_word(data, 1, "evalReportHash"),
        patch_hash=_word(data, 2, "patchHash"),
        artifact_hash=_word(data, 3, "artifactHash"),
        via_legacy_route=_word_bool(data, 4, "viaLegacyRoute"),
        provenance=_provenance(log),
    )


@dataclass(frozen=True)
class RigEpochInherited:
    """The rig lane's epoch-head publication. Same §17.237 role as :class:`EpochInherited`."""

    epoch: int
    inherited_from_epoch: int
    inherited_parent_root: str
    new_state_root: str
    from_genesis: bool
    provenance: LogProvenance = LogProvenance()


def decode_rig_epoch_inherited(log: Mapping[str, Any]) -> RigEpochInherited:
    _require_topic0(log, RIG_EPOCH_INHERITED_TOPIC0, EVENT_RIG_EPOCH_INHERITED)
    data = _data(log)
    flag = _word_bool(data, 2, "fromGenesis")
    return RigEpochInherited(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        inherited_from_epoch=_topic_uint(log, 2, "inheritedFromEpoch", bits=64),
        inherited_parent_root=_word(data, 0, "inheritedParentRoot"),
        new_state_root=_word(data, 1, "newStateRoot"),
        from_genesis=flag,
        provenance=_provenance(log),
    )


#: The rig epoch context's SIX pins, in the registry's DECLARED order
#: (``RigCoreTexStateRegistry.RigCoreTexEpochContext``). Transcribing this order wrongly would
#: mis-assign every pin without changing the topic0, so it is stated once and consumed twice — by
#: the context decoder and by the finalization decoder, whose seven ``bytes32`` are the final root
#: FOLLOWED BY exactly these six.
RIG_EPOCH_CONTEXT_PINS: Tuple[str, ...] = (
    "epoch_context_root", "core_version_hash", "baseline_manifest_hash",
    "hidden_seed_commit", "work_policy_hash")


@dataclass(frozen=True)
class RigEpochContextSet:
    """The rig lane's epoch LAW publication. NO head field, deliberately.

    The registry's own NatSpec is explicit that ``setEpochContext`` "pins the epoch's LAW; it does
    not, and must not, name the epoch's head" — the §17.237 rule, expressed as a missing field
    rather than as a check that could be forgotten. A decoder that invented a parent here would
    hand a validator a coordinator-selected head.
    """

    epoch: int
    epoch_context_root: str
    core_version_hash: str
    baseline_manifest_hash: str
    hidden_seed_commit: str
    work_policy_hash: str
    provenance: LogProvenance = LogProvenance()

    def pins(self) -> Dict[str, str]:
        return {name: getattr(self, name) for name in RIG_EPOCH_CONTEXT_PINS}


def decode_rig_epoch_context_set(log: Mapping[str, Any]) -> RigEpochContextSet:
    """Decode ``RigCoreTexEpochContextSet``. Five static ``bytes32`` words; nothing dynamic."""
    _require_topic0(log, RIG_EPOCH_CONTEXT_SET_TOPIC0, EVENT_RIG_EPOCH_CONTEXT_SET)
    data = _data(log)
    values = {name: _word(data, index, name)
              for index, name in enumerate(RIG_EPOCH_CONTEXT_PINS)}
    return RigEpochContextSet(epoch=_topic_uint(log, 1, "epoch", bits=64),
                              provenance=_provenance(log), **values)


@dataclass(frozen=True)
class RigEpochFinalized:
    """A SEALED rig epoch: its parent, final root, five frozen pins and transition count.

    ``parent_state_root`` is the root the epoch INHERITED (a recorded historical fact written on
    its first advance), not a re-derivation — which is why a validator can walk the non-empty
    epochs as a chain from these events alone.
    """

    epoch: int
    parent_state_root: str
    final_state_root: str
    epoch_context_root: str
    core_version_hash: str
    baseline_manifest_hash: str
    hidden_seed_commit: str
    work_policy_hash: str
    transitions: int
    provenance: LogProvenance = LogProvenance()

    def pins(self) -> Dict[str, str]:
        return {name: getattr(self, name) for name in RIG_EPOCH_CONTEXT_PINS}


def decode_rig_epoch_finalized(log: Mapping[str, Any]) -> RigEpochFinalized:
    """Decode ``RigCoreTexEpochFinalized``: 7 ``bytes32`` then a ``uint64`` transition count."""
    _require_topic0(log, RIG_EPOCH_FINALIZED_TOPIC0, EVENT_RIG_EPOCH_FINALIZED)
    data = _data(log)
    values = {name: _word(data, 2 + index, name)
              for index, name in enumerate(RIG_EPOCH_CONTEXT_PINS)}
    return RigEpochFinalized(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        parent_state_root=_word(data, 0, "parentStateRoot"),
        final_state_root=_word(data, 1, "finalStateRoot"),
        transitions=_word_uint(data, 7, "transitions", bits=64),
        provenance=_provenance(log),
        **values)


# --------------------------------------------------------------------------- #
# The V4 path — old epochs keep decoding, unchanged
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class V4StateAdvanced:
    """A faithful port of ``decodeCoreTexStateAdvanced``. FIELD NAMES are the TypeScript ones.

    Values match the canonical decoder's bytes; only the rendering differs (bare hex here,
    ``0x``-prefixed there — see the module docstring). This exists so a V5 validator can ingest a
    mixed log feed and still route old epochs to the old law instead of choking on them.
    """

    epoch: int
    transitionIndex: int
    miner: str
    parentStateRoot: str
    newStateRoot: str
    patchHash: str
    evalReportHash: str
    coreVersionHash: str
    corpusRoot: str
    activeFrontierRoot: str
    improvementCredits: int
    wordCount: int
    compactPatchBytes: bytes
    provenance: LogProvenance = LogProvenance()


#: 7 bytes32 + improvementCredits(uint256) + wordCount(uint16) then the bytes pointer = words 0..9.
_V4_ADVANCE_HEAD_WORDS = 10


def decode_v4_state_advanced(log: Mapping[str, Any]) -> V4StateAdvanced:
    """The V4 decode path, kept alive verbatim (§17.236: old deployments stay replayable)."""
    _require_topic0(log, V4_STATE_ADVANCED_TOPIC0, EVENT_V4_STATE_ADVANCED)
    data = _data(log)
    return V4StateAdvanced(
        epoch=_topic_uint(log, 1, "epoch", bits=64),
        transitionIndex=_topic_uint(log, 2, "transitionIndex", bits=64),
        miner=_topic_address(log, 3, "miner"),
        parentStateRoot=_word(data, 0, "parentStateRoot"),
        newStateRoot=_word(data, 1, "newStateRoot"),
        patchHash=_word(data, 2, "patchHash"),
        evalReportHash=_word(data, 3, "evalReportHash"),
        coreVersionHash=_word(data, 4, "coreVersionHash"),
        corpusRoot=_word(data, 5, "corpusRoot"),
        activeFrontierRoot=_word(data, 6, "activeFrontierRoot"),
        improvementCredits=_word_uint(data, 7, "improvementCredits"),
        wordCount=_word_uint(data, 8, "wordCount", bits=16),
        compactPatchBytes=_tail_bytes(data, 9, _V4_ADVANCE_HEAD_WORDS, "compactPatchBytes"),
        provenance=_provenance(log),
    )


#: The decoder each recognised event name routes to.
DECODERS: Dict[str, Callable[[Mapping[str, Any]], Any]] = {
    EVENT_V5_FRONTIER_ADVANCED: decode_frontier_advanced,
    EVENT_V5_EPOCH_FINALIZED: decode_memory_epoch_finalized,
    EVENT_V5_EPOCH_INHERITED: decode_epoch_inherited,
    EVENT_V5_EPOCH_CONTEXT_SET: decode_memory_epoch_context_set,
    EVENT_V5_EPOCH_COMMIT_SET: decode_epoch_commit_set,
    EVENT_V5_EPOCH_SECRET_REVEALED: decode_epoch_secret_revealed,
    EVENT_V5_CREDIT_ACCEPTED: decode_credit_accepted,
    EVENT_V4_STATE_ADVANCED: decode_v4_state_advanced,
    EVENT_RIG_STATE_ADVANCED: decode_rig_state_advanced,
    EVENT_RIG_SCREENER_PASS: decode_rig_screener_pass,
    EVENT_RIG_EPOCH_INHERITED: decode_rig_epoch_inherited,
    EVENT_RIG_EPOCH_FINALIZED: decode_rig_epoch_finalized,
    EVENT_RIG_EPOCH_CONTEXT_SET: decode_rig_epoch_context_set,
}


def decode(log: Mapping[str, Any], deployments: Optional[DeploymentSet] = None):
    """Route + decode in one call. Returns ``(Route, decoded_or_None)``.

    An IGNORE route yields ``(route, None)`` — an unknown topic0 is never an exception. A
    recognised topic0 with no decoder (``CoreTexEpochFinalized``, which the V4 replayer owns)
    also yields ``None``, with the route still naming it.
    """
    r = route(log, deployments)
    if not r.recognised:
        return r, None
    decoder = DECODERS.get(r.event or "")
    if decoder is None:
        return r, None
    return r, decoder(log)


# --------------------------------------------------------------------------- #
# Per-epoch pins (the V4 ``expectedPinsForEpoch`` pattern, without the flat fallback)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class EpochPins:
    """Everything immutable that an epoch pins, read from THAT epoch's confirmed context.

    ``entropy_commitment`` is the field the V4 replayer declares and never reads (see
    ``replay.V4_DEAD_PATH_DEFECT``). Here it is required, and V5 replay checks it.
    ``revealed_secret`` is optional because reveal happens after the epoch's advances.

    THERE IS NO ``parent_frontier_root`` HERE (operator ruling §17.237). An epoch's head is not a
    pin: it is not configured, published or signed by anyone — it is DERIVED from confirmed chain
    history by :func:`sync.derive_epoch_parents`, which mirrors the contract's own resolution
    rule. Keeping a coordinator-published head in the pin set would have made the validator's
    epoch parent a coordinator input, which rule 6 forbids outright.
    """

    epoch: int
    runtime_abi_root: str
    benchmark_law_root: str
    counter_resource_law_root: str
    entropy_commitment: str
    revealed_secret: Optional[str] = None

    def __post_init__(self) -> None:
        fr.check_epoch(self.epoch)
        for field in ("runtime_abi_root", "benchmark_law_root", "counter_resource_law_root",
                      "entropy_commitment"):
            fr.check_root(getattr(self, field), field)
        if self.revealed_secret is not None:
            fr.check_root(self.revealed_secret, "revealed_secret")

    def as_dict(self) -> Dict[str, Any]:
        out = {"epoch": self.epoch,
               "runtime_abi_root": self.runtime_abi_root,
               "benchmark_law_root": self.benchmark_law_root,
               "counter_resource_law_root": self.counter_resource_law_root,
               "entropy_commitment": self.entropy_commitment}
        if self.revealed_secret is not None:
            out["revealed_secret"] = self.revealed_secret
        return out


#: A resolver maps ONE epoch to ITS pins, or ``None``. There is deliberately no flat/global form.
PinResolver = Callable[[int], Optional[EpochPins]]


def resolve_pins(resolver: Optional[PinResolver], epoch: int) -> EpochPins:
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
    if not isinstance(pins, EpochPins):
        raise DispatchTypeError(
            f"pin resolver returned {type(pins).__name__}, expected EpochPins")
    if pins.epoch != epoch:
        raise MissingEpochPinsError(
            f"pin resolver returned pins for epoch {pins.epoch} when asked for {epoch}")
    return pins


def pins_from_mapping(pins: Mapping[int, EpochPins]) -> PinResolver:
    """A resolver over a pre-read ``{epoch: EpochPins}`` map."""
    table = dict(pins)
    return lambda epoch: table.get(epoch)


def build_pins_from_logs(logs: Iterable[Mapping[str, Any]],
                         deployments: Optional[DeploymentSet] = None
                         ) -> Dict[int, EpochPins]:
    """Assemble ``{epoch: EpochPins}`` from CONFIRMED context/commit/reveal logs alone.

    This is the whole "no coordinator API" claim, executable: context set + commit set (+ reveal)
    are public events, so a validator reconstructs every epoch pin from the same log feed it
    replays. An epoch missing either the context or the commit is simply ABSENT from the result —
    the resolver then returns ``None`` and the caller records a backlog entry.
    """
    contexts: Dict[int, MemoryEpochContextSet] = {}
    commits: Dict[int, str] = {}
    secrets: Dict[int, str] = {}
    for log in logs:
        r, decoded = decode(log, deployments)
        if decoded is None:
            continue
        if isinstance(decoded, MemoryEpochContextSet):
            contexts[decoded.epoch] = decoded          # last write wins: pins are re-settable
        elif isinstance(decoded, EpochCommitSet):      # until the commit freezes them
            commits[decoded.epoch] = decoded.epoch_commit
        elif isinstance(decoded, EpochSecretRevealed):
            secrets[decoded.epoch] = decoded.epoch_secret
    out: Dict[int, EpochPins] = {}
    for epoch, ctx in contexts.items():
        commit = commits.get(epoch)
        if commit is None or commit == ZERO_WORD:
            continue                                   # unarmed epoch: no commit, hence no pins
        out[epoch] = EpochPins(
            epoch=epoch,
            runtime_abi_root=ctx.runtime_abi_root,
            benchmark_law_root=ctx.benchmark_law_root,
            counter_resource_law_root=ctx.counter_resource_law_root,
            entropy_commitment=commit,
            revealed_secret=secrets.get(epoch))
    return out


# --------------------------------------------------------------------------- #
# Per-epoch pins, RIG lane
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RigEpochPins:
    """Everything the RIG lane's epoch pins, from that epoch's own confirmed context + commit.

    A DIFFERENT SET FROM :class:`EpochPins`, not a superset, and deliberately a separate type.
    The retired memory lane pinned the three law roots the deterministic evaluation needs
    (``runtime_abi_root``, ``benchmark_law_root``, ``counter_resource_law_root``). The rig registry
    pins the six values it ENFORCES on every advance — four of them are re-checked word by word in
    ``_recordStateAdvance`` and two more are re-checked at finalization — and it pins none of the
    three. They are not two spellings of one idea, and one dataclass that carried both would be
    one ``getattr`` away from checking a rig advance against a law pin no rig contract holds.

    THERE IS NO ``parent_state_root`` HERE, for the §17.237 reason the memory lane's pins have no
    head: an epoch's head is DERIVED from confirmed history (``resolveEpochParent``), never
    configured. The registry's own context struct has no head field for exactly this reason.

    ``entropy_commitment`` comes from the MINING contract's ``EpochCommitSet`` — the arm point,
    and the same event that freezes these pins. ``revealed_secret`` is optional because the reveal
    necessarily happens after the epoch's advances (the mining contract refuses it until the epoch
    has ENDED).
    """

    epoch: int
    epoch_context_root: str
    core_version_hash: str
    baseline_manifest_hash: str
    hidden_seed_commit: str
    work_policy_hash: str
    entropy_commitment: str
    revealed_secret: Optional[str] = None

    def __post_init__(self) -> None:
        fr.check_epoch(self.epoch)
        for field in RIG_EPOCH_CONTEXT_PINS + ("entropy_commitment",):
            fr.check_root(getattr(self, field), field)
        if self.revealed_secret is not None:
            fr.check_root(self.revealed_secret, "revealed_secret")

    def enforced_pins(self) -> Dict[str, str]:
        """The FOUR the registry re-checks on every advance, keyed by the EVENT's field names.

        ``baseline_manifest_hash`` and ``hidden_seed_commit`` are excluded on purpose: the advance
        path does not carry them, so a validator that "checked" them against an advance would be
        comparing a pin against a value the log never asserted.
        """
        return {"epoch_context_root": self.epoch_context_root,
                "core_version_hash": self.core_version_hash,
                "work_policy_hash": self.work_policy_hash}

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
    registry's ``RigCoreTexEpochContextSet`` and the mining contract's ``EpochCommitSet`` are
    public events, so a validator reconstructs every rig epoch pin from the same log feed it
    replays — no coordinator API, no operator file.

    An epoch missing EITHER the context or the commit is ABSENT from the result rather than
    partially present: an unarmed epoch's pins are still re-settable, so treating a context-only
    epoch as pinned would let a later ``setEpochContext`` silently change what a replay checked
    against. That is exactly the freeze rule the registry enforces on chain
    (``EpochCommitAlreadySet``), mirrored here.

    Contexts use LAST-WRITE-WINS up to the commit, which is the same reason: before the arm point
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


# --------------------------------------------------------------------------- #
# Encoding (test doubles + local-chain fixtures; never used against a live chain)
# --------------------------------------------------------------------------- #
def _pad_word(value: int) -> str:
    return f"{value:064x}"


def encode_frontier_advanced_log(*, address: str, epoch: int, transition_index: int, miner: str,
                                 parent_frontier_root: str, new_frontier_root: str,
                                 candidate_release_root: str, composition_root: str,
                                 eval_report_hash: str, benchmark_law_root: str,
                                 runtime_abi_root: str, transition_bytes: bytes,
                                 block_number: int = 0, log_index: int = 0,
                                 transaction_hash: Optional[str] = None) -> Dict[str, Any]:
    """Encode a V5 advance log exactly as the contract emits it.

    Present so the decoder is tested against the real ABI layout rather than against itself, and
    so V5-G's local-chain proof has a byte-level reference. It writes nothing and calls nothing.
    """
    head = "".join(_pad_word(int(r, 16)) for r in (
        parent_frontier_root, new_frontier_root, candidate_release_root, composition_root,
        eval_report_hash, benchmark_law_root, runtime_abi_root))
    payload = bytes(transition_bytes)
    padded = payload + b"\x00" * ((WORD - len(payload) % WORD) % WORD)
    data = (head + _pad_word(_ADVANCE_HEAD_WORDS * WORD) + _pad_word(len(payload))
            + padded.hex())
    return {
        "address": address,
        "topics": [to_0x(V5_FRONTIER_ADVANCED_TOPIC0), to_0x(_pad_word(epoch)),
                   to_0x(_pad_word(transition_index)),
                   to_0x(_pad_word(int(miner[2:] if miner.startswith("0x") else miner, 16)))],
        "data": "0x" + data,
        "blockNumber": block_number,
        "logIndex": log_index,
        "transactionHash": transaction_hash or ("0x" + _pad_word(block_number * 1000 + log_index)),
    }


def encode_epoch_inherited_log(*, address: str, epoch: int, inherited_from_epoch: int,
                               inherited_parent_root: str, new_frontier_root: str,
                               from_genesis: bool, block_number: int = 0, log_index: int = 0,
                               transaction_hash: Optional[str] = None) -> Dict[str, Any]:
    """Encode the epoch-head publication exactly as the registry emits it."""
    return {
        "address": address,
        "topics": [to_0x(V5_EPOCH_INHERITED_TOPIC0), to_0x(_pad_word(epoch)),
                   to_0x(_pad_word(inherited_from_epoch))],
        "data": "0x" + _pad_word(int(inherited_parent_root, 16))
                + _pad_word(int(new_frontier_root, 16)) + _pad_word(1 if from_genesis else 0),
        "blockNumber": block_number,
        "logIndex": log_index,
        "transactionHash": transaction_hash or ("0x" + _pad_word(block_number * 1000 + log_index)),
    }


def encode_simple_log(*, address: str, topic0: str, indexed: Sequence[str],
                      words: Sequence[str], block_number: int = 0,
                      log_index: int = 0) -> Dict[str, Any]:
    """Encode a fully-static event (context set, commit set, reveal, credit accepted)."""
    return {
        "address": address,
        "topics": [to_0x(topic0)] + [to_0x(t) for t in indexed],
        "data": "0x" + "".join(words),
        "blockNumber": block_number,
        "logIndex": log_index,
        "transactionHash": "0x" + _pad_word(block_number * 1000 + log_index),
    }
