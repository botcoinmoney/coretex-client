# SPDX-License-Identifier: Apache-2.0
"""The rig lane's event surface, derived from the EXACT deployed contracts.

READ THIS BEFORE CHANGING ANYTHING HERE.

:mod:`.dispatch` carries a rig table too — ``RigCoreTexStateAdvanced``,
``RigCoreTexScreenerPassRecorded``, ``RigCoreTexEpochInherited``, ``RigCoreTexEpochContextSet``,
``RigCoreTexEpochFinalized``. **No deployed contract emits any of them.** Grepping the exact rig
sources (``botcoin-mining-rigs`` @ ``cdb91d21`` plus ``RigCoreTexStateRegistry.sol``) for those
five names returns nothing. The staged table was written against a design that the exact-source
vendoring superseded, and it is preserved in :mod:`.dispatch` as history — a decoder for a
protocol that was never deployed — rather than deleted, because deleting it would erase the
evidence of what changed. Everything a real rig deployment emits is HERE.

THE FACT THAT FORCED THIS MODULE TO EXIST. The registry's advance event is::

    CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,
                         bytes32,uint256,uint16,bytes)

which hashes to ``f2b42259…``. Descriptor-v3 collapsed the two context words into one
``epochContextRoot``, so the live topic deliberately moved. The previous ``2f0a8989…`` topic is
kept below as an explicitly legacy descriptor-v2 decoder and is never accepted by the live route.

Three consequences, all load-bearing, all asserted below rather than left as prose:

Live routing remains address-scoped because topic0 alone never identifies a deployment. A legacy
descriptor-v2 log is decoded only by an explicitly named legacy function; the live route has no
dual-accept branch.

WHERE EACH EVENT LIVES. This is the other thing the staged table got wrong: the rig lane's epoch
context is emitted by the **verifier**, not the registry (design §4, "Epoch context is DELEGATED,
not owned"), and the credit is emitted by **mining**. Three contracts, one lane.

    ==========================  ===========================================================
    ``registry``                ``CoreTexStateAdvanced``, ``CoreTexEpochFinalized``
    ``mining``                  ``RigCoreTexCreditAccepted``, ``RigCreditAccepted``,
                                ``EpochCommitSet``, ``EpochSecretRevealed``
    ``verifier``                ``CoreTexEpochContextSet``, ``CoreTexPolicyScheduled``
    ==========================  ===========================================================

There is NO screener-pass event anywhere. Priced work that did not move the root is visible only
as a ``RigCoreTexCreditAccepted`` with no advance in the same transaction — which is exactly the
shape :mod:`.join` keys on, and exactly why §7.5's fall-through rule exists.

DECODING IS DELEGATED, NOT REIMPLEMENTED. The word/topic readers come from :mod:`.dispatch`. They
are strict (length a multiple of 32, tail offsets in range and aligned, padding zero, no dirty
high bits in narrow topics) and there must be exactly one such implementation, or the two will
disagree on a malformed log and only one of them will be right.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import dispatch as dp
from . import frontier as fr
from .keccak256 import keccak256_hex

#: The protocol identifier for what the exact contracts deploy. Distinct from
#: ``dispatch.PROTOCOL_RIG`` ("coretex.rig-state.v1"), which names the STAGED, never-deployed
#: event set — conflating the two is precisely the mistake this module exists to prevent.
PROTOCOL_RIG_EXACT = "coretex.rig-state.exact/v3"


# --------------------------------------------------------------------------- #
# Signatures — transcribed from the exact sources, hashed here, never copied as digests
# --------------------------------------------------------------------------- #
#: ``rig/mining/RigCoreTexRegistry.sol`` at canonical descriptor-v3.
STATE_ADVANCED_SIG = (
    "CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "uint256,uint16,bytes)")
EPOCH_FINALIZED_SIG = (
    "CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)")
#: ``BotcoinMiningRigsV1.sol:165-174``. The join's source B.
CORETEX_CREDIT_ACCEPTED_SIG = (
    "RigCoreTexCreditAccepted(uint64,uint256,address,uint64,bytes32,bytes32,uint256,uint256)")
#: ``BotcoinMiningRigsV1.sol:155-163``. The STANDARD (non-CoreTex) receipt, which shares the rig's
#: ``rigNextIndex``/``rigLastReceiptHash`` chain — so receipt-continuity replay must consume it.
CREDIT_ACCEPTED_SIG = (
    "RigCreditAccepted(uint64,uint256,address,uint64,bytes32,bytes32,uint256)")
EPOCH_COMMIT_SET_SIG = "EpochCommitSet(uint64,bytes32)"
EPOCH_SECRET_REVEALED_SIG = "EpochSecretRevealed(uint64,bytes32)"
#: ``RigCoreTexVerifier.sol:82-89`` — the epoch's law pins, on the VERIFIER.
EPOCH_CONTEXT_SET_SIG = "CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32)"

# Explicit descriptor-v2 history. These signatures are not members of RIG_LOG_TOPICS and are
# never routed as live events. Callers replaying a genuine retired deployment must opt in by name.
LEGACY_V2_STATE_ADVANCED_SIG = (
    "CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32,uint256,uint16,bytes)")
LEGACY_V2_EPOCH_FINALIZED_SIG = (
    "CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)")
LEGACY_V2_EPOCH_CONTEXT_SET_SIG = (
    "CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32,bytes32,bytes32)")
#: ``RigCoreTexVerifier.sol:90-97`` — the scoring law, scheduled by ``effectiveEpoch``. This is
#: what makes HISTORICAL law recoverable: a policy is announced for the epoch it starts applying
#: at, so "the law at that transition" is a lookup, not an assumption about today.
POLICY_SCHEDULED_SIG = (
    "CoreTexPolicyScheduled(uint32,uint64,bytes32,uint256,uint256[],uint256[])")

#: EVERY topic0 here is DERIVED from the signature above it. Four of them are ALSO pinned as
#: literals below, and the two sets are cross-checked at import: pinning is worth its maintenance
#: cost exactly where a digest is SHARED with another lane, because there a silent signature edit
#: would re-route confirmed history rather than fail. For the rig's own new events the derivation
#: is the sole authority; a hand-copied digest would only add a way to be wrong.
STATE_ADVANCED_TOPIC0 = dp.event_topic(STATE_ADVANCED_SIG)
EPOCH_FINALIZED_TOPIC0 = dp.event_topic(EPOCH_FINALIZED_SIG)
CORETEX_CREDIT_ACCEPTED_TOPIC0 = dp.event_topic(CORETEX_CREDIT_ACCEPTED_SIG)
CREDIT_ACCEPTED_TOPIC0 = dp.event_topic(CREDIT_ACCEPTED_SIG)
EPOCH_COMMIT_SET_TOPIC0 = dp.event_topic(EPOCH_COMMIT_SET_SIG)
EPOCH_SECRET_REVEALED_TOPIC0 = dp.event_topic(EPOCH_SECRET_REVEALED_SIG)
EPOCH_CONTEXT_SET_TOPIC0 = dp.event_topic(EPOCH_CONTEXT_SET_SIG)
POLICY_SCHEDULED_TOPIC0 = dp.event_topic(POLICY_SCHEDULED_SIG)
LEGACY_V2_STATE_ADVANCED_TOPIC0 = dp.event_topic(LEGACY_V2_STATE_ADVANCED_SIG)
LEGACY_V2_EPOCH_FINALIZED_TOPIC0 = dp.event_topic(LEGACY_V2_EPOCH_FINALIZED_SIG)
LEGACY_V2_EPOCH_CONTEXT_SET_TOPIC0 = dp.event_topic(LEGACY_V2_EPOCH_CONTEXT_SET_SIG)

_PINNED = {
    STATE_ADVANCED_TOPIC0: "f2b422592475276aa1bbea8c780acec02e5628df6e59392a7ce6625907ca54e7",
    EPOCH_FINALIZED_TOPIC0: "212234825d6a82269e63c2bc21582948deb7729436c4dcba0dfdd831351c43b2",
    EPOCH_CONTEXT_SET_TOPIC0: "024a552750f4344a8386eb7109fcbdfd7c822052efcc0cf8c92d0619a3cec80f",
    LEGACY_V2_STATE_ADVANCED_TOPIC0: "2f0a89894d44aa2294de109d294ac072f0e206dc834a0c35c6fbf1623ec02dd0",
    LEGACY_V2_EPOCH_FINALIZED_TOPIC0: "7c882e64d34d7e0b82f8004ec182f5b9e942388f7b7b1ea60233306c02821085",
    EPOCH_COMMIT_SET_TOPIC0: "59292804aa2c2d886e7b2e3982ee2e6df6e3d52f35220fbcafc233d216f7ddf6",
    EPOCH_SECRET_REVEALED_TOPIC0:
        "874024d45050fc7f9a2b883212a09399fe2d44dcff11ef6e75782efd2bc22bb6",
}
for _derived, _pin in _PINNED.items():
    if _derived != _pin:                                    # pragma: no cover - fail closed
        raise RuntimeError(f"topic0 drift: derived {_derived}, pinned {_pin}")

# The previous deployment remains identifiable, while the live path must not collide with it.
if LEGACY_V2_STATE_ADVANCED_TOPIC0 != dp.V4_STATE_ADVANCED_TOPIC0:  # pragma: no cover
    raise RuntimeError("the explicit legacy-v2 advance pin drifted from its genuine deployment")
if STATE_ADVANCED_TOPIC0 == LEGACY_V2_STATE_ADVANCED_TOPIC0:       # pragma: no cover
    raise RuntimeError("descriptor-v3 live advance topic unexpectedly equals retired v2")

#: The ``eth_getLogs`` topic0 OR-set a rig validator actually subscribes to. Compare
#: ``dispatch.RIG_TOPICS``, which contains none of the advance/credit/context topics a real
#: deployment emits.
RIG_LOG_TOPICS: Tuple[str, ...] = tuple(sorted({
    STATE_ADVANCED_TOPIC0, EPOCH_FINALIZED_TOPIC0, CORETEX_CREDIT_ACCEPTED_TOPIC0,
    CREDIT_ACCEPTED_TOPIC0, EPOCH_COMMIT_SET_TOPIC0, EPOCH_SECRET_REVEALED_TOPIC0,
    EPOCH_CONTEXT_SET_TOPIC0, POLICY_SCHEDULED_TOPIC0}))

EVENT_NAMES: Dict[str, str] = {
    STATE_ADVANCED_TOPIC0: "CoreTexStateAdvanced",
    EPOCH_FINALIZED_TOPIC0: "CoreTexEpochFinalized",
    CORETEX_CREDIT_ACCEPTED_TOPIC0: "RigCoreTexCreditAccepted",
    CREDIT_ACCEPTED_TOPIC0: "RigCreditAccepted",
    EPOCH_COMMIT_SET_TOPIC0: "EpochCommitSet",
    EPOCH_SECRET_REVEALED_TOPIC0: "EpochSecretRevealed",
    EPOCH_CONTEXT_SET_TOPIC0: "CoreTexEpochContextSet",
    POLICY_SCHEDULED_TOPIC0: "CoreTexPolicyScheduled",
}


class RigEventError(dp.DispatchError):
    """A log that names a rig event but is not a well-formed encoding of it."""


class RigAddressError(dp.DispatchError):
    """A log from an address this deployment does not claim. Never downgraded to a warning."""


# --------------------------------------------------------------------------- #
# Deployment identity
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RigDeployment:
    """The three addresses that make one rig lane, plus the chain it lives on.

    All three are REQUIRED. A validator that knew only the registry could not tell a credit event
    apart from any other contract's event with the same topic0, and could not read the epoch's law
    pins at all — they are on the verifier.
    """

    chain_id: int
    registry: str
    mining: str
    verifier: str

    def __post_init__(self) -> None:
        for name in ("registry", "mining", "verifier"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
                raise RigAddressError(f"{name} must be a 0x-prefixed 20-byte address, got {value!r}")
        lowered = {n: getattr(self, n).lower() for n in ("registry", "mining", "verifier")}
        if len(set(lowered.values())) != 3:
            raise RigAddressError(
                f"registry/mining/verifier must be three DISTINCT addresses: {lowered}")

    def role_of(self, address: str) -> Optional[str]:
        target = str(address or "").lower()
        for name in ("registry", "mining", "verifier"):
            if getattr(self, name).lower() == target:
                return name
        return None

    @property
    def addresses(self) -> Tuple[str, str, str]:
        return (self.registry, self.mining, self.verifier)


#: Which contract each event is only ever legitimate from. A ``CoreTexStateAdvanced`` from the
#: MINING address is not a rig advance with an odd emitter — it is a different protocol's log that
#: happens to share a topic0, and treating it as an advance is how lanes get mixed.
EXPECTED_EMITTER: Dict[str, str] = {
    STATE_ADVANCED_TOPIC0: "registry",
    EPOCH_FINALIZED_TOPIC0: "registry",
    CORETEX_CREDIT_ACCEPTED_TOPIC0: "mining",
    CREDIT_ACCEPTED_TOPIC0: "mining",
    EPOCH_COMMIT_SET_TOPIC0: "mining",
    EPOCH_SECRET_REVEALED_TOPIC0: "mining",
    EPOCH_CONTEXT_SET_TOPIC0: "verifier",
    POLICY_SCHEDULED_TOPIC0: "verifier",
}


@dataclass(frozen=True)
class RigRoute:
    """What a log is, once its address has been consulted. ``None`` name = not ours, ignore it."""

    protocol: Optional[str]
    event: Optional[str]
    emitter_role: Optional[str]
    topic0: str


def route_rig_log(log: Mapping[str, Any], deployment: RigDeployment) -> RigRoute:
    """Classify one log against a deployment. UNKNOWN is ignored; MISPLACED is an error.

    The distinction matters. An unknown topic0 means the registry gained an administrative event a
    field validator has never heard of — ignoring it is the only behaviour that does not brick
    every deployed validator on the next upgrade. A KNOWN topic0 from the WRONG one of our three
    addresses is different: something is emitting our events from a contract we did not expect,
    and continuing would mean deciding which of two contradictory claims to believe.
    """
    topics = log.get("topics") or ()
    if not topics:
        return RigRoute(None, None, None, "")
    topic0 = dp.from_0x(topics[0], "topics[0]").hex()
    name = EVENT_NAMES.get(topic0)
    role = deployment.role_of(log.get("address", ""))
    if name is None:
        return RigRoute(None, None, role, topic0)
    if role is None:
        # Not one of ours. A shared topic0 (the V4 collision) makes this the COMMON case, not an
        # exceptional one, so it is a quiet "not mine" rather than an error.
        return RigRoute(None, None, None, topic0)
    expected = EXPECTED_EMITTER[topic0]
    if role != expected:
        raise RigAddressError(
            f"{name} arrived from this deployment's {role} ({log.get('address')}) but only the "
            f"{expected} emits it; topic0 is not an identity and this log cannot be attributed")
    return RigRoute(PROTOCOL_RIG_EXACT, name, role, topic0)


# --------------------------------------------------------------------------- #
# Decoders
# --------------------------------------------------------------------------- #
def _require(log: Mapping[str, Any], topic0: str, name: str) -> None:
    dp._require_topic0(log, topic0, name)                                      # noqa: SLF001


@dataclass(frozen=True)
class StateAdvanced:
    """The confirmed transition — join source A (design §7.1).

    ``compact_patch_bytes`` is the VERBATIM patch, not a hash of it. That is the property that
    makes log-only patch reconstruction possible (§7.3) and it is why :attr:`patch_hash` can be
    re-derived here rather than trusted.
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
    #: ``uint16 transitionFormatVersion`` — renamed from ``wordCount`` by
    #: it is the zero-extension of the 97-byte descriptor's version byte, not a word count.
    transition_format_version: int
    compact_patch_bytes: bytes
    provenance: dp.LogProvenance

    #: The §7.4 primary key. ``transition_index`` is NOT in it: it is a per-epoch ordering, dense
    #: and zero-based, and using it across epochs (or as an identity) is the documented mistake.
    @property
    def join_key(self) -> Tuple[int, str, str]:
        return (self.epoch, self.parent_state_root, self.patch_hash)


_ADVANCE_HEAD_WORDS = 9


def decode_state_advanced(log: Mapping[str, Any]) -> StateAdvanced:
    _require(log, STATE_ADVANCED_TOPIC0, "CoreTexStateAdvanced")
    data = dp._data(log)                                                       # noqa: SLF001
    patch = dp._tail_bytes(data, 8, _ADVANCE_HEAD_WORDS, "compactPatchBytes")   # noqa: SLF001
    return StateAdvanced(
        epoch=dp._topic_uint(log, 1, "epoch", bits=64),                         # noqa: SLF001
        transition_index=dp._topic_uint(log, 2, "transitionIndex", bits=64),    # noqa: SLF001
        miner=dp._topic_address(log, 3, "miner"),                               # noqa: SLF001
        parent_state_root=dp._word(data, 0, "parentStateRoot"),                 # noqa: SLF001
        new_state_root=dp._word(data, 1, "newStateRoot"),                       # noqa: SLF001
        patch_hash=dp._word(data, 2, "patchHash"),                              # noqa: SLF001
        eval_report_hash=dp._word(data, 3, "evalReportHash"),                   # noqa: SLF001
        core_version_hash=dp._word(data, 4, "coreVersionHash"),                 # noqa: SLF001
        epoch_context_root=dp._word(data, 5, "epochContextRoot"),               # noqa: SLF001
        improvement_credits=dp._word_uint(data, 6, "improvementCredits"),       # noqa: SLF001
        transition_format_version=dp._word_uint(data, 7, "transitionFormatVersion",  # noqa: SLF001
                                                 bits=16),
        compact_patch_bytes=patch,
        provenance=dp._provenance(log))                                         # noqa: SLF001


@dataclass(frozen=True)
class EpochFinalized:
    epoch: int
    parent_state_root: str
    final_state_root: str
    core_version_hash: str
    epoch_context_root: str
    patch_set_root: str
    score_root: str
    provenance: dp.LogProvenance


def decode_epoch_finalized(log: Mapping[str, Any]) -> EpochFinalized:
    _require(log, EPOCH_FINALIZED_TOPIC0, "CoreTexEpochFinalized")
    data = dp._data(log)                                                       # noqa: SLF001
    names = ("parent_state_root", "final_state_root", "core_version_hash",
             "epoch_context_root", "patch_set_root", "score_root")
    values = {n: dp._word(data, i, n) for i, n in enumerate(names)}            # noqa: SLF001
    return EpochFinalized(epoch=dp._topic_uint(log, 1, "epoch", bits=64),      # noqa: SLF001
                          provenance=dp._provenance(log), **values)            # noqa: SLF001


@dataclass(frozen=True)
class CoreTexCreditAccepted:
    """Join source B (design §7.1). ``receipt_hash`` is the value step 4 must reproduce."""

    epoch: int
    rig_id: int
    operator: str
    solve_index: int
    receipt_hash: str
    challenge_id: str
    work_units_bps: int
    credits_earned: int
    provenance: dp.LogProvenance
    #: ``True`` for the CoreTex receipt, ``False`` for the standard one. Both advance the SAME
    #: per-rig chain, which is the whole reason receipt-continuity replay has to see both.
    coretex: bool = True


def decode_coretex_credit(log: Mapping[str, Any]) -> CoreTexCreditAccepted:
    _require(log, CORETEX_CREDIT_ACCEPTED_TOPIC0, "RigCoreTexCreditAccepted")
    data = dp._data(log)                                                       # noqa: SLF001
    return CoreTexCreditAccepted(
        epoch=dp._topic_uint(log, 1, "epochId", bits=64),                       # noqa: SLF001
        rig_id=dp._topic_uint256(log, 2, "rigId"),                              # noqa: SLF001
        operator=dp._topic_address(log, 3, "operator"),                         # noqa: SLF001
        solve_index=dp._word_uint(data, 0, "solveIndex", bits=64),              # noqa: SLF001
        receipt_hash=dp._word(data, 1, "receiptHash"),                          # noqa: SLF001
        challenge_id=dp._word(data, 2, "challengeId"),                          # noqa: SLF001
        work_units_bps=dp._word_uint(data, 3, "workUnitsBps"),                  # noqa: SLF001
        credits_earned=dp._word_uint(data, 4, "creditsEarned"),                 # noqa: SLF001
        provenance=dp._provenance(log), coretex=True)                           # noqa: SLF001


def decode_standard_credit(log: Mapping[str, Any]) -> CoreTexCreditAccepted:
    """``RigCreditAccepted`` — no ``workUnitsBps``, same rig receipt chain."""
    _require(log, CREDIT_ACCEPTED_TOPIC0, "RigCreditAccepted")
    data = dp._data(log)                                                       # noqa: SLF001
    return CoreTexCreditAccepted(
        epoch=dp._topic_uint(log, 1, "epochId", bits=64),                       # noqa: SLF001
        rig_id=dp._topic_uint256(log, 2, "rigId"),                              # noqa: SLF001
        operator=dp._topic_address(log, 3, "operator"),                         # noqa: SLF001
        solve_index=dp._word_uint(data, 0, "solveIndex", bits=64),              # noqa: SLF001
        receipt_hash=dp._word(data, 1, "receiptHash"),                          # noqa: SLF001
        challenge_id=dp._word(data, 2, "challengeId"),                          # noqa: SLF001
        work_units_bps=0,
        credits_earned=dp._word_uint(data, 3, "creditsEarned"),                 # noqa: SLF001
        provenance=dp._provenance(log), coretex=False)                          # noqa: SLF001


#: The three canonical pins: the context parent seeds live state; the manifest root carries all
#: admission inputs; the core version identifies the active bundle.
EPOCH_CONTEXT_EVENT_FIELDS = ("parent_state_root", "epoch_context_root", "core_version_hash")


@dataclass(frozen=True)
class EpochContextSet:
    epoch: int
    parent_state_root: str
    epoch_context_root: str
    core_version_hash: str
    provenance: dp.LogProvenance

    def law_pins(self) -> Dict[str, str]:
        """The two context values an advance carries and the registry enforces. NOT the head."""
        return {"epoch_context_root": self.epoch_context_root,
                "core_version_hash": self.core_version_hash}


def decode_epoch_context_set(log: Mapping[str, Any]) -> EpochContextSet:
    _require(log, EPOCH_CONTEXT_SET_TOPIC0, "CoreTexEpochContextSet")
    data = dp._data(log)                                                       # noqa: SLF001
    values = {n: dp._word(data, i, n)
              for i, n in enumerate(EPOCH_CONTEXT_EVENT_FIELDS)}                  # noqa: SLF001
    return EpochContextSet(epoch=dp._topic_uint(log, 1, "epochId", bits=64),   # noqa: SLF001
                           provenance=dp._provenance(log), **values)           # noqa: SLF001


@dataclass(frozen=True)
class LegacyV2StateAdvanced:
    """Genuine retired descriptor-v2 deployment event. Never returned by the live router."""

    epoch: int
    transition_index: int
    miner: str
    parent_state_root: str
    new_state_root: str
    patch_hash: str
    eval_report_hash: str
    core_version_hash: str
    corpus_root: str
    active_frontier_root: str
    improvement_credits: int
    transition_format_version: int
    compact_patch_bytes: bytes
    provenance: dp.LogProvenance

    @property
    def join_key(self) -> Tuple[int, str, str]:
        return (self.epoch, self.parent_state_root, self.patch_hash)


def decode_legacy_v2_state_advanced(log: Mapping[str, Any]) -> LegacyV2StateAdvanced:
    """Decode only the genuine 13-field descriptor-v2 advance shape."""
    _require(log, LEGACY_V2_STATE_ADVANCED_TOPIC0, "LegacyV2CoreTexStateAdvanced")
    data = dp._data(log)                                                       # noqa: SLF001
    patch = dp._tail_bytes(data, 9, 10, "compactPatchBytes")                  # noqa: SLF001
    return LegacyV2StateAdvanced(
        epoch=dp._topic_uint(log, 1, "epoch", bits=64),                        # noqa: SLF001
        transition_index=dp._topic_uint(log, 2, "transitionIndex", bits=64),  # noqa: SLF001
        miner=dp._topic_address(log, 3, "miner"),                              # noqa: SLF001
        parent_state_root=dp._word(data, 0, "parentStateRoot"),                # noqa: SLF001
        new_state_root=dp._word(data, 1, "newStateRoot"),                      # noqa: SLF001
        patch_hash=dp._word(data, 2, "patchHash"),                             # noqa: SLF001
        eval_report_hash=dp._word(data, 3, "evalReportHash"),                  # noqa: SLF001
        core_version_hash=dp._word(data, 4, "coreVersionHash"),                # noqa: SLF001
        corpus_root=dp._word(data, 5, "corpusRoot"),                           # noqa: SLF001
        active_frontier_root=dp._word(data, 6, "activeFrontierRoot"),          # noqa: SLF001
        improvement_credits=dp._word_uint(data, 7, "improvementCredits"),      # noqa: SLF001
        transition_format_version=dp._word_uint(                               # noqa: SLF001
            data, 8, "transitionFormatVersion", bits=16),
        compact_patch_bytes=patch,
        provenance=dp._provenance(log))                                        # noqa: SLF001


@dataclass(frozen=True)
class LegacyV2EpochFinalized:
    epoch: int
    parent_state_root: str
    final_state_root: str
    core_version_hash: str
    corpus_root: str
    active_frontier_root: str
    patch_set_root: str
    score_root: str
    baseline_manifest_hash: str
    provenance: dp.LogProvenance


def decode_legacy_v2_epoch_finalized(log: Mapping[str, Any]) -> LegacyV2EpochFinalized:
    """Decode only the genuine retired descriptor-v2 finalization shape."""
    _require(log, LEGACY_V2_EPOCH_FINALIZED_TOPIC0, "LegacyV2CoreTexEpochFinalized")
    data = dp._data(log)                                                       # noqa: SLF001
    names = ("parent_state_root", "final_state_root", "core_version_hash", "corpus_root",
             "active_frontier_root", "patch_set_root", "score_root", "baseline_manifest_hash")
    values = {n: dp._word(data, i, n) for i, n in enumerate(names)}           # noqa: SLF001
    return LegacyV2EpochFinalized(
        epoch=dp._topic_uint(log, 1, "epoch", bits=64),                        # noqa: SLF001
        provenance=dp._provenance(log), **values)                              # noqa: SLF001


@dataclass(frozen=True)
class EpochCommitSet:
    epoch: int
    entropy_commitment: str
    provenance: dp.LogProvenance


def decode_epoch_commit_set(log: Mapping[str, Any]) -> EpochCommitSet:
    _require(log, EPOCH_COMMIT_SET_TOPIC0, "EpochCommitSet")
    return EpochCommitSet(epoch=dp._topic_uint(log, 1, "epochId", bits=64),    # noqa: SLF001
                          entropy_commitment=dp._topic_bytes32(log, 2, "epochCommit"),  # noqa: SLF001,E501
                          provenance=dp._provenance(log))                      # noqa: SLF001


@dataclass(frozen=True)
class EpochSecretRevealed:
    epoch: int
    revealed_secret: str
    provenance: dp.LogProvenance


def decode_epoch_secret_revealed(log: Mapping[str, Any]) -> EpochSecretRevealed:
    _require(log, EPOCH_SECRET_REVEALED_TOPIC0, "EpochSecretRevealed")
    return EpochSecretRevealed(epoch=dp._topic_uint(log, 1, "epochId", bits=64),  # noqa: SLF001
                               revealed_secret=dp._word(dp._data(log), 0, "secret"),  # noqa: SLF001,E501
                               provenance=dp._provenance(log))                 # noqa: SLF001


@dataclass(frozen=True)
class PolicyScheduled:
    """A scoring-law version and the epoch it STARTS applying at — the historical-law index."""

    rules_version: int
    effective_epoch: int
    policy_hash: str
    screener_work_bps: int
    provenance: dp.LogProvenance


def decode_policy_scheduled(log: Mapping[str, Any]) -> PolicyScheduled:
    _require(log, POLICY_SCHEDULED_TOPIC0, "CoreTexPolicyScheduled")
    data = dp._data(log)                                                       # noqa: SLF001
    return PolicyScheduled(
        rules_version=dp._topic_uint(log, 1, "rulesVersion", bits=32),          # noqa: SLF001
        effective_epoch=dp._topic_uint(log, 2, "effectiveEpoch", bits=64),      # noqa: SLF001
        policy_hash=dp._topic_bytes32(log, 3, "policyHash"),                    # noqa: SLF001
        screener_work_bps=dp._word_uint(data, 0, "screenerWorkBps"),            # noqa: SLF001
        provenance=dp._provenance(log))                                         # noqa: SLF001


_DECODERS = {
    STATE_ADVANCED_TOPIC0: decode_state_advanced,
    EPOCH_FINALIZED_TOPIC0: decode_epoch_finalized,
    CORETEX_CREDIT_ACCEPTED_TOPIC0: decode_coretex_credit,
    CREDIT_ACCEPTED_TOPIC0: decode_standard_credit,
    EPOCH_COMMIT_SET_TOPIC0: decode_epoch_commit_set,
    EPOCH_SECRET_REVEALED_TOPIC0: decode_epoch_secret_revealed,
    EPOCH_CONTEXT_SET_TOPIC0: decode_epoch_context_set,
    POLICY_SCHEDULED_TOPIC0: decode_policy_scheduled,
}


def decode(log: Mapping[str, Any], deployment: RigDeployment):
    """Route, then decode. ``None`` for anything that is not this deployment's."""
    route = route_rig_log(log, deployment)
    if route.protocol is None:
        return None
    return _DECODERS[route.topic0](log)


@dataclass
class DecodedLogs:
    """Everything one scan produced, split by kind and kept in chain order.

    Order is preserved rather than re-sorted: within a transaction the advance PRECEDES the credit
    (mining calls the verifier at ``:450`` and emits at ``:454``), and the join relies on that.
    """

    advances: List[StateAdvanced]
    coretex_credits: List[CoreTexCreditAccepted]
    standard_credits: List[CoreTexCreditAccepted]
    finalizations: List[EpochFinalized]
    contexts: List[EpochContextSet]
    commits: List[EpochCommitSet]
    reveals: List[EpochSecretRevealed]
    policies: List[PolicyScheduled]
    ignored: int = 0

    def context_for(self, epoch: int) -> Optional[EpochContextSet]:
        """The LAST context set for an epoch. The verifier refuses a re-set after the epoch is
        armed, so at most one can survive arming; taking the last is correct either way."""
        found = [c for c in self.contexts if c.epoch == int(epoch)]
        return found[-1] if found else None


def scan(logs: Iterable[Mapping[str, Any]], deployment: RigDeployment) -> DecodedLogs:
    out = DecodedLogs([], [], [], [], [], [], [], [])
    buckets = {
        StateAdvanced: out.advances, EpochFinalized: out.finalizations,
        EpochContextSet: out.contexts, EpochCommitSet: out.commits,
        EpochSecretRevealed: out.reveals, PolicyScheduled: out.policies,
    }
    for log in logs:
        decoded = decode(log, deployment)
        if decoded is None:
            out.ignored += 1
            continue
        if isinstance(decoded, CoreTexCreditAccepted):
            (out.coretex_credits if decoded.coretex else out.standard_credits).append(decoded)
            continue
        buckets[type(decoded)].append(decoded)
    return out


def scan_legacy_v2(logs: Iterable[Mapping[str, Any]], deployment: RigDeployment) -> DecodedLogs:
    """Explicit historical scanner for a genuine descriptor-v2 deployment.

    It is intentionally separate from :func:`scan`: a live descriptor-v3 subscription never
    dual-accepts the retired advance/finalization topics.
    """
    out = DecodedLogs([], [], [], [], [], [], [], [])
    common = {
        CORETEX_CREDIT_ACCEPTED_TOPIC0: decode_coretex_credit,
        CREDIT_ACCEPTED_TOPIC0: decode_standard_credit,
        EPOCH_COMMIT_SET_TOPIC0: decode_epoch_commit_set,
        EPOCH_SECRET_REVEALED_TOPIC0: decode_epoch_secret_revealed,
        POLICY_SCHEDULED_TOPIC0: decode_policy_scheduled,
    }
    for log in logs:
        topics = log.get("topics") or ()
        if not topics:
            out.ignored += 1
            continue
        topic0 = dp.from_0x(topics[0], "topics[0]").hex()
        role = deployment.role_of(log.get("address", ""))
        decoded = None
        if topic0 == LEGACY_V2_STATE_ADVANCED_TOPIC0:
            if role == "registry":
                decoded = decode_legacy_v2_state_advanced(log)
            elif role is not None:
                raise RigAddressError("legacy-v2 CoreTexStateAdvanced came from a non-registry "
                                      f"deployment address {log.get('address')}")
        elif topic0 == LEGACY_V2_EPOCH_FINALIZED_TOPIC0:
            if role == "registry":
                decoded = decode_legacy_v2_epoch_finalized(log)
            elif role is not None:
                raise RigAddressError("legacy-v2 CoreTexEpochFinalized came from a non-registry "
                                      f"deployment address {log.get('address')}")
        elif topic0 in common:
            expected_role = "mining" if topic0 != POLICY_SCHEDULED_TOPIC0 else "verifier"
            if role == expected_role:
                decoded = common[topic0](log)
            elif role is not None:
                raise RigAddressError(f"legacy-v2 event {topic0} came from {role}, expected "
                                      f"{expected_role}")
        if decoded is None:
            out.ignored += 1
        elif isinstance(decoded, LegacyV2StateAdvanced):
            out.advances.append(decoded)  # type: ignore[arg-type]
        elif isinstance(decoded, LegacyV2EpochFinalized):
            out.finalizations.append(decoded)  # type: ignore[arg-type]
        elif isinstance(decoded, CoreTexCreditAccepted):
            (out.coretex_credits if decoded.coretex else out.standard_credits).append(decoded)
        elif isinstance(decoded, EpochCommitSet):
            out.commits.append(decoded)
        elif isinstance(decoded, EpochSecretRevealed):
            out.reveals.append(decoded)
        elif isinstance(decoded, PolicyScheduled):
            out.policies.append(decoded)
    return out


# --------------------------------------------------------------------------- #
# The content-addressed epoch context — coretex.epoch-context/v1
# --------------------------------------------------------------------------- #
EPOCH_CONTEXT_FORMAT = "coretex.epoch-context/v1"
EPOCH_CONTEXT_ROOT_FIELDS: Tuple[str, ...] = (
    "corpus_root", "active_frontier_root", "baseline_manifest_hash", "benchmark_law_root",
    "runtime_abi_root", "counter_resource_law_root", "selection_law_root")
EPOCH_CONTEXT_FIELDS: Tuple[str, ...] = (
    "format", "epoch", "corpus_root", "active_frontier_root", "baseline_manifest_hash",
    "benchmark_law_root", "runtime_abi_root", "counter_resource_law_root",
    "selection_law_root", "admission_thresholds_ppm", "seed_commitment")
EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS: Tuple[str, ...] = (
    "scheme", "binding_rule", "commitment_source")
EPOCH_CONTEXT_UNAVAILABLE = "EPOCH_CONTEXT_UNAVAILABLE"
EPOCH_CONTEXT_MALFORMED = "EPOCH_CONTEXT_MALFORMED"
EPOCH_CONTEXT_ADDRESS_MISMATCH = "EPOCH_CONTEXT_ADDRESS_MISMATCH"


class EpochContextError(RigEventError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _epoch_context_require(condition: Any, code: str, message: str) -> None:
    if not condition:
        raise EpochContextError(code, message)


def validate_epoch_context(manifest: Any) -> Dict[str, Any]:
    """Validate the closed epoch-context document without repairing any spelling."""
    _epoch_context_require(isinstance(manifest, Mapping), EPOCH_CONTEXT_MALFORMED,
                           f"an epoch context must be an object, got {type(manifest).__name__}")
    _epoch_context_require(manifest.get("format") == EPOCH_CONTEXT_FORMAT,
                           EPOCH_CONTEXT_MALFORMED,
                           f"format {manifest.get('format')!r} is not "
                           f"{EPOCH_CONTEXT_FORMAT!r}")
    unknown = sorted(set(manifest) - set(EPOCH_CONTEXT_FIELDS))
    missing = sorted(set(EPOCH_CONTEXT_FIELDS) - set(manifest))
    _epoch_context_require(not unknown, EPOCH_CONTEXT_MALFORMED,
                           f"unknown field(s) {unknown}; the schema is closed")
    _epoch_context_require(not missing, EPOCH_CONTEXT_MALFORMED,
                           f"required field(s) {missing} are absent")
    try:
        fr.check_epoch(manifest["epoch"], "epoch_context.epoch")
        for field in EPOCH_CONTEXT_ROOT_FIELDS:
            root = fr.check_root(manifest[field], f"epoch_context.{field}")
            _epoch_context_require(root != "0" * 64, EPOCH_CONTEXT_MALFORMED,
                                   f"epoch_context.{field} is the all-zero root")
        canonical = fr.canonical_bytes(manifest)
    except fr.FrontierError as exc:
        raise EpochContextError(EPOCH_CONTEXT_MALFORMED, str(exc)) from exc

    thresholds = manifest["admission_thresholds_ppm"]
    _epoch_context_require(isinstance(thresholds, Mapping) and bool(thresholds),
                           EPOCH_CONTEXT_MALFORMED,
                           "epoch_context.admission_thresholds_ppm must be a nonempty object")
    for key, value in thresholds.items():
        _epoch_context_require(isinstance(key, str) and bool(key), EPOCH_CONTEXT_MALFORMED,
                               "admission threshold keys must be nonempty strings")
        _epoch_context_require(isinstance(value, int) and not isinstance(value, bool)
                               and 0 <= value <= 0xffff_ffff, EPOCH_CONTEXT_MALFORMED,
                               f"admission threshold {key!r} must be a uint32")

    seed = manifest["seed_commitment"]
    _epoch_context_require(isinstance(seed, Mapping), EPOCH_CONTEXT_MALFORMED,
                           "epoch_context.seed_commitment must be an object")
    seed_unknown = sorted(set(seed) - set(EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS))
    seed_missing = sorted(set(EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS) - set(seed))
    _epoch_context_require(not seed_unknown and not seed_missing, EPOCH_CONTEXT_MALFORMED,
                           f"seed_commitment closed-schema mismatch: missing={seed_missing}, "
                           f"unexpected={seed_unknown}")
    for field in EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS:
        _epoch_context_require(isinstance(seed[field], str) and bool(seed[field]),
                               EPOCH_CONTEXT_MALFORMED,
                               f"seed_commitment.{field} must be a non-empty string")
    # Keep the call visible: addressability is defined by these exact canonical bytes.
    if fr.canonical_bytes(manifest) != canonical:                   # pragma: no cover
        raise EpochContextError(EPOCH_CONTEXT_UNAVAILABLE, "epoch context canonicalization drift")
    return dict(manifest)


def epoch_context_root(manifest: Mapping[str, Any]) -> str:
    return fr.sha256_hex(fr.canonical_bytes(validate_epoch_context(manifest)))


def verify_epoch_context_bytes(served: bytes, *, expected_root: str) -> Dict[str, Any]:
    """Rehash served canonical bytes, bind them to pin 3, then validate the closed document."""
    pin = fr.check_root(expected_root, "epochContextRoot")
    observed = fr.sha256_hex(bytes(served))
    if observed != pin:
        raise EpochContextError(
            EPOCH_CONTEXT_ADDRESS_MISMATCH,
            f"bytes served for epochContextRoot {pin} hash to {observed}")
    try:
        document = fr.parse_json(bytes(served).decode("utf-8"))
    except (UnicodeDecodeError, fr.FrontierError) as exc:
        raise EpochContextError(EPOCH_CONTEXT_UNAVAILABLE,
                                f"epoch context bytes are not canonical JSON: {exc}") from exc
    validated = validate_epoch_context(document)
    if fr.canonical_bytes(validated) != bytes(served):
        raise EpochContextError(EPOCH_CONTEXT_UNAVAILABLE,
                                "epoch context bytes are not canonical")
    return validated


# --------------------------------------------------------------------------- #
# The transition descriptor — coretex.transition-descriptor/v3
# --------------------------------------------------------------------------- #
# SUPERSEDES the 4-changed-word compact patch below in full. Normative reference:
# ``botcoin-mining-rigs`` @ ``a473f3fd1038a81f8ef456cd4c7ce1f7b9fbef6e``, including the
# descriptor-v3 correction recorded in ``docs/CORETEX-TRANSITION-DESCRIPTOR-V2.md`` and its
# companion audit. Mirrored here from the
# migrated coordinator's ``v5/validator/dispatch.py`` (``encode_transition_descriptor`` /
# ``decode_transition_descriptor``) and ``v5/resolver/receipt.py`` (the typehash transcription),
# with this repo's own typed-refusal-code and file-generation discipline kept intact.
#
# WHAT WAS DELETED, AND WHY EACH DELETION IS A DELETION AND NOT A RETIREMENT. Everything below
# this section (``COMPACT_PATCH_*``, ``PATCH_TYPE_WORD_RANGES``, ``CompactPatchError`` and its 14
# codes, ``CompactPatch``, ``_read_leb128_word_index``, ``decode_compact_patch``) was PRODUCTION
# machinery — an encoder a coordinator signed against and a decoder a validator ran — retired
# pre-production by the operator directive that produced the descriptor family. It is removed, not
# archived: the retired label it hashed under (``coretex-patch-hash-v1``) is kept, below, because a
# signer that was never migrated produces bytes that look right and hash wrong, and "signed under
# the retired 4-word rule" is a cheaper answer than "these bytes are wrong". ``transition_from_patch``
# — which asserted the RETIRED word-diff model over these same log bytes and was never called from
# anywhere in this package — is deleted outright rather than migrated: it was dead code built on a
# premise (verbatim canonical-JSON transition bytes in the log) the descriptor model does not have.
#
# THE FORMAT. 97 bytes, no padding, no optional field, no length prefix — the length IS the
# format:
#
#     [0]        uint8   version             == 0x21
#     [1..33)    bytes32 patchArtifactHash   != 0, sha256 of the complete canonical patch artifact
#     [33..65)   bytes32 parentStateRoot     == the receipt's signed parentStateRoot
#     [65..97)   bytes32 newStateRoot        == the receipt's signed newStateRoot
#
# THE CHAIN COMMITS AND ORDERS THE TRANSITION; IT NEVER STORES IT AND NEVER INTERPRETS IT. The
# complete canonical patch artifact lives OFF CHAIN, addressed by ``patchArtifactHash``, and is
# replayed deterministically by anyone (spec §5.4). That is why ``patchHash`` is now a content
# address of the whole EDGE — ``(version, artifact, parent, new)`` — and not, as under the
# retired model, of the input side only: the old header carried ``parentStateRoot`` and never the
# resulting root, so one ``patchHash`` was compatible with any ``newStateRoot`` a receipt named
# (audit L-6). :func:`decode_transition_descriptor` therefore checks the descriptor's
# ``newStateRoot`` against the receipt — a check that did not and could not exist before.
#
# CHECK ORDER mirrors the contract: non-empty, version byte, exact length, hash, fields. Reading
# the discriminator first makes an unmigrated 0x20 signer fail by name before its 105-byte length
# or v2 label can obscure the actual fault.

#: ``RigCoreTexVerifier.TRANSITION_DESCRIPTOR_BYTES`` (the length IS the format) and
#: ``.TRANSITION_DESCRIPTOR_VERSION`` (an OPAQUE enumerated tag compared for EQUALITY — never
#: arithmetic, never a range, and not a packed major/minor pair).
#:
#: IMPORTED, NOT TRANSCRIBED (review M-11.2 / M-1). These two values were previously a second
#: hand-written copy of what :mod:`.rig_receipt_binding` already states, with nothing asserting the
#: copies agreed — and the v2 review counted seven independent transcriptions of ``105``/``0x20``
#: across the three repos, of which this module held one. One copy per package is the most this repo can do
#: about that on its own; the binding module is the one that a cross-repo parity test can compare
#: against the generated binding, so the binding module is the copy that survives.
from .rig_receipt_binding import (                                          # noqa: E402
    TRANSITION_DESCRIPTOR_BYTES, TRANSITION_DESCRIPTOR_VERSION)

#: Field offsets, stated once.
TRANSITION_DESCRIPTOR_VERSION_OFFSET = 0
TRANSITION_DESCRIPTOR_ARTIFACT_OFFSET = 1
TRANSITION_DESCRIPTOR_PARENT_OFFSET = 33
TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET = 65

#: PERMANENTLY BURNED version bytes (spec §7.1). ``0x01``-``0x07`` were the retired compact patch's
#: ``patchType`` values and ``0xff`` was ``COMPACT_PATCH_TYPE_UNRESTRICTED`` — the value every real
#: epoch-180 advance actually used. ``0x00`` was never legal anywhere and is burned with the low run
#: so the whole range is ONE rule rather than two.
TRANSITION_DESCRIPTOR_BURNED_VERSIONS: Tuple[int, ...] = tuple(range(0x00, 0x08)) + (0xFF,)
#: UNASSIGNED and refused. Left deliberately EMPTY so the first descriptor version is not ADJACENT
#: to the burned range: an off-by-one in a hand-written encoder lands in a hole, not on a version.
TRANSITION_DESCRIPTOR_UNASSIGNED_VERSIONS: Tuple[int, ...] = tuple(range(0x08, 0x20))
RETIRED_TRANSITION_DESCRIPTOR_VERSION = 0x20

#: ``_validatedScoreDelta`` bounds both score members to ``[0, 1e6]`` and requires a STRICT
#: improvement, so a legal delta is ``1..1_000_000``.
TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM = 1
TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM = 1_000_000

# ── The domain-separation table. Four prefix-free labels (spec §4.2) ────────────────────────────
#: THE LIVE RULE — ``RigCoreTexVerifier._validateDescriptorHash``.
TRANSITION_DESCRIPTOR_HASH_LABEL = b"coretex-transition-descriptor-v3"
#: THIS LANE'S immediately superseded 105-byte descriptor label.
TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL = b"coretex-transition-descriptor-v2"
#: THIS LANE'S OWN RETIRED LABEL (the 4-word compact patch's — was ``PATCH_HASH_LABEL``), and the
#: most dangerous of the three precisely because it is this lane's own history: a signer that was
#: never migrated produces bytes that look right and hash wrong.
TRANSITION_DESCRIPTOR_RETIRED_LABEL = b"coretex-patch-hash-v1"
#: The V5 MEMORY lane's transition-hash domain (was ``SUPERSEDED_PATCH_HASH_LABEL``) — never this
#: lane's rule, and already the cause of one production incident here.
TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL = b"coretex-memory-transition-hash-v1"
#: Every DEAD label, in the order spec §4.2 tables them. Both are REFUSED, never "unsupported".
TRANSITION_DESCRIPTOR_DEAD_LABELS: Tuple[bytes, ...] = (
    TRANSITION_DESCRIPTOR_SUPERSEDED_V2_LABEL, TRANSITION_DESCRIPTOR_RETIRED_LABEL,
    TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL)

if TRANSITION_DESCRIPTOR_HASH_LABEL in TRANSITION_DESCRIPTOR_DEAD_LABELS:  # pragma: no cover
    raise RuntimeError("the live descriptor label is one of the dead ones")
for _dead in TRANSITION_DESCRIPTOR_DEAD_LABELS:                            # pragma: no cover
    if (TRANSITION_DESCRIPTOR_HASH_LABEL.startswith(_dead)
            or _dead.startswith(TRANSITION_DESCRIPTOR_HASH_LABEL)):
        raise RuntimeError(
            f"{_dead!r} is a prefix of the live label (or vice versa); abi.encodePacked would "
            "admit a (label, payload) re-split")
TRANSITION_DESCRIPTOR_HASH_RULE = (
    'keccak256(abi.encodePacked("coretex-transition-descriptor-v3", compactPatchBytes))')


def transition_descriptor_hash(descriptor_bytes: bytes) -> str:
    """The LABELLED rule the verifier enforces, as bare lowercase hex.

    Plain ``keccak256(descriptorBytes)`` is a third value and the one a naive reimplementation
    reaches for first (spec §4.2). It is never a substitute.
    """
    return keccak256_hex(TRANSITION_DESCRIPTOR_HASH_LABEL + bytes(descriptor_bytes))


#: Back-compatible alias: every call site in this package that reasoned about "the patch hash"
#: before v2 reasons about the descriptor hash now. Kept as one name, one rule, one label.
patch_hash = transition_descriptor_hash


def _dead_label_hint(data: bytes, expected: str) -> str:
    """Name the dead label a mismatched ``patchHash`` DOES correspond to, if it is one.

    An operator chasing "these bytes are wrong" when the answer is "this signer was never
    migrated" is an expensive detour, so both dead labels are tried and named — the "superseded
    label" idiom this decoder used before v2, carried forward with the second label added.
    """
    for label in TRANSITION_DESCRIPTOR_DEAD_LABELS:
        if keccak256_hex(label + data) == expected:
            return (f" (it DOES match the DEAD label {label.decode('utf-8')!r}, so this advance "
                    "was produced by a signer still on that rule — that label is REFUSED here, "
                    "not unsupported: it is a different value for every input)")
    if keccak256_hex(data) == expected:
        return (" (it matches PLAIN undomained keccak256 of the same bytes, which is a third "
                "value and belongs to nothing)")
    return ""


def check_patch_hash(advance: StateAdvanced) -> None:
    """Design §7.2 step 8, under the v3 rule. Self-verifying: the log carries both the bytes and
    their hash."""
    computed = transition_descriptor_hash(advance.compact_patch_bytes)
    if computed != advance.patch_hash:
        raise RigEventError(
            f"patchHash mismatch: {TRANSITION_DESCRIPTOR_HASH_RULE} = {computed}, the confirmed "
            f"advance says {advance.patch_hash}"
            f"{_dead_label_hint(advance.compact_patch_bytes, advance.patch_hash)}")


class TransitionDescriptorError(RigEventError):
    """A transition descriptor the deployed verifier would have reverted on. Never a soft failure.

    ``code`` IS THE CONTRACT and is frozen: a negative control that only asserts "something threw"
    passes just as happily when the decoder refuses for the wrong reason.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ── Descriptor refusal codes — one per RigCoreTexVerifier revert, in the contract's check order ─
#: ``InvalidTransitionDescriptor`` — empty or not exactly 97 bytes.
DESCRIPTOR_LENGTH_INVALID = "DESCRIPTOR_LENGTH_INVALID"
#: ``RetiredTransitionDescriptorVersion(uint8)`` — the previous 0x20 layout is named separately.
DESCRIPTOR_VERSION_RETIRED = "DESCRIPTOR_VERSION_RETIRED"
#: ``TransitionDescriptorHashMismatch`` — these bytes are not a malformed descriptor, they are a
#: DIFFERENT descriptor.
DESCRIPTOR_HASH_MISMATCH = "DESCRIPTOR_HASH_MISMATCH"
#: ``UnsupportedTransitionDescriptorVersion(uint8)`` — carries the offending byte, so a legacy
#: ``0x01``/``0xff`` names itself.
DESCRIPTOR_VERSION_UNSUPPORTED = "DESCRIPTOR_VERSION_UNSUPPORTED"
#: ``InvalidTransitionDescriptor`` — ``patchArtifactHash == 0``: committed to nothing.
DESCRIPTOR_ARTIFACT_HASH_ZERO = "DESCRIPTOR_ARTIFACT_HASH_ZERO"
#: ``TransitionDescriptorParentMismatch``.
DESCRIPTOR_PARENT_MISMATCH = "DESCRIPTOR_PARENT_MISMATCH"
#: ``TransitionDescriptorNewRootMismatch`` — the transition's OUTPUT side, committed for the first
#: time. The retired patch had no such field and therefore no such check.
DESCRIPTOR_NEW_ROOT_MISMATCH = "DESCRIPTOR_NEW_ROOT_MISMATCH"
#: ``TransitionDescriptorVersionMismatch`` — the SIGNED ``transitionFormatVersion`` (a ``uint16``
#: whose upper byte MUST be zero) is not the descriptor's version byte. The descriptor byte is the
#: authority; the signed member is the binding.
DESCRIPTOR_FORMAT_VERSION_MISMATCH = "DESCRIPTOR_FORMAT_VERSION_MISMATCH"
#: ``UnexpectedTransitionDescriptor`` — a screener pass (outcome 1) advances no state, so it MUST
#: carry an EMPTY descriptor and zero scores. STRICTER than the retired verifier, which tolerated a
#: well-formed patch on a screener and let it pre-burn the advance's dedupe key (audit L-4).
DESCRIPTOR_UNEXPECTED = "DESCRIPTOR_UNEXPECTED"
#: ``UnexpectedTransitionDescriptor`` — a screener pass signs a NON-ZERO ``patchHash``. Its own
#: code, distinct from :data:`DESCRIPTOR_UNEXPECTED`, because "you sent bytes you must not send"
#: and "you named a transition key you must not name" are different defects with different
#: histories: removing the bytes without forbidding the word is what made the second screener
#: against a parent unminable (review H-2).
SCREENER_PATCH_HASH_NONZERO = "SCREENER_PATCH_HASH_NONZERO"
#: ``InvalidCoreTexRoot`` — a state advance (outcome 2) signs ``patchHash == bytes32(0)``. The
#: outcome-2 half of the same rule; ``_validateCoreTexNonZero`` no longer states it outcome-
#: independently precisely so the screener half could become "MUST be zero".
STATE_ADVANCE_PATCH_HASH_ZERO = "STATE_ADVANCE_PATCH_HASH_ZERO"

DESCRIPTOR_REFUSALS: Tuple[str, ...] = (
    DESCRIPTOR_LENGTH_INVALID, DESCRIPTOR_VERSION_RETIRED, DESCRIPTOR_HASH_MISMATCH,
    DESCRIPTOR_VERSION_UNSUPPORTED,
    DESCRIPTOR_ARTIFACT_HASH_ZERO, DESCRIPTOR_PARENT_MISMATCH, DESCRIPTOR_NEW_ROOT_MISMATCH,
    DESCRIPTOR_FORMAT_VERSION_MISMATCH, DESCRIPTOR_UNEXPECTED,
    SCREENER_PATCH_HASH_NONZERO, STATE_ADVANCE_PATCH_HASH_ZERO)


@dataclass(frozen=True)
class TransitionDescriptor:
    """A decoded 97-byte transition descriptor. Roots are bare lowercase hex."""

    version: int
    #: sha256 content address of the COMPLETE canonical patch artifact. Never the eval artifact:
    #: ``artifactHash`` addresses what proves the SCORE, this addresses what defines the STATE
    #: CHANGE (spec §3.3).
    patch_artifact_hash: str
    parent_state_root: str
    new_state_root: str
    raw: bytes

    def as_dict(self) -> Dict[str, Any]:
        return {"version": self.version, "patch_artifact_hash": self.patch_artifact_hash,
                "parent_state_root": self.parent_state_root,
                "new_state_root": self.new_state_root, "bytes": len(self.raw)}


def encode_transition_descriptor(*, patch_artifact_hash: str, parent_state_root: str,
                                  new_state_root: str) -> bytes:
    """Build ``compactPatchBytes`` exactly as ``_validateTransitionDescriptor`` reads them back.

    Everything written here is re-read by :func:`decode_transition_descriptor` before it is
    returned, so the encoder cannot emit a descriptor this module would refuse. There is
    deliberately NO ``version`` parameter — one deployed verifier accepts exactly one version
    (spec §7.2); adversarial fixtures build a wrong version by MUTATING byte 0.
    """
    artifact = fr.check_root(patch_artifact_hash, "patch_artifact_hash")
    parent = fr.check_root(parent_state_root, "parent_state_root")
    new_root = fr.check_root(new_state_root, "new_state_root")
    if artifact == "0" * 64:
        raise TransitionDescriptorError(
            DESCRIPTOR_ARTIFACT_HASH_ZERO,
            "patchArtifactHash is zero. A descriptor committing to nothing would be structurally "
            "valid and would advance the head to a root with no addressable derivation")
    raw = (bytes([TRANSITION_DESCRIPTOR_VERSION]) + bytes.fromhex(artifact)
           + bytes.fromhex(parent) + bytes.fromhex(new_root))
    decode_transition_descriptor(raw, parent_state_root=parent, new_state_root=new_root)
    return raw


def decode_transition_descriptor(raw: bytes, *, parent_state_root: Optional[str] = None,
                                  new_state_root: Optional[str] = None,
                                  expected_patch_hash: Optional[str] = None,
                                  transition_format_version: Optional[int] = None
                                  ) -> TransitionDescriptor:
    """Decode ``compactPatchBytes`` exactly as ``RigCoreTexVerifier`` validates them (spec §6.1
    rows 4-12, checked in that order — each failure the earliest true statement about what is
    wrong).

    The optional arguments are the cross-checks the contract performs against the SIGNED receipt.
    Re-doing them is how a validator confirms the descriptor belongs to THIS advance rather than
    merely being well-formed — and under v3 that includes the transition's OUTPUT side, which
    the retired patch never carried.
    """
    data = bytes(raw)
    # 4. Non-empty, then 5/6. VERSION FIRST: byte zero is shared by every descriptor-family layout.
    if not data:
        raise TransitionDescriptorError(
            DESCRIPTOR_LENGTH_INVALID,
            f"a transition descriptor is EXACTLY {TRANSITION_DESCRIPTOR_BYTES} bytes; this one is "
            f"{len(data)}. The length is the format: there is no padding, no optional field and "
            "no length prefix")
    version = data[TRANSITION_DESCRIPTOR_VERSION_OFFSET]
    if version != TRANSITION_DESCRIPTOR_VERSION:
        if version == RETIRED_TRANSITION_DESCRIPTOR_VERSION:
            raise TransitionDescriptorError(
                DESCRIPTOR_VERSION_RETIRED,
                "descriptor version 0x20 is the retired 105-byte descriptor-v2 layout; the live "
                "rig accepts only 0x21 and never dual-accepts the previous format")
        if version in TRANSITION_DESCRIPTOR_BURNED_VERSIONS:
            why = ("PERMANENTLY BURNED: 0x01-0x07 were the retired compact patch's patchType "
                   "values, 0xff was COMPACT_PATCH_TYPE_UNRESTRICTED, and 0x00 is burned too")
        elif version in TRANSITION_DESCRIPTOR_UNASSIGNED_VERSIONS:
            why = "UNASSIGNED: 0x08-0x1f is deliberately empty"
        else:
            why = "reserved for a successor; one deployed verifier accepts exactly one version"
        raise TransitionDescriptorError(
            DESCRIPTOR_VERSION_UNSUPPORTED,
            f"descriptor version 0x{version:02x} is not 0x{TRANSITION_DESCRIPTOR_VERSION:02x} — "
            f"{why}")
    # 7. exact length, after the version has named the format.
    if len(data) != TRANSITION_DESCRIPTOR_BYTES:
        raise TransitionDescriptorError(
            DESCRIPTOR_LENGTH_INVALID,
            f"a version-0x{version:02x} transition descriptor is EXACTLY "
            f"{TRANSITION_DESCRIPTOR_BYTES} bytes; this one is {len(data)}")
    # 8. the hash rule.
    if expected_patch_hash is not None:
        computed = transition_descriptor_hash(data)
        expected = str(expected_patch_hash).lower().replace("0x", "")
        if computed != expected:
            raise TransitionDescriptorError(
                DESCRIPTOR_HASH_MISMATCH,
                f"{TRANSITION_DESCRIPTOR_HASH_RULE} is {computed}, the confirmed advance says "
                f"{expected}{_dead_label_hint(data, expected)}")
    # 9. the artifact address must be non-zero.
    artifact_hash = data[TRANSITION_DESCRIPTOR_ARTIFACT_OFFSET:
                         TRANSITION_DESCRIPTOR_PARENT_OFFSET].hex()
    if artifact_hash == "0" * 64:
        raise TransitionDescriptorError(
            DESCRIPTOR_ARTIFACT_HASH_ZERO,
            "patchArtifactHash is zero: the descriptor commits to no artifact, so the head would "
            "advance to a root with no addressable derivation")
    parent = data[TRANSITION_DESCRIPTOR_PARENT_OFFSET:TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET].hex()
    new_root = data[TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET:].hex()
    # 10/11. parent and new root, one at a time, each with its own revert.
    if parent_state_root is not None:
        expected_parent = str(parent_state_root).lower().replace("0x", "")
        if parent != expected_parent:
            raise TransitionDescriptorError(
                DESCRIPTOR_PARENT_MISMATCH,
                f"the descriptor's parentStateRoot {parent} is not the receipt's {expected_parent}")
    if new_state_root is not None:
        expected_new = str(new_state_root).lower().replace("0x", "")
        if new_root != expected_new:
            raise TransitionDescriptorError(
                DESCRIPTOR_NEW_ROOT_MISMATCH,
                f"the descriptor's newStateRoot {new_root} is not the receipt's {expected_new}. "
                "This check did not exist under the retired model because the patch carried no "
                "resulting root at all")
    # 12. the SIGNED uint16 must be the zero-extension of the version byte.
    if transition_format_version is not None and int(transition_format_version) != version:
        raise TransitionDescriptorError(
            DESCRIPTOR_FORMAT_VERSION_MISMATCH,
            f"the receipt signs transitionFormatVersion={int(transition_format_version)} but the "
            f"descriptor's version byte is 0x{version:02x}. The descriptor byte is the AUTHORITY; "
            "the signed member is the binding, and its upper byte MUST be zero")
    return TransitionDescriptor(version=version, patch_artifact_hash=artifact_hash,
                                parent_state_root=parent, new_state_root=new_root, raw=data)


def _is_zero_word(value: Any) -> bool:
    """Is this ``bytes32`` the zero word, in any spelling this package renders one in?"""
    if isinstance(value, (bytes, bytearray)):
        return not any(bytes(value))
    text = str(value).strip().lower().removeprefix("0x")
    return text != "" and set(text) == {"0"}


def check_screener_descriptor(raw: bytes, *, transition_format_version: Optional[int] = None,
                              score_before_ppm: Optional[int] = None,
                              score_after_ppm: Optional[int] = None,
                              patch_hash: Optional[Any] = None) -> None:
    """Outcome 1 carries NO descriptor, a ZERO ``patchHash`` and zero scores. Anything else is
    refused.

    A TIGHTENING THE FRAME DID NOT ASK FOR (audit L-4), recorded rather than buried: the retired
    verifier tolerated a non-empty patch on a screener and validated only its hash, which let a
    screener pre-burn the advance's ``coreTexPatchCredited`` dedupe key.

    THE FIRST CUT OF THAT TIGHTENING REMOVED THE BYTES AND NOT THE WORD, and that half-fix was its
    own defect (review H-2). ``patchHash`` is a SIGNED member; the retired
    ``_validateCoreTexNonZero`` demanded it be non-zero on EVERY outcome, so with an empty
    descriptor mandatory the only descriptor-derived value an honest implementer could reach was
    the CONSTANT ``keccak256(LABEL ‖ "")``. A screener therefore burned exactly one dedupe key per
    ``(epoch, parentStateRoot)`` — a screener never moves the root — and the SECOND screener
    against that parent reverted ``DuplicateCoreTexPatch``, killing
    ``coreTexScreenerCapPerRigPerEpoch`` and the entire difficulty ramp, both of which exist to
    count MANY screeners between advances.

    ``RigCoreTexVerifier`` closes both halves by making the rule explicit rather than implicit:
    ``_validateScreenerReceipt`` requires ``patchHash == bytes32(0)`` — the one word that names no
    transition — and ``validateAndRecord`` reads and writes ``coreTexPatchCredited`` ONLY on
    outcome 2. This checker mirrors the first half; the second is a chain-side storage rule with no
    off-chain observable. ``patch_hash`` is optional only so a caller that does not have the signed
    member can still check the rest; when it IS supplied the zero rule is enforced.
    """
    data = bytes(raw or b"")
    if data:
        raise TransitionDescriptorError(
            DESCRIPTOR_UNEXPECTED,
            f"a screener pass carries {len(data)} descriptor byte(s); outcome 1 advances no "
            "state, so it MUST carry an EMPTY compactPatchBytes")
    if patch_hash is not None and not _is_zero_word(patch_hash):
        raise TransitionDescriptorError(
            SCREENER_PATCH_HASH_NONZERO,
            f"a screener pass signs patchHash={patch_hash!r}; outcome 1 credits NO transition, so "
            "its patchHash MUST be bytes32(0) — the one word that names no transition. A "
            "descriptor-derived value here is necessarily the constant keccak256(LABEL ‖ \"\"), "
            "which is why the retired rule made the second screener against a parent unminable")
    for name, value in (("transitionFormatVersion", transition_format_version),
                        ("scoreBeforePpm", score_before_ppm), ("scoreAfterPpm", score_after_ppm)):
        if value is not None and int(value) != 0:
            raise TransitionDescriptorError(
                DESCRIPTOR_UNEXPECTED,
                f"a screener pass signs {name}={int(value)}; outcome 1 requires "
                "transitionFormatVersion, scoreBeforePpm and scoreAfterPpm to all be zero")


def check_state_advance_patch_hash(patch_hash: Any) -> None:
    """Outcome 2's ``patchHash`` MUST be non-zero — the outcome-2 half of the H-2 rule.

    ``_validateCoreTexNonZero`` deliberately no longer states "patchHash is non-zero always" (that
    is what forced a screener to name SOME word); ``_validateStateAdvanceReceipt`` states the
    outcome-2 half instead, and refuses with the ROOT error rather than a hash-mismatch error that
    would misdescribe the defect. Redundant with the hash rule — a keccak output cannot be zero —
    and kept for exactly that reason.
    """
    if _is_zero_word(patch_hash):
        raise TransitionDescriptorError(
            STATE_ADVANCE_PATCH_HASH_ZERO,
            "a state advance (outcome 2) signs patchHash=bytes32(0); the descriptor hash is a "
            "keccak output and can never be zero, so this receipt commits to no transition at all")


# --------------------------------------------------------------------------- #
# The canonical patch artifact (spec §5) — SCOPED to the T-1/T-2 shape
# --------------------------------------------------------------------------- #
# The full spec allows one artifact to move an arbitrary number of profile releases and/or the
# composition root in a single transition (spec §8, T-3/T-4/T-5), because the chain no longer
# bounds breadth. Expressing that here would mean widening :mod:`.frontier`'s transition/manifest
# model past its documented one-profile-per-transition law
# (``frontier.apply_transition``'s single ``target_profile``), and :mod:`.frontier` is
# DELIBERATELY OUT OF SCOPE for this migration (it is not one of the files the migration touches;
# widening it is a frontier-law change, not a rig-lane wire-format change). So the artifact
# envelope below is the STRICT SUPERSET FLOOR: it gives every real advance this repo can produce
# today (T-1/T-2 — the only shapes the mainnet rehearsal ever used, per spec §8) the v2
# commitment discipline — a patchArtifactHash-addressed, fetched, rehashed and replayed edit — and
# leaves T-3/T-4/T-5 breadth as a documented gap rather than a silent one. See
# ``docs/V5-RIG-VALIDATOR.md`` for the operator-facing note.
TRANSITION_ARTIFACT_FORMAT = "coretex.transition-artifact/v2"
#: CLOSED schema, scoped to one :mod:`.frontier` transition per artifact (see the note above).
TRANSITION_ARTIFACT_FIELDS: Tuple[str, ...] = (
    "format", "parent_state_root", "new_state_root", "score_delta_ppm", "transition")

# ── Off-chain refusals (spec §6.3), spelled exactly as the spec tables them, plus one structural
#    code the spec's table does not name ──────────────────────────────────────────────────────
TRANSITION_ARTIFACT_UNAVAILABLE = "TRANSITION_ARTIFACT_UNAVAILABLE"
TRANSITION_ARTIFACT_ADDRESS_MISMATCH = "TRANSITION_ARTIFACT_ADDRESS_MISMATCH"
TRANSITION_ARTIFACT_NOT_CANONICAL = "TRANSITION_ARTIFACT_NOT_CANONICAL"
TRANSITION_PARENT_MISMATCH = "TRANSITION_PARENT_MISMATCH"
TRANSITION_REPLAY_ROOT_MISMATCH = "TRANSITION_REPLAY_ROOT_MISMATCH"
TRANSITION_SCORE_DELTA_MISMATCH = "TRANSITION_SCORE_DELTA_MISMATCH"
TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED = "TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED"
#: The artifact document is not a well-formed member of its family. Distinct from NOT_CANONICAL,
#: which is about the SERIALIZATION of a document that does parse.
TRANSITION_ARTIFACT_MALFORMED = "TRANSITION_ARTIFACT_MALFORMED"

OFFCHAIN_TRANSITION_REFUSALS: Tuple[str, ...] = (
    TRANSITION_ARTIFACT_UNAVAILABLE, TRANSITION_ARTIFACT_ADDRESS_MISMATCH,
    TRANSITION_ARTIFACT_NOT_CANONICAL, TRANSITION_PARENT_MISMATCH,
    TRANSITION_REPLAY_ROOT_MISMATCH, TRANSITION_SCORE_DELTA_MISMATCH,
    TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED)
TRANSITION_ARTIFACT_REFUSALS: Tuple[str, ...] = OFFCHAIN_TRANSITION_REFUSALS + (
    TRANSITION_ARTIFACT_MALFORMED,)


class TransitionArtifactError(RigEventError):
    """An OFF-CHAIN refusal about the canonical patch artifact the descriptor addresses.

    Distinct from :class:`TransitionDescriptorError`: a descriptor refusal says "the chain would
    not have accepted these bytes"; an artifact refusal says "the chain accepted the commitment
    and the thing it commits to is unavailable, substituted, non-canonical or does not replay".
    REFUSE, NEVER DEGRADE (spec §6.3): "the artifact did not mention it" MUST NOT become a way to
    avoid publishing it, and "we could not fetch it" MUST NOT become a way to accept it.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def transition_artifact_bytes(artifact: Mapping[str, Any]) -> bytes:
    """The canonical bytes a ``patchArtifactHash`` addresses — the repo's ONE canonical-JSON law,
    imported from :mod:`.frontier`, never restated."""
    try:
        return fr.canonical_bytes(artifact)
    except fr.FrontierError as exc:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_NOT_CANONICAL,
            f"the artifact does not canonicalize under the repo's canonical-JSON law: {exc}"
        ) from exc


def transition_artifact_root(artifact: Mapping[str, Any]) -> str:
    """``sha256(canonical_bytes(artifact))`` — the content address, as bare lowercase hex.

    sha256, not keccak (spec §4.3): ``patchHash`` is keccak because it is a ``bytes32`` a Solidity
    verifier compares; ``patchArtifactHash`` is sha256 because it is how the object is FETCHED, and
    every content-addressed object in this system is addressed by sha256.
    """
    return fr.sha256_hex(transition_artifact_bytes(artifact))


def validate_transition_artifact(artifact: Any) -> Dict[str, Any]:
    """Structural validation of one ``coretex.transition-artifact/v2`` document. CLOSED schema.

    Scoped to the single-:mod:`.frontier`-transition shape (see the section note above): T-1 (one
    profile, one hook) and T-2 (one profile, all six hooks) are both expressible here because
    :mod:`.frontier` already treats "which hooks moved" as internal to the release manifest a
    transition names, not as a field of the transition itself.
    """
    if not isinstance(artifact, Mapping):
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            f"a transition artifact must be an object, got {type(artifact).__name__}")
    if artifact.get("format") != TRANSITION_ARTIFACT_FORMAT:
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            f"format {artifact.get('format')!r} is not {TRANSITION_ARTIFACT_FORMAT!r}")
    unknown = sorted(set(artifact) - set(TRANSITION_ARTIFACT_FIELDS))
    if unknown:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED,
                                      f"unknown field(s) {unknown} — the schema is CLOSED")
    missing = sorted(set(TRANSITION_ARTIFACT_FIELDS) - set(artifact))
    if missing:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED,
                                      f"required field(s) {missing} are absent")
    try:
        parent_root = fr.check_root(artifact["parent_state_root"], "artifact.parent_state_root")
        new_root = fr.check_root(artifact["new_state_root"], "artifact.new_state_root")
    except fr.FrontierError as exc:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED, str(exc)) from exc
    delta = artifact["score_delta_ppm"]
    if (not isinstance(delta, int) or isinstance(delta, bool)
            or not (TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM <= delta
                    <= TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM)):
        raise TransitionArtifactError(
            TRANSITION_ARTIFACT_MALFORMED,
            f"score_delta_ppm {delta!r} must be an int in "
            f"{TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM}.."
            f"{TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM}")
    try:
        fr.validate_transition(artifact["transition"])
    except fr.FrontierError as exc:
        raise TransitionArtifactError(TRANSITION_ARTIFACT_MALFORMED,
                                      f"transition is not a valid frontier transition: {exc}"
                                      ) from exc
    transition_artifact_bytes(artifact)      # fail closed before anyone addresses it
    return {"format": artifact["format"], "parent_state_root": parent_root,
            "new_state_root": new_root, "score_delta_ppm": delta,
            "transition": dict(artifact["transition"])}


def check_transition_artifact_binds_descriptor(artifact: Mapping[str, Any], *,
                                               descriptor: "TransitionDescriptor",
                                               expected_score_delta_ppm: Optional[int] = None
                                               ) -> Dict[str, Any]:
    """Validate + check the two off-chain bindings the artifact can prove WITHOUT the parent state.

    Everything else — does the artifact re-hash to ``descriptor.patch_artifact_hash``, and does
    replaying ``transition`` from the real parent manifest actually reach ``newStateRoot`` — needs
    the fetch and the parent manifest, which the pipeline/chain-first callers already own; this
    function is the pure part.
    """
    document = validate_transition_artifact(artifact)
    if document["parent_state_root"] != descriptor.parent_state_root:
        raise TransitionArtifactError(
            TRANSITION_PARENT_MISMATCH,
            f"artifact.parent_state_root {document['parent_state_root']} != descriptor's "
            f"{descriptor.parent_state_root}")
    if document["new_state_root"] != descriptor.new_state_root:
        raise TransitionArtifactError(
            TRANSITION_REPLAY_ROOT_MISMATCH,
            f"artifact.new_state_root {document['new_state_root']} != descriptor's "
            f"{descriptor.new_state_root}")
    if (expected_score_delta_ppm is not None
            and document["score_delta_ppm"] != int(expected_score_delta_ppm)):
        raise TransitionArtifactError(
            TRANSITION_SCORE_DELTA_MISMATCH,
            f"artifact.score_delta_ppm {document['score_delta_ppm']} != signed receipt delta "
            f"{int(expected_score_delta_ppm)}")
    return document


# --------------------------------------------------------------------------- #
# HISTORY — the retired 4-changed-word compact patch (coretex-patch-hash-v1 era)
# --------------------------------------------------------------------------- #
# KEPT, not deleted: epoch-180 mainnet-rehearsal advances (two 75-byte patches, patchType 0xff,
# wordCount 1) are LEGACY-ERA history. They remain valid against the deployed LEGACY verifier and
# MUST NOT be re-read under either descriptor generation — their first byte, 0xff, is a burned
# (spec §9.5). This decoder is the only thing that can still parse them; deleting it would erase
# the evidence of what changed, not just the machinery for changing it.
#
# ``decode_compact_patch`` MUST NOT be called on anything decoded from a live v3 deployment. What
# actually happens if it is: 97 falls inside the retired ``42..178`` length window, so the LENGTH
# check passes — but a v3 descriptor's first byte is ``0x21``, which is not a key of
# ``PATCH_TYPE_WORD_RANGES``, so the very next check raises ``PATCH_TYPE_UNKNOWN`` before any word
# is parsed. IT REFUSES, LOUDLY, AND IT NEVER MISREADS THE BYTES.
#
# That is stated precisely on purpose. An earlier version of this note claimed the decoder "would
# not even refuse it outright — it would misread a descriptor as a same-length compact patch",
# which is false, and a comment that overstates a hazard invites someone to "fix" the perceived
# asymmetry by loosening the very check that closes it. THE PATCH-TYPE CHECK IS LOAD-BEARING: it is
# the whole reason the two formats are mutually unparseable in this direction, and it MUST NOT be
# loosened, widened to unknown types, or made a warning. (The other direction is closed by
# ``0x01``-``0x07`` and ``0xff`` being permanently-burned descriptor versions.)
#
# Routing is still the caller's job — by deployment/epoch, exactly as it already must be for the V4
# topic0 collision this package documents elsewhere. A refusal is the right outcome for a v2
# descriptor reaching this decoder, but it is not a substitute for not sending it here.

#: ``RigCoreTexVerifier`` constants, transcribed from the exact RETIRED source (``cdb91d2``).
COMPACT_PATCH_HEADER_BYTES = 42
COMPACT_PATCH_MAX_BYTES = 178
COMPACT_PATCH_MAX_WORDS = 4
#: Word indices at or above this were reserved and refused on chain.
RESERVED_WORD_START = 992
#: ``_readUint64BE`` result had to fit int64 — the RETIRED contract refused anything larger.
MAX_SCORE_DELTA = 9_223_372_036_854_775_807

#: ``_wordMatchesPatchType``. ``0xff`` was the unrestricted type; the rest were windowed.
PATCH_TYPE_WORD_RANGES: Dict[int, Optional[Tuple[int, int]]] = {
    0x01: (384, 671), 0x02: (32, 383), 0x03: (800, 895), 0x04: (672, 799),
    0x05: (896, 991), 0x06: (0, 31), 0x07: (384, 671), 0xFF: None,
}


class CompactPatchError(RigEventError):
    """A compact patch that the RETIRED verifier would have reverted on. History only — see the
    section note above. ``code`` IS THE CONTRACT and is frozen."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# The refusal codes, one per revert in the RETIRED `_validateCompactPatch` (plus its hash rule).
PATCH_LENGTH_INVALID = "PATCH_LENGTH_INVALID"
PATCH_TYPE_UNKNOWN = "PATCH_TYPE_UNKNOWN"
PATCH_WORD_COUNT_INVALID = "PATCH_WORD_COUNT_INVALID"
PATCH_SCORE_DELTA_OVERFLOW = "PATCH_SCORE_DELTA_OVERFLOW"
PATCH_SCORE_DELTA_MISMATCH = "PATCH_SCORE_DELTA_MISMATCH"
PATCH_PARENT_MISMATCH = "PATCH_PARENT_MISMATCH"
PATCH_INDEX_TRUNCATED = "PATCH_INDEX_TRUNCATED"
PATCH_INDEX_OVERLONG = "PATCH_INDEX_OVERLONG"
PATCH_INDEX_REDUNDANT = "PATCH_INDEX_REDUNDANT"
PATCH_INDEX_RESERVED = "PATCH_INDEX_RESERVED"
PATCH_INDEX_OUT_OF_WINDOW = "PATCH_INDEX_OUT_OF_WINDOW"
PATCH_INDEX_DUPLICATE = "PATCH_INDEX_DUPLICATE"
PATCH_WORD_TRUNCATED = "PATCH_WORD_TRUNCATED"
PATCH_TRAILING_BYTES = "PATCH_TRAILING_BYTES"
PATCH_HASH_MISMATCH = "PATCH_HASH_MISMATCH"


@dataclass(frozen=True)
class CompactPatch:
    """The decoded RETIRED rig state patch: a header plus ``wordCount`` (index, value) pairs."""

    patch_type: int
    word_count: int
    score_delta_ppm: int
    parent_state_root: str
    #: ``index -> 32-byte value``, in the order they appeared. Indices are unique by contract.
    words: Tuple[Tuple[int, str], ...]
    raw: bytes

    def as_dict(self) -> Dict[str, Any]:
        return {"patch_type": self.patch_type, "word_count": self.word_count,
                "score_delta_ppm": self.score_delta_ppm,
                "parent_state_root": self.parent_state_root,
                "words": [{"index": i, "value": v} for i, v in self.words],
                "bytes": len(self.raw)}


def _read_leb128_word_index(data: bytes, offset: int) -> Tuple[int, int]:
    """``_readLeb128WordIndex``, RETIRED. At most two bytes; the two-byte form must be
    non-redundant."""
    if offset >= len(data):
        raise CompactPatchError(PATCH_INDEX_TRUNCATED,
                                "word index runs past the end of the patch")
    first = data[offset]
    value = first & 0x7F
    nxt = offset + 1
    if not first & 0x80:
        return value, nxt
    if nxt >= len(data):
        raise CompactPatchError(PATCH_INDEX_TRUNCATED, "truncated two-byte word index")
    second = data[nxt]
    if second & 0x80:
        raise CompactPatchError(PATCH_INDEX_OVERLONG, "word index is longer than two bytes")
    value |= (second & 0x7F) << 7
    if value < 128 or value >= 1024:
        raise CompactPatchError(
            PATCH_INDEX_REDUNDANT,
            f"two-byte word index decodes to {value}, which is not in [128, 1024): a redundant "
            "encoding would give one index two spellings, and therefore one patch two hashes")
    return value, nxt + 1


def decode_compact_patch(raw: bytes, *, parent_state_root: Optional[str] = None,
                         score_delta_ppm: Optional[int] = None,
                         expected_patch_hash: Optional[str] = None) -> CompactPatch:
    """Decode ``compactPatchBytes`` exactly as the RETIRED ``_validateCompactPatch`` did.

    HISTORY ONLY (see the section note above) — a decoder for the ``coretex-patch-hash-v1`` era,
    kept so epoch-180-and-earlier legacy-format advances stay replayable. ``expected_patch_hash``
    is checked against :data:`TRANSITION_DESCRIPTOR_RETIRED_LABEL`, the RETIRED label, not either
    descriptor rule.
    """
    data = bytes(raw)
    if expected_patch_hash is not None:
        computed = keccak256_hex(TRANSITION_DESCRIPTOR_RETIRED_LABEL + data)
        expected = str(expected_patch_hash).lower().replace("0x", "")
        if computed != expected:
            superseded = keccak256_hex(TRANSITION_DESCRIPTOR_SUPERSEDED_MEMORY_LABEL + data)
            hint = (" (it DOES match the superseded 'coretex-memory-transition-hash-v1' label)"
                    if superseded == expected else "")
            raise CompactPatchError(
                PATCH_HASH_MISMATCH,
                f"keccak256(label \u2016 compactPatchBytes) is {computed}, the signed receipt says "
                f"{expected}{hint}")
    if len(data) < COMPACT_PATCH_HEADER_BYTES or len(data) > COMPACT_PATCH_MAX_BYTES:
        raise CompactPatchError(
            PATCH_LENGTH_INVALID,
            f"a compact patch is {COMPACT_PATCH_HEADER_BYTES}..{COMPACT_PATCH_MAX_BYTES} bytes; "
            f"this one is {len(data)}")
    patch_type = data[0]
    word_count = data[1]
    if patch_type not in PATCH_TYPE_WORD_RANGES:
        raise CompactPatchError(PATCH_TYPE_UNKNOWN, f"unknown patchType 0x{patch_type:02x}")
    if word_count == 0 or word_count > COMPACT_PATCH_MAX_WORDS:
        raise CompactPatchError(
            PATCH_WORD_COUNT_INVALID,
            f"wordCount {word_count} is outside 1..{COMPACT_PATCH_MAX_WORDS}")
    score_delta = int.from_bytes(data[2:10], "big")
    if score_delta > MAX_SCORE_DELTA:
        raise CompactPatchError(PATCH_SCORE_DELTA_OVERFLOW,
                                f"scoreDelta {score_delta} exceeds int64")
    if score_delta_ppm is not None and score_delta != int(score_delta_ppm):
        raise CompactPatchError(
            PATCH_SCORE_DELTA_MISMATCH,
            f"the patch declares scoreDelta {score_delta} but the signed receipt says "
            f"{score_delta_ppm}")
    parent = data[10:42].hex()
    if parent_state_root is not None:
        expected = str(parent_state_root).lower().replace("0x", "")
        if parent != expected:
            raise CompactPatchError(
                PATCH_PARENT_MISMATCH,
                f"the patch's parentStateRoot {parent} is not the advance's {expected}")

    words: List[Tuple[int, str]] = []
    seen: set = set()
    offset = COMPACT_PATCH_HEADER_BYTES
    window = PATCH_TYPE_WORD_RANGES[patch_type]
    for _ in range(word_count):
        index, offset = _read_leb128_word_index(data, offset)
        if index >= RESERVED_WORD_START:
            raise CompactPatchError(
                PATCH_INDEX_RESERVED,
                f"word index {index} is reserved (>= {RESERVED_WORD_START})")
        if window is not None and not window[0] <= index <= window[1]:
            raise CompactPatchError(
                PATCH_INDEX_OUT_OF_WINDOW,
                f"word index {index} is outside patchType 0x{patch_type:02x}'s window {window}")
        if index in seen:
            raise CompactPatchError(PATCH_INDEX_DUPLICATE, f"duplicate word index {index}")
        seen.add(index)
        if offset + 32 > len(data):
            raise CompactPatchError(PATCH_WORD_TRUNCATED,
                                    "word value runs past the end of the patch")
        words.append((index, data[offset:offset + 32].hex()))
        offset += 32
    if offset != len(data):
        raise CompactPatchError(
            PATCH_TRAILING_BYTES,
            f"{len(data) - offset} trailing byte(s) after {word_count} word(s); the RETIRED "
            "contract required the patch to end exactly where its last word does")
    return CompactPatch(patch_type=patch_type, word_count=word_count,
                        score_delta_ppm=score_delta, parent_state_root=parent,
                        words=tuple(words), raw=data)
