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


def context_parent_continuity(decoded: DecodedLogs) -> Dict[str, Any]:
    """Reconstruct each served epoch from its confirmed verifier context parent.

    ``RigCoreTexRegistry.liveStateRoot(epoch)`` returns the verifier's
    ``coreTexParentStateRoot(epoch)`` until the first accepted transition.  The constructor's
    ``GENESIS_STATE_ROOT`` is therefore an immutable deployment fact and diagnostic only; it is
    never an input to this reconstruction.  This mirrors the deployed contract exactly.
    """
    problems: List[str] = []
    parents: Dict[str, str] = {}
    by_epoch: Dict[int, List[StateAdvanced]] = {}
    for advance in decoded.advances:
        by_epoch.setdefault(advance.epoch, []).append(advance)
    for epoch, group in sorted(by_epoch.items()):
        ordered = sorted(group, key=lambda item: item.transition_index)
        contexts = sorted((ctx for ctx in decoded.contexts if ctx.epoch == epoch),
                          key=lambda item: item.provenance.position)
        if not contexts:
            problems.append(
                f"epoch {epoch} has accepted transitions but no confirmed CoreTexEpochContextSet")
            continue
        first = ordered[0]
        before = [ctx for ctx in contexts if ctx.provenance.position < first.provenance.position]
        if not before:
            problems.append(
                f"epoch {epoch}'s context was not confirmed before its first transition")
            continue
        context = before[-1]
        parents[str(epoch)] = context.parent_state_root
        after = [ctx for ctx in contexts if ctx.provenance.position > first.provenance.position]
        if after:
            problems.append(
                f"epoch {epoch} published a replacement context after state activity began")
        if first.transition_index != 0:
            problems.append(
                f"epoch {epoch}'s first observed transition is index {first.transition_index}, "
                "not index 0; a deployment-block scan must not invent the missing prefix")
        if first.parent_state_root != context.parent_state_root:
            problems.append(
                f"epoch {epoch}'s first transition builds on {first.parent_state_root}, but its "
                f"confirmed context parent is {context.parent_state_root}")
        expected_parent = context.parent_state_root
        expected_index = 0
        for advance in ordered:
            if advance.transition_index != expected_index:
                problems.append(
                    f"epoch {epoch} transition index {advance.transition_index} follows "
                    f"{expected_index - 1}; the accepted history is not dense")
                expected_index = advance.transition_index
            if advance.parent_state_root != expected_parent:
                problems.append(
                    f"epoch {epoch} transition {advance.transition_index} builds on "
                    f"{advance.parent_state_root}, expected live root {expected_parent}")
            if advance.epoch_context_root != context.epoch_context_root:
                problems.append(
                    f"epoch {epoch} transition {advance.transition_index} carries epoch context "
                    f"{advance.epoch_context_root}, confirmed context is "
                    f"{context.epoch_context_root}")
            if advance.core_version_hash != context.core_version_hash:
                problems.append(
                    f"epoch {epoch} transition {advance.transition_index} carries core version "
                    f"{advance.core_version_hash}, confirmed context is "
                    f"{context.core_version_hash}")
            expected_parent = advance.new_state_root
            expected_index = advance.transition_index + 1
    return {"operational_context_parents": parents, "problems": problems,
            "constructor_genesis_used_as_state_authority": False}


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
    "benchmark_law_root", "runtime_abi_root", "compatibility_lock_root")


class TransitionArtifactError(RigEventError):
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
#: holds — the candidate was built against a superseded frontier. Its own code because "stale
#: parent" and "replay produced another root" are different facts for an operator.
TRANSITION_RELEASE_PRIOR_MISMATCH = "TRANSITION_RELEASE_PRIOR_MISMATCH"
#: Spec §8 T-6, made enforceable: a law pin moved. That is an EPOCH-CONTEXT operation, not a mined
#: transition, and no descriptor can express it — so it is refused HERE by name rather than
#: surfacing later as an unattributable replay mismatch.
TRANSITION_LAW_PIN_CHANGE = "TRANSITION_LAW_PIN_CHANGE"
#: ``newStateRoot == parentStateRoot``: the artifact expresses no state change and the registry
#: would revert ``NoOpAdvance``.
#:
#: GAP-1 (recorded, not worked around). Spec §8 T-5 — a derived-state-only improvement — is
#: STRUCTURALLY expressible but COMMITS NOTHING. ``derived_state`` is carried by the artifact, and
#: the resulting manifest's ``parent_frontier_root`` advances to the parent's root, so the state
#: root does move and this refusal does not fire. But the resulting state is a
#: ``coretex.memory-frontier.v1`` manifest whose schema is CLOSED and has no derived-state field,
#: so two artifacts with completely different ``derived_state`` produce the SAME ``newStateRoot``
#: and replay cannot refute a substituted derived state. Closing that is a FRONTIER-LAW change (a
#: new manifest field plus a version), which is outside this migration.
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
    # ZERO OR MORE entries. Empty is LEGAL and is exactly what a composition-only change looks like
    # (spec §8, T-4) — the retired model refused `wordCount == 0` outright, which made an entire
    # class of legitimate improvement unmineable and said so nowhere.
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
# is out of this migration's scope for exactly the reason GAP-1 is.
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
                               component_references: Optional[Mapping[str, Any]] = None
                               ) -> Dict[str, Any]:
    """DETERMINISTIC REPLAY: ``(parentStateRoot, artifact) -> exactly one resulting manifest``.

    THE ARTIFACT PLUS THE PARENT STATE IS THE AUTHORITY; THE CHAIN IS THE CLOCK (spec §5.4). This
    is a PURE FUNCTION. It takes no input from the transaction, the block, the miner's identity, the
    wall clock or any unpinned network resource, so two honest validators replaying the same pair
    MUST agree — and disagreeing with the descriptor's ``newStateRoot`` is a PUBLICLY PROVABLE
    refutation requiring nothing but chain data and the addressed bytes.

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
                          f"{profiles[pid]}; the candidate was built against a superseded frontier")
        profiles[pid] = move["new_release_root"]

    replayed = dict(parent_manifest)
    replayed["epoch"] = document["epoch"]
    replayed["parent_frontier_root"] = parent_root
    replayed["profiles"] = profiles
    replayed["default_composition_root"] = document["resulting_composition_root"]

    # THE LAW PINS ARE CARRIED FORWARD BY CONSTRUCTION (they are copied from the parent above and
    # never touched). Checking the artifact's own resulting manifest against them is what makes
    # spec §8's T-6 refusal NAMEABLE rather than an unattributable root mismatch.
    stated = document["resulting_frontier_manifest"]
    for pin in TRANSITION_ARTIFACT_LAW_PINS:
        if pin in replayed or pin in stated:
            _artifact_require(stated.get(pin) == replayed.get(pin), TRANSITION_LAW_PIN_CHANGE,
                              f"the artifact's resulting manifest moves the law pin {pin!r} from "
                              f"{replayed.get(pin)!r} to {stated.get(pin)!r}. Law pins are carried "
                              "forward by EVERY mined transition; moving one moves coreVersionHash, "
                              "which is an epoch-context operation performed by "
                              "CORETEX_CONTEXT_OPERATOR and which NO descriptor can express "
                              "(spec §8, T-6)")

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
