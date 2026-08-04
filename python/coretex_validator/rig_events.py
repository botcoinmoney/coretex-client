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
                         bytes32,bytes32,uint256,uint16,bytes)

which hashes to ``2f0a8989…`` — **byte-identical to the V4 lane's advance topic0**. That is
deliberate on the contract's side (RIG-CORETEX-REGISTRY-DESIGN.md §7.3: "an indexer written for
``RigCoreTexRegistry`` decodes our logs unchanged"), and it flatly contradicts the staged
dispatcher's premise that "V5 must never emit an event that collides with
``CoreTexStateAdvanced``'s topic0". Both statements cannot be true, and the contract wins: it is
the thing that emits logs.

Three consequences, all load-bearing, all asserted below rather than left as prose:

1. **topic0 is not an identity.** A log at ``2f0a8989…`` is a V4 advance or a rig advance
   depending ONLY on which address emitted it. Any router that keys on topic0 alone will mix the
   two lanes' history together. :func:`route_rig_log` therefore takes the deployment addresses and
   refuses a log from an address it was not given.
2. **The rig subscription must include the V4 topic0.** ``dispatch.RIG_TOPICS`` does not, so an
   ``eth_getLogs`` filtered by it retrieves ZERO advances from a real rig registry.
   :data:`RIG_LOG_TOPICS` is the filter that actually works.
3. **The wire format is shared, so the DECODE is shared.** Identical topic0 means identical
   signature string means identical field layout — the V4 decoder reads a rig advance correctly.
   What differs is the MEANING (which registry owns the epoch, which verifier holds its pins), so
   the lanes diverge at interpretation, never at decoding.

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
PROTOCOL_RIG_EXACT = "coretex.rig-state.exact/v1"


# --------------------------------------------------------------------------- #
# Signatures — transcribed from the exact sources, hashed here, never copied as digests
# --------------------------------------------------------------------------- #
#: ``RigCoreTexStateRegistry.sol`` / ``rig/mining/RigCoreTexRegistry.sol``. IDENTICAL in both, and
#: identical to the V4 lane's — see the module docstring.
STATE_ADVANCED_SIG = (
    "CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32,uint256,uint16,bytes)")
EPOCH_FINALIZED_SIG = (
    "CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,"
    "bytes32)")
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
EPOCH_CONTEXT_SET_SIG = "CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32,bytes32,bytes32)"
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

_PINNED = {
    STATE_ADVANCED_TOPIC0: "2f0a89894d44aa2294de109d294ac072f0e206dc834a0c35c6fbf1623ec02dd0",
    EPOCH_FINALIZED_TOPIC0: "7c882e64d34d7e0b82f8004ec182f5b9e942388f7b7b1ea60233306c02821085",
    EPOCH_COMMIT_SET_TOPIC0: "59292804aa2c2d886e7b2e3982ee2e6df6e3d52f35220fbcafc233d216f7ddf6",
    EPOCH_SECRET_REVEALED_TOPIC0:
        "874024d45050fc7f9a2b883212a09399fe2d44dcff11ef6e75782efd2bc22bb6",
}
for _derived, _pin in _PINNED.items():
    if _derived != _pin:                                    # pragma: no cover - fail closed
        raise RuntimeError(f"topic0 drift: derived {_derived}, pinned {_pin}")

#: THE COLLISION, ASSERTED. If a future contract cut renames the advance event, this fails at
#: import and every assumption built on "the rig advance shares V4's topic0" gets re-examined
#: instead of quietly becoming false.
if STATE_ADVANCED_TOPIC0 != dp.V4_STATE_ADVANCED_TOPIC0:    # pragma: no cover - fail closed
    raise RuntimeError(
        "the rig registry's advance topic0 no longer equals the V4 lane's. That is a GOOD change, "
        "but this package routes on the assumption that it does not hold; re-read "
        "rig_events.route_rig_log and docs/V5-RIG-VALIDATOR.md before relaxing anything.")
if EPOCH_FINALIZED_TOPIC0 != dp.V4_EPOCH_FINALIZED_TOPIC0:  # pragma: no cover - fail closed
    raise RuntimeError("the rig registry's finalization topic0 no longer equals the V4 lane's")

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
    corpus_root: str
    active_frontier_root: str
    improvement_credits: int
    word_count: int
    compact_patch_bytes: bytes
    provenance: dp.LogProvenance

    #: The §7.4 primary key. ``transition_index`` is NOT in it: it is a per-epoch ordering, dense
    #: and zero-based, and using it across epochs (or as an identity) is the documented mistake.
    @property
    def join_key(self) -> Tuple[int, str, str]:
        return (self.epoch, self.parent_state_root, self.patch_hash)


_ADVANCE_HEAD_WORDS = 10


def decode_state_advanced(log: Mapping[str, Any]) -> StateAdvanced:
    _require(log, STATE_ADVANCED_TOPIC0, "CoreTexStateAdvanced")
    data = dp._data(log)                                                       # noqa: SLF001
    patch = dp._tail_bytes(data, 9, _ADVANCE_HEAD_WORDS, "compactPatchBytes")   # noqa: SLF001
    return StateAdvanced(
        epoch=dp._topic_uint(log, 1, "epoch", bits=64),                         # noqa: SLF001
        transition_index=dp._topic_uint(log, 2, "transitionIndex", bits=64),    # noqa: SLF001
        miner=dp._topic_address(log, 3, "miner"),                               # noqa: SLF001
        parent_state_root=dp._word(data, 0, "parentStateRoot"),                 # noqa: SLF001
        new_state_root=dp._word(data, 1, "newStateRoot"),                       # noqa: SLF001
        patch_hash=dp._word(data, 2, "patchHash"),                              # noqa: SLF001
        eval_report_hash=dp._word(data, 3, "evalReportHash"),                   # noqa: SLF001
        core_version_hash=dp._word(data, 4, "coreVersionHash"),                 # noqa: SLF001
        corpus_root=dp._word(data, 5, "corpusRoot"),                            # noqa: SLF001
        active_frontier_root=dp._word(data, 6, "activeFrontierRoot"),           # noqa: SLF001
        improvement_credits=dp._word_uint(data, 7, "improvementCredits"),       # noqa: SLF001
        word_count=dp._word_uint(data, 8, "wordCount", bits=16),                # noqa: SLF001
        compact_patch_bytes=patch,
        provenance=dp._provenance(log))                                         # noqa: SLF001


@dataclass(frozen=True)
class EpochFinalized:
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


def decode_epoch_finalized(log: Mapping[str, Any]) -> EpochFinalized:
    _require(log, EPOCH_FINALIZED_TOPIC0, "CoreTexEpochFinalized")
    data = dp._data(log)                                                       # noqa: SLF001
    names = ("parent_state_root", "final_state_root", "core_version_hash", "corpus_root",
             "active_frontier_root", "patch_set_root", "score_root", "baseline_manifest_hash")
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


#: The five law pins the verifier publishes per epoch. ``parent_state_root`` is the epoch's
#: CONTEXT PARENT — the head epoch N inherits — and is deliberately NOT called a "pin" elsewhere
#: in this package: it is a head, and heads and law have different rules.
EPOCH_CONTEXT_FIELDS = ("parent_state_root", "corpus_root", "active_frontier_root",
                        "baseline_manifest_hash", "core_version_hash")


@dataclass(frozen=True)
class EpochContextSet:
    epoch: int
    parent_state_root: str
    corpus_root: str
    active_frontier_root: str
    baseline_manifest_hash: str
    core_version_hash: str
    provenance: dp.LogProvenance

    def law_pins(self) -> Dict[str, str]:
        """The four values an advance carries and the registry enforces. NOT the head."""
        return {"corpus_root": self.corpus_root,
                "active_frontier_root": self.active_frontier_root,
                "core_version_hash": self.core_version_hash,
                "baseline_manifest_hash": self.baseline_manifest_hash}


def decode_epoch_context_set(log: Mapping[str, Any]) -> EpochContextSet:
    _require(log, EPOCH_CONTEXT_SET_TOPIC0, "CoreTexEpochContextSet")
    data = dp._data(log)                                                       # noqa: SLF001
    values = {n: dp._word(data, i, n) for i, n in enumerate(EPOCH_CONTEXT_FIELDS)}  # noqa: SLF001
    return EpochContextSet(epoch=dp._topic_uint(log, 1, "epochId", bits=64),   # noqa: SLF001
                           provenance=dp._provenance(log), **values)           # noqa: SLF001


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


# --------------------------------------------------------------------------- #
# The patch-hash rule
# --------------------------------------------------------------------------- #
#: ``RigCoreTexVerifier.sol:411-415``. THIS label, not the memory lane's.
#:
#: ``chain_first.RIG_PATCH_HASH_LABEL`` in the staged validator is
#: ``b"coretex-memory-transition-hash-v1"`` — the V5 MEMORY lane's transition-hash domain, which
#: the rig generated binding explicitly records as SUPERSEDED ("receipts signed under that label
#: revert ``CompactPatchHashMismatch`` on chain"). The two labels give different digests for every
#: input, so the staged check does not merely differ in style: it refuses every real advance.
#: Recorded as a finding in ``docs/V5-RIG-VALIDATOR.md``.
PATCH_HASH_LABEL = b"coretex-patch-hash-v1"
#: What the staged validator used. Kept so the two can be compared in a report rather than argued.
SUPERSEDED_PATCH_HASH_LABEL = b"coretex-memory-transition-hash-v1"


def patch_hash(compact_patch_bytes: bytes) -> str:
    """``keccak256(utf8("coretex-patch-hash-v1") ‖ compactPatchBytes)``, bare lowercase hex."""
    return keccak256_hex(PATCH_HASH_LABEL + bytes(compact_patch_bytes))


def check_patch_hash(advance: StateAdvanced) -> None:
    """Design §7.2 step 8. Self-verifying: the log carries both the bytes and their hash."""
    computed = patch_hash(advance.compact_patch_bytes)
    if computed != advance.patch_hash:
        superseded = keccak256_hex(SUPERSEDED_PATCH_HASH_LABEL + advance.compact_patch_bytes)
        hint = (" (it DOES match the superseded 'coretex-memory-transition-hash-v1' label, so "
                "this advance was produced by a signer still on the memory lane's rule)"
                if superseded == advance.patch_hash else "")
        raise RigEventError(
            f"patchHash mismatch: keccak256(label ‖ compactPatchBytes) = {computed}, the "
            f"confirmed advance says {advance.patch_hash}{hint}")


def transition_from_patch(advance: StateAdvanced) -> Dict[str, Any]:
    """The frontier transition the patch bytes ARE, parsed and validated.

    The rig lane's ``compactPatchBytes`` is the canonical JSON of the transition document (that is
    what the coordinator hashes into ``patchHash``), so a validator recovers the edit from the log
    alone — no artifact fetch, no archive node. Raises through :mod:`.frontier` if the bytes are
    not a valid transition, which is the honest outcome: an advance whose patch does not parse is
    not an advance anyone can replay.
    """
    check_patch_hash(advance)
    return fr.validate_transition(fr.parse_json(advance.compact_patch_bytes.decode("utf-8")))


# --------------------------------------------------------------------------- #
# The compact patch — a CONTRACT-MANDATED BINARY LAYOUT, not JSON
# --------------------------------------------------------------------------- #
#: ``RigCoreTexVerifier`` constants, transcribed from the exact source (``cdb91d2``).
COMPACT_PATCH_HEADER_BYTES = 42
COMPACT_PATCH_MAX_BYTES = 178
COMPACT_PATCH_MAX_WORDS = 4
#: Word indices at or above this are reserved and refused on chain.
RESERVED_WORD_START = 992
#: ``_readUint64BE`` result must fit int64 — the contract refuses anything larger.
MAX_SCORE_DELTA = 9_223_372_036_854_775_807

#: ``_wordMatchesPatchType``. ``0xff`` is the unrestricted type; the rest are windowed.
PATCH_TYPE_WORD_RANGES: Dict[int, Optional[Tuple[int, int]]] = {
    0x01: (384, 671), 0x02: (32, 383), 0x03: (800, 895), 0x04: (672, 799),
    0x05: (896, 991), 0x06: (0, 31), 0x07: (384, 671), 0xFF: None,
}


class CompactPatchError(RigEventError):
    """A compact patch that the verifier would have reverted on. Never a soft failure.

    Every refusal here mirrors a specific ``revert`` in ``_validateCompactPatch``, because a patch
    that is on chain HAS passed that function: anything this decoder rejects either never landed
    or was not decoded as the contract decodes it. Silently tolerating a malformed patch would
    mean the validator disagreed with the chain about what was accepted.
    """


@dataclass(frozen=True)
class CompactPatch:
    """The decoded rig state patch: a header plus ``wordCount`` (index, value) pairs."""

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
    """``_readLeb128WordIndex``. At most two bytes, and the two-byte form must be non-redundant.

    The ``value < 128`` refusal on a two-byte encoding is the important one: without it, ``0x82
    0x00`` and ``0x02`` would both decode to 2, giving one word index two spellings — and a patch
    with two spellings has two hashes, which would break the ``patchHash`` binding.
    """
    if offset >= len(data):
        raise CompactPatchError("word index runs past the end of the patch")
    first = data[offset]
    value = first & 0x7F
    nxt = offset + 1
    if not first & 0x80:
        return value, nxt
    if nxt >= len(data):
        raise CompactPatchError("truncated two-byte word index")
    second = data[nxt]
    if second & 0x80:
        raise CompactPatchError("word index is longer than two bytes")
    value |= (second & 0x7F) << 7
    if value < 128 or value >= 1024:
        raise CompactPatchError(
            f"two-byte word index decodes to {value}, which is not in [128, 1024): a redundant "
            "encoding would give one index two spellings, and therefore one patch two hashes")
    return value, nxt + 1


def decode_compact_patch(raw: bytes, *, parent_state_root: Optional[str] = None,
                         score_delta_ppm: Optional[int] = None) -> CompactPatch:
    """Decode ``compactPatchBytes`` exactly as ``RigCoreTexVerifier._validateCompactPatch`` does.

    THIS IS NOT THE MEMORY LANE'S ``transitionBytes``. That field is canonical JSON; this one is a
    binary struct the verifier reverts on if it is anything else. The two encodings are different
    formats for different protocols, and feeding one to the other's parser fails with a UTF-8
    error on the very first byte of a real rig patch (``0xff``). Canonical JSON in this field
    would have been rejected on chain, so the JSON reading can never be right here.

    ``parent_state_root`` and ``score_delta_ppm`` are checked when supplied — those are the two
    cross-checks the contract performs against the SIGNED receipt, and re-doing them is how a
    validator confirms the patch belongs to the advance rather than merely being well-formed.
    """
    data = bytes(raw)
    if len(data) < COMPACT_PATCH_HEADER_BYTES or len(data) > COMPACT_PATCH_MAX_BYTES:
        raise CompactPatchError(
            f"a compact patch is {COMPACT_PATCH_HEADER_BYTES}..{COMPACT_PATCH_MAX_BYTES} bytes; "
            f"this one is {len(data)}")
    patch_type = data[0]
    word_count = data[1]
    if patch_type not in PATCH_TYPE_WORD_RANGES:
        raise CompactPatchError(f"unknown patchType 0x{patch_type:02x}")
    if word_count == 0 or word_count > COMPACT_PATCH_MAX_WORDS:
        raise CompactPatchError(
            f"wordCount {word_count} is outside 1..{COMPACT_PATCH_MAX_WORDS}")
    score_delta = int.from_bytes(data[2:10], "big")
    if score_delta > MAX_SCORE_DELTA:
        raise CompactPatchError(f"scoreDelta {score_delta} exceeds int64")
    if score_delta_ppm is not None and score_delta != int(score_delta_ppm):
        raise CompactPatchError(
            f"the patch declares scoreDelta {score_delta} but the signed receipt says "
            f"{score_delta_ppm}")
    parent = data[10:42].hex()
    if parent_state_root is not None:
        expected = str(parent_state_root).lower().replace("0x", "")
        if parent != expected:
            raise CompactPatchError(
                f"the patch's parentStateRoot {parent} is not the advance's {expected}")

    words: List[Tuple[int, str]] = []
    seen: set = set()
    offset = COMPACT_PATCH_HEADER_BYTES
    window = PATCH_TYPE_WORD_RANGES[patch_type]
    for _ in range(word_count):
        index, offset = _read_leb128_word_index(data, offset)
        if index >= RESERVED_WORD_START:
            raise CompactPatchError(f"word index {index} is reserved (>= {RESERVED_WORD_START})")
        if window is not None and not window[0] <= index <= window[1]:
            raise CompactPatchError(
                f"word index {index} is outside patchType 0x{patch_type:02x}'s window {window}")
        if index in seen:
            raise CompactPatchError(f"duplicate word index {index}")
        seen.add(index)
        if offset + 32 > len(data):
            raise CompactPatchError("word value runs past the end of the patch")
        words.append((index, data[offset:offset + 32].hex()))
        offset += 32
    if offset != len(data):
        raise CompactPatchError(
            f"{len(data) - offset} trailing byte(s) after {word_count} word(s); the contract "
            "requires the patch to end exactly where its last word does")
    return CompactPatch(patch_type=patch_type, word_count=word_count,
                        score_delta_ppm=score_delta, parent_state_root=parent,
                        words=tuple(words), raw=data)
