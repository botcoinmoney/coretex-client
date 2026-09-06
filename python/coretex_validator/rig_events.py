# SPDX-License-Identifier: Apache-2.0
"""The sole public rig-lane event surface, derived from the deployed contract ABI.

The registry's advance event is::

    CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,
                         bytes32,uint256,uint16,bytes)

which hashes to ``f2b42259…``. Routing is address-scoped because topic0 alone never identifies a
deployment. There is one decoder and one current wire path.

WHERE EACH EVENT LIVES. The rig lane's epoch context is emitted by the **verifier**, not the
registry (design §4, "Epoch context is DELEGATED,
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

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import dispatch as dp
from . import frontier as fr
from .keccak256 import keccak256_hex

#: The public protocol identifier.
PROTOCOL_RIG = "coretex.rig-state/v3"


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
COORDINATOR_SIGNER_UPDATED_SIG = "CoordinatorSignerUpdated(address,address)"
#: ``RigCoreTexVerifier.sol:82-89`` — the epoch's law pins, on the VERIFIER.
EPOCH_CONTEXT_SET_SIG = "CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32)"

#: ``RigCoreTexVerifier.sol:90-97`` — the scoring law, scheduled by ``effectiveEpoch``. This is
#: what keeps ``rulesVersion`` dynamically chain-read for every public epoch.
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
COORDINATOR_SIGNER_UPDATED_TOPIC0 = dp.event_topic(COORDINATOR_SIGNER_UPDATED_SIG)
EPOCH_CONTEXT_SET_TOPIC0 = dp.event_topic(EPOCH_CONTEXT_SET_SIG)
POLICY_SCHEDULED_TOPIC0 = dp.event_topic(POLICY_SCHEDULED_SIG)

_PINNED = {
    STATE_ADVANCED_TOPIC0: "f2b422592475276aa1bbea8c780acec02e5628df6e59392a7ce6625907ca54e7",
    EPOCH_FINALIZED_TOPIC0: "212234825d6a82269e63c2bc21582948deb7729436c4dcba0dfdd831351c43b2",
    EPOCH_CONTEXT_SET_TOPIC0: "024a552750f4344a8386eb7109fcbdfd7c822052efcc0cf8c92d0619a3cec80f",
    EPOCH_COMMIT_SET_TOPIC0: "59292804aa2c2d886e7b2e3982ee2e6df6e3d52f35220fbcafc233d216f7ddf6",
    EPOCH_SECRET_REVEALED_TOPIC0:
        "874024d45050fc7f9a2b883212a09399fe2d44dcff11ef6e75782efd2bc22bb6",
}
for _derived, _pin in _PINNED.items():
    if _derived != _pin:                                    # pragma: no cover - fail closed
        raise RuntimeError(f"topic0 drift: derived {_derived}, pinned {_pin}")

#: The ``eth_getLogs`` topic0 OR-set a public validator subscribes to.
RIG_LOG_TOPICS: Tuple[str, ...] = tuple(sorted({
    STATE_ADVANCED_TOPIC0, EPOCH_FINALIZED_TOPIC0, CORETEX_CREDIT_ACCEPTED_TOPIC0,
    CREDIT_ACCEPTED_TOPIC0, EPOCH_COMMIT_SET_TOPIC0, EPOCH_SECRET_REVEALED_TOPIC0,
    EPOCH_CONTEXT_SET_TOPIC0, POLICY_SCHEDULED_TOPIC0, COORDINATOR_SIGNER_UPDATED_TOPIC0}))

EVENT_NAMES: Dict[str, str] = {
    STATE_ADVANCED_TOPIC0: "CoreTexStateAdvanced",
    EPOCH_FINALIZED_TOPIC0: "CoreTexEpochFinalized",
    CORETEX_CREDIT_ACCEPTED_TOPIC0: "RigCoreTexCreditAccepted",
    CREDIT_ACCEPTED_TOPIC0: "RigCreditAccepted",
    EPOCH_COMMIT_SET_TOPIC0: "EpochCommitSet",
    EPOCH_SECRET_REVEALED_TOPIC0: "EpochSecretRevealed",
    COORDINATOR_SIGNER_UPDATED_TOPIC0: "CoordinatorSignerUpdated",
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
    COORDINATOR_SIGNER_UPDATED_TOPIC0: "mining",
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
    return RigRoute(PROTOCOL_RIG, name, role, topic0)


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


@dataclass(frozen=True)
class CoordinatorSignerUpdated:
    """One operational signer rotation on the shared mining contract."""

    old_signer: str
    new_signer: str
    provenance: dp.LogProvenance


def decode_coordinator_signer_updated(log: Mapping[str, Any]) -> CoordinatorSignerUpdated:
    _require(log, COORDINATOR_SIGNER_UPDATED_TOPIC0, "CoordinatorSignerUpdated")
    return CoordinatorSignerUpdated(
        old_signer=dp._topic_address(log, 1, "oldSigner"),                     # noqa: SLF001
        new_signer=dp._topic_address(log, 2, "newSigner"),                     # noqa: SLF001
        provenance=dp._provenance(log))                                         # noqa: SLF001


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
    COORDINATOR_SIGNER_UPDATED_TOPIC0: decode_coordinator_signer_updated,
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
    signer_updates: List[CoordinatorSignerUpdated] = field(default_factory=list)
    ignored: int = 0

    def context_for(self, epoch: int) -> Optional[EpochContextSet]:
        """The last context set for an epoch.

        The verifier refuses a replacement after the epoch commit exists, so at most one context
        can govern state activity; taking the last is deterministic for an incomplete pre-commit
        log prefix as well.
        """
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
        CoordinatorSignerUpdated: out.signer_updates,
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
# Current epoch-context and descriptor authority
# --------------------------------------------------------------------------- #
# Event-address routing above is standalone-client plumbing.  Epoch-context parsing, transition
# descriptor decoding, and deterministic transition replay are the exact vendored implementation
# in dispatch.py.  Keeping these as aliases makes every public client entry point execute that one
# implementation; there is no second decoder or historical-format branch in this package.
_CURRENT_PROTOCOL_EXPORTS = (
    "EPOCH_CONTEXT_ADDRESS_MISMATCH",
    "EPOCH_CONTEXT_FIELDS",
    "EPOCH_CONTEXT_FORMAT",
    "EPOCH_CONTEXT_MALFORMED",
    "EPOCH_CONTEXT_ROOT_FIELDS",
    "EPOCH_CONTEXT_SEED_COMMITMENT_FIELDS",
    "EPOCH_CONTEXT_UNAVAILABLE",
    "DESCRIPTOR_ARTIFACT_HASH_ZERO",
    "DESCRIPTOR_EMPTY",
    "DESCRIPTOR_FORMAT_VERSION_MISMATCH",
    "DESCRIPTOR_HASH_MISMATCH",
    "DESCRIPTOR_LENGTH_INVALID",
    "DESCRIPTOR_NEW_ROOT_MISMATCH",
    "DESCRIPTOR_PARENT_MISMATCH",
    "DESCRIPTOR_REFUSALS",
    "DESCRIPTOR_UNEXPECTED",
    "DESCRIPTOR_VERSION_UNSUPPORTED",
    "SCREENER_PATCH_HASH_NONZERO",
    "ADVANCE_PATCH_HASH_ZERO",
    "TRANSITION_ARTIFACT_ADDRESS_MISMATCH",
    "TRANSITION_ARTIFACT_FIELDS",
    "TRANSITION_ARTIFACT_FORMAT",
    "TRANSITION_ARTIFACT_MALFORMED",
    "TRANSITION_ARTIFACT_NOT_CANONICAL",
    "TRANSITION_ARTIFACT_REFUSALS",
    "TRANSITION_ARTIFACT_UNAVAILABLE",
    "TRANSITION_CLOSURE_MALFORMED",
    "TRANSITION_CLOSURE_MISMATCH",
    "TRANSITION_CLOSURE_REFUSALS",
    "TRANSITION_CLOSURE_UNDERDECLARED",
    "TRANSITION_CLOSURE_UNKNOWN_ID",
    "TRANSITION_DESCRIPTOR_ARTIFACT_OFFSET",
    "TRANSITION_DESCRIPTOR_BYTES",
    "TRANSITION_DESCRIPTOR_HASH_LABEL",
    "TRANSITION_DESCRIPTOR_HASH_RULE",
    "TRANSITION_DESCRIPTOR_MAX_SCORE_DELTA_PPM",
    "TRANSITION_DESCRIPTOR_MIN_SCORE_DELTA_PPM",
    "TRANSITION_DESCRIPTOR_NEW_ROOT_OFFSET",
    "TRANSITION_DESCRIPTOR_PARENT_OFFSET",
    "TRANSITION_DESCRIPTOR_VERSION",
    "TRANSITION_DESCRIPTOR_VERSION_OFFSET",
    "TRANSITION_DESCRIPTOR_VERSION_UNSUPPORTED",
    "TRANSITION_EPOCH_CONTEXT_MISMATCH",
    "TRANSITION_LAW_PIN_CHANGE",
    "TRANSITION_NO_OP",
    "TRANSITION_PARENT_MISMATCH",
    "TRANSITION_RELEASE_PRIOR_MISMATCH",
    "TRANSITION_REPLAY_ROOT_MISMATCH",
    "TRANSITION_SCORE_DELTA_MISMATCH",
    "EpochContextError",
    "TransitionArtifactError",
    "TransitionDescriptor",
    "TransitionDescriptorError",
    "check_screener_descriptor",
    "check_transition_artifact_self_consistency",
    "check_transition_closure",
    "check_transition_epoch_context",
    "decode_transition_descriptor",
    "derive_transition_closure",
    "encode_transition_descriptor",
    "epoch_context_root",
    "finalize_transition_artifact_byte_length",
    "replay_transition_artifact",
    "transition_artifact_bytes",
    "transition_artifact_root",
    "transition_descriptor_hash",
    "validate_epoch_context",
    "validate_transition_artifact",
    "verify_epoch_context_bytes",
    "verify_transition_artifact_bytes",
)
for _protocol_name in _CURRENT_PROTOCOL_EXPORTS:
    globals()[_protocol_name] = getattr(dp, _protocol_name)


def check_patch_hash(advance: StateAdvanced) -> None:
    """Require the confirmed patch hash to address the confirmed descriptor bytes."""
    computed = dp.transition_descriptor_hash(advance.compact_patch_bytes)
    if computed != advance.patch_hash:
        raise RigEventError(
            f"patchHash mismatch: {dp.TRANSITION_DESCRIPTOR_HASH_RULE} = {computed}, "
            f"the confirmed advance says {advance.patch_hash}")


def check_state_advance_patch_hash(patch_hash: Any) -> None:
    """Require an outcome-2 receipt to name a descriptor rather than the zero word."""
    text = (bytes(patch_hash).hex() if isinstance(patch_hash, (bytes, bytearray))
            else str(patch_hash).strip().lower().removeprefix("0x"))
    if text == dp.DESCRIPTOR_ZERO_PATCH_HASH:
        raise dp.TransitionDescriptorError(
            dp.ADVANCE_PATCH_HASH_ZERO,
            "a state advance signs patchHash=bytes32(0), which names no transition")
