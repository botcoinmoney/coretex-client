# SPDX-License-Identifier: Apache-2.0
"""Registry-ROTATION continuity — a refusal this validator performs, NOT a chain guarantee.

==============================================================================================
READ THIS PARAGRAPH BEFORE YOU READ ANY OF THE CODE.

Everything in this module is a **convention** that the honest parties choose to honour. It is not
enforced by the chain and it cannot be. ``RigCoreTexVerifier.setCoreTexRegistry`` is gated on the
access-manager role **MINING_POLICY_ADMIN** and the *only* thing it checks is that the current
epoch is unlocked (``!_coreTexEpochLocked(mining.currentEpoch())``). It does not read
``PREDECESSOR_REGISTRY()``, it does not read ``MIN_ACCEPTED_EPOCH()``, it does not read
``GENESIS_STATE_ROOT()``, and it does not look at bytecode. **A holder of that role can point the
verifier at any address that answers ``ICoreTexRegistry``, including one that violates every rule
below, and the rig contracts — which are FROZEN and are not being modified — will accept it.**

So what this module buys is exactly this and nothing more: this validator will REFUSE to report a
snapshot as continuous across a rotation that fails the rule, and will say why. A validator that
does not run the check is not prevented from following an unapproved rotation. **Complete on-chain
prevention would require a separately audited change to** ``RigCoreTexVerifier``. Do not quote this
module as if it made a bad rotation impossible; it makes one UNFOLLOWED BY THE PARTIES THAT RUN IT,
which is a weaker and different claim, and the difference is the whole reason this text exists.
See :data:`ROTATION_CONVENTION_LIMITATION`.
==============================================================================================

WHAT THIS CHECKS THAT THE M-11 CONSTRUCTOR DOES NOT — this is not a duplicate.

``RigCoreTexStateRegistry(accessManager, genesisStateRoot, minAcceptedEpoch, predecessorRegistry)``
already PROVES on chain, at construction, that the successor's declared predecessor was retired,
that ``serviceCeilingEpoch == minAcceptedEpoch - 1``, that the handover epoch was finalized there,
and that the inherited head is the one the predecessor sealed. That answers *"is this a well-formed
successor of the registry it names?"*.

It cannot answer *"is the registry it names the one THIS VALIDATOR has been reading, and is this
successor the one the approved release describes?"* — the contract has no idea what release
artifact anyone is holding. Checks 1-3 are that binding; checks 4-6 are about facts the constructor
never sees. A well-formed successor of a **sibling or forked** lineage passes the constructor and
fails check 1, which is precisely what check 1 is for.

WHY THIS MATTERS TO A *VALIDATOR* SPECIFICALLY. :mod:`.release` already identifies a registry by
three fields — address, code hash, and the verifier binding — because a successor deployed from the
same source has an IDENTICAL code hash and, once it has inherited the epoch contexts, answers the
pin getters identically. The verifier binding tells you *which registry is live*. It does not tell
you whether the live one has any legitimate relationship to the one whose history you already
replayed. That is this module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

ZERO_ADDRESS = "0x" + "00" * 20

# ── The six typed refusals ────────────────────────────────────────────────────────────────── #

#: 1. the successor's ``PREDECESSOR_REGISTRY()`` is not the registry this validator was reading.
ROTATION_PREDECESSOR_NOT_INCUMBENT = "ROTATION_PREDECESSOR_NOT_INCUMBENT"
#: 2. ``MIN_ACCEPTED_EPOCH()`` != ``incumbent.serviceCeilingEpoch() + 1``.
ROTATION_EPOCH_FLOOR_NOT_CONTIGUOUS = "ROTATION_EPOCH_FLOOR_NOT_CONTIGUOUS"
#: 3. ``GENESIS_STATE_ROOT()`` is not the head the incumbent sealed (or there is no sealed head).
ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD = "ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD"
#: 4. the deployed runtime code hash is not the one the approved release pins.
ROTATION_BYTECODE_NOT_APPROVED = "ROTATION_BYTECODE_NOT_APPROVED"
#: 5. the successor answers to a different verifier and/or a different epoch clock.
ROTATION_VERIFIER_OR_CLOCK_REBOUND = "ROTATION_VERIFIER_OR_CLOCK_REBOUND"
#: 6. the rotation did not land at an unlocked epoch boundary.
ROTATION_EPOCH_LOCKED = "ROTATION_EPOCH_LOCKED"

#: Every code, in the order :func:`evaluate_rotation_continuity` applies them. A suite asserts the
#: inventory against this so a seventh condition cannot be added without being covered.
ROTATION_CODES: Tuple[str, ...] = (
    ROTATION_PREDECESSOR_NOT_INCUMBENT,
    ROTATION_EPOCH_FLOOR_NOT_CONTIGUOUS,
    ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD,
    ROTATION_BYTECODE_NOT_APPROVED,
    ROTATION_VERIFIER_OR_CLOCK_REBOUND,
    ROTATION_EPOCH_LOCKED,
)

# ── The limitation, as a first-class value ────────────────────────────────────────────────── #

#: **THE THING AN OPERATOR MUST READ.**
#:
#: It is a constant rather than a docstring so that it is UNMISSABLE: it is embedded verbatim in
#: every refusal this module produces, attached to the ACCEPT verdict too, carried into
#: :func:`.release.verify_deployment`'s report under ``wiring["rotation"]``, printed by the CLI, and
#: asserted by the suite. An operator who never opens a source file still sees it, and a refusal
#: that quotes it cannot be mistaken for a statement that the chain stopped something.
ROTATION_CONVENTION_LIMITATION: Mapping[str, str] = {
    "status": "CONVENTION_NOT_CHAIN_ENFORCED",
    "role": "MINING_POLICY_ADMIN",
    "entry_point": "RigCoreTexVerifier.setCoreTexRegistry(address)",
    "entry_point_source": "contracts/rig/mining/RigCoreTexVerifier.sol:331-338",
    "on_chain_precondition": (
        "the ONLY on-chain precondition is !_coreTexEpochLocked(mining.currentEpoch()) "
        "(RigCoreTexVerifier.sol:465-468). The setter reads neither PREDECESSOR_REGISTRY nor "
        "MIN_ACCEPTED_EPOCH nor GENESIS_STATE_ROOT nor any code hash."),
    "enforced_by": "the coordinator and coretex-client, by refusal, off chain",
    "not_enforced_by": "the rig contracts, which are FROZEN and are not being modified",
    "statement": (
        "REGISTRY-ROTATION CONTINUITY IS A CONVENTION, NOT A CHAIN GUARANTEE. The access-manager "
        "role MINING_POLICY_ADMIN retains the theoretical ability to point RigCoreTexVerifier at "
        "any registry it likes, including one that violates every rule below, and the rig "
        "contracts will accept it. What this check guarantees is only that parties running it "
        "refuse to treat such a registry as continuous with the history they replayed. Complete "
        "on-chain prevention would require a separately audited change to RigCoreTexVerifier (a "
        "lineage assertion inside setCoreTexRegistry); no such change exists, and none is "
        "proposed here."),
    "residual_risk": (
        "an unapproved MINING_POLICY_ADMIN rotation is DETECTED by every party that runs this "
        "check and is NOT PREVENTED for any party that does not"),
    "would_require_to_close": (
        "a separately audited RigCoreTexVerifier change asserting "
        "successor.PREDECESSOR_REGISTRY() == address(coreTexRegistry) inside setCoreTexRegistry, "
        "plus a deployment of that verifier. Out of scope: the rig contracts are frozen."),
}

#: One line, for anywhere that can carry only a string. Appended to every refusal reason.
ROTATION_LIMITATION_LINE = (
    "registry-rotation continuity is a CONVENTION enforced off chain by the coordinator and "
    "coretex-client, NOT a chain guarantee: MINING_POLICY_ADMIN can still repoint "
    "RigCoreTexVerifier.setCoreTexRegistry at any registry, and complete on-chain prevention "
    "would require a separately audited verifier change")


class RotationError(Exception):
    """A rotation this validator refuses to treat as continuous."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ── The observed facts ────────────────────────────────────────────────────────────────────── #


@dataclass(frozen=True)
class IncumbentFacts:
    """What the registry being rotated AWAY from says about itself."""

    address: str
    #: ``retired()``. False means there is no sealed handover at all.
    retired: bool
    #: ``serviceCeilingEpoch()``. Meaningful ONLY when ``retired`` — the contract says so.
    service_ceiling_epoch: int
    #: ``hasAnyTransition()``. False takes the degenerate never-mined branch.
    has_any_transition: bool
    #: ``epochFinalized(service_ceiling_epoch)``.
    handover_epoch_finalized: bool
    #: ``liveStateRoot(ceiling)`` when it mined, else its own ``GENESIS_STATE_ROOT()`` — read the
    #: way the successor's own constructor reads it (RigCoreTexStateRegistry.sol:501-518).
    sealed_head: str
    core_tex_verifier: str
    epoch_clock: str


@dataclass(frozen=True)
class SuccessorFacts:
    """What the candidate says about itself."""

    address: str
    #: ``PREDECESSOR_REGISTRY()``. Zero means it claims to be a genesis deployment.
    predecessor_registry: str
    min_accepted_epoch: int
    genesis_state_root: str
    #: ``keccak256(runtime code)`` at the observation block, bare lowercase 64-hex.
    code_hash: str
    core_tex_verifier: str
    epoch_clock: str


@dataclass(frozen=True)
class RotationEpochFacts:
    """The verifier's three lock terms, READ AT ``rotation_block - 1``.

    WHY NOT "NOW". ``_coreTexEpochLocked`` is evaluated by the setter, inside the rotation
    transaction, against the state immediately before it. Re-reading the same terms at validation
    time is a different question with a different answer: a LEGITIMATE rotation is followed by
    mining, so the successor's ``transitionCount(currentEpoch)`` becomes non-zero within the hour
    and a "read it now" check would refuse the very rotations it exists to bless. Pinning the read
    to the rotation block makes the check re-checkable by anyone, forever, from confirmed data.
    """

    rotation_block: int
    epoch: int
    total_credits: int
    screener_passes: int
    #: ``transitionCount(epoch)`` on the INCUMBENT — the registry still bound when the setter ran.
    incumbent_transition_count: int


@dataclass(frozen=True)
class RotationObservation:
    incumbent: IncumbentFacts
    successor: SuccessorFacts
    epoch: RotationEpochFacts
    #: The code hash the APPROVED RELEASE pins for the successor. ``None`` is NOT a pass.
    approved_registry_code_hash: Optional[str]
    approved_release_path: str
    observation_block: int


@dataclass(frozen=True)
class RotationRefusal:
    code: str
    checked: str
    expected: str
    observed: str
    reason: str

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "checked": self.checked, "expected": self.expected,
                "observed": self.observed, "reason": self.reason}


@dataclass
class RotationVerdict:
    accepted: bool
    refusals: List[RotationRefusal] = field(default_factory=list)
    checks: List[str] = field(default_factory=list)

    @property
    def codes(self) -> List[str]:
        return [refusal.code for refusal in self.refusals]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "codes": self.codes,
            "refusals": [refusal.as_dict() for refusal in self.refusals],
            "checks": list(self.checks),
            # Attached to the ACCEPT too, and deliberately: an accepted rotation is exactly when a
            # reader is most likely to mistake this refusal for a chain guarantee.
            "limitation": dict(ROTATION_CONVENTION_LIMITATION),
        }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _root(value: Any) -> str:
    """Roots are compared bare-lowercase-hex; the ``0x`` prefix is presentation, not identity."""
    return _norm(value).removeprefix("0x")


def evaluate_rotation_continuity(observation: RotationObservation) -> RotationVerdict:
    """THE RULE. Pure: no chain, no clock, no files, so every branch is drivable by a suite.

    Collect-all rather than fail-fast, matching :func:`.release.verify_deployment`: an operator
    repairing a mis-staged rotation should see the whole list once, not one item per re-run.
    """
    inc, suc, ep = observation.incumbent, observation.successor, observation.epoch
    refusals: List[RotationRefusal] = []
    checks: List[str] = []

    def refuse(code: str, checked: str, expected: Any, observed: Any, reason: str) -> None:
        refusals.append(RotationRefusal(
            code=code, checked=checked, expected=str(expected), observed=str(observed),
            reason=f"{reason} [{ROTATION_LIMITATION_LINE}]"))

    # ── 1. the successor's declared predecessor is OUR incumbent ───────────────────────────
    #
    # NOT what the constructor proved. The constructor proved the candidate is well formed with
    # respect to WHATEVER address it was handed; it had no way to know which registry this
    # validator replayed. A successor of a sibling deployment, or of a fork of this lineage,
    # passes the constructor and fails here — which is the entire point.
    #
    # A GENESIS claim is refused HERE rather than special-cased: a lane that already has an
    # incumbent with confirmed history cannot legitimately rotate onto a registry asserting there
    # is no lineage before it. The claim is falsifiable and we are falsifying it.
    declared = _norm(suc.predecessor_registry)
    incumbent_address = _norm(inc.address)
    if declared != incumbent_address:
        if declared == ZERO_ADDRESS:
            reason = (
                f"the candidate registry {_norm(suc.address)} declares itself a GENESIS deployment "
                f"(PREDECESSOR_REGISTRY() == 0), but this lane already has an incumbent registry "
                f"at {incumbent_address} holding confirmed history. A genesis claim asserts there "
                "is no lineage before it; one read of the incumbent refutes it, and adopting it "
                "would silently restart the lineage at a head nobody sealed")
        else:
            reason = (
                f"the candidate registry {_norm(suc.address)} names {declared} as its predecessor, "
                f"but the registry this validator has been reading is {incumbent_address}. The "
                "M-11 constructor already PROVED this candidate is a well-formed successor — of "
                "the registry it names. It cannot prove that registry is ours, because the "
                "contract has no idea whose history we replayed. This check is that binding, and "
                "a well-formed successor of somebody else's lineage is what it exists to refuse")
        refuse(ROTATION_PREDECESSOR_NOT_INCUMBENT, "successor.PREDECESSOR_REGISTRY()",
               incumbent_address, declared, reason)
    else:
        checks.append(
            f"1. successor.PREDECESSOR_REGISTRY() == the incumbent this validator read "
            f"({incumbent_address})")

    # ── 2. the authoritative windows are contiguous ────────────────────────────────────────
    #
    # ``MIN_ACCEPTED_EPOCH`` is the successor's immutable floor, ``serviceCeilingEpoch`` the
    # incumbent's one-shot ceiling (D6). ``floor == ceiling + 1`` is the only relation leaving no
    # epoch served by both and none served by neither. The constructor asserts the same arithmetic
    # against the predecessor it was handed; re-asserting it against OUR incumbent's ceiling read
    # NOW also catches a ceiling that moved after the successor was constructed.
    expected_floor = inc.service_ceiling_epoch + 1
    if suc.min_accepted_epoch != expected_floor:
        if suc.min_accepted_epoch > expected_floor:
            tail = (f"Epochs {expected_floor}..{suc.min_accepted_epoch - 1} would be served by "
                    "NEITHER registry — a hole no later deployment can fill, because both windows "
                    "are immutable/one-shot.")
        else:
            tail = (f"Epochs {suc.min_accepted_epoch}..{inc.service_ceiling_epoch} would be "
                    "claimed by BOTH registries, which is two authoritative heads for one epoch.")
        refuse(ROTATION_EPOCH_FLOOR_NOT_CONTIGUOUS, "successor.MIN_ACCEPTED_EPOCH()",
               expected_floor, suc.min_accepted_epoch,
               f"the incumbent {incumbent_address} sealed its service window at epoch "
               f"{inc.service_ceiling_epoch}, so the only contiguous floor for a successor is "
               f"{expected_floor}; the candidate declares {suc.min_accepted_epoch}. {tail}")
    else:
        checks.append(
            f"2. successor.MIN_ACCEPTED_EPOCH() == incumbent.serviceCeilingEpoch() + 1 "
            f"({expected_floor}) — contiguous, no gap, no overlap")

    # ── 3. the declared genesis is the head the incumbent actually SEALED ──────────────────
    #
    # The precondition is part of the check, not separate from it. An incumbent that is not
    # RETIRED has no sealed head, and one whose handover epoch is not FINALIZED has a head that
    # can still move. "We could not determine the sealed head" and "we checked and it matches"
    # must never be the same outcome.
    if not inc.retired:
        refuse(ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD, "incumbent.retired()", "true", "false",
               f"the incumbent {incumbent_address} has NOT been retired, so it has no sealed head "
               "for the candidate's GENESIS_STATE_ROOT to equal — and it can still accept "
               "advances for the epochs the candidate claims. retireAtEpoch is CONFIG_ADMIN while "
               "setCoreTexRegistry is MINING_POLICY_ADMIN, deliberately different keys so a "
               "handover is not a single-signature operation; an unretired incumbent means that "
               "ceremony did not happen")
    elif inc.has_any_transition and not inc.handover_epoch_finalized:
        refuse(ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD,
               f"incumbent.epochFinalized({inc.service_ceiling_epoch})", "true", "false",
               f"the incumbent {incumbent_address} mined epoch {inc.service_ceiling_epoch} but "
               "never FINALIZED it, so its live root is still a head that can move. Inheriting it "
               "would fix the successor's immutable genesis to a value the predecessor has not "
               "committed to")
    elif _root(suc.genesis_state_root) != _root(inc.sealed_head):
        provenance = (" (liveStateRoot at the finalized handover epoch)" if inc.has_any_transition
                      else " (the incumbent never mined, so the head that carries across is its "
                           "own GENESIS_STATE_ROOT, unchanged)")
        refuse(ROTATION_GENESIS_ROOT_NOT_SEALED_HEAD, "successor.GENESIS_STATE_ROOT()",
               _root(inc.sealed_head), _root(suc.genesis_state_root),
               f"the candidate's immutable GENESIS_STATE_ROOT is {_root(suc.genesis_state_root)}, "
               f"but the head the incumbent {incumbent_address} sealed at epoch "
               f"{inc.service_ceiling_epoch} is {_root(inc.sealed_head)}{provenance}. Adopting it "
               "would fork the state lineage at the handover: every advance the successor records "
               "would chain from a parent this lane never reached, and a replay of the two "
               "registries together would not be one history")
    else:
        checks.append(
            f"3. successor.GENESIS_STATE_ROOT() == the incumbent's sealed head "
            f"{_root(inc.sealed_head)} (retired, handover epoch {inc.service_ceiling_epoch} "
            f"{'finalized' if inc.has_any_transition else 'never mined'})")

    # ── 4. the bytecode is the approved release's bytecode ─────────────────────────────────
    #
    # Nothing on chain constrains this at all. A registry that answers every lineage getter
    # "correctly" while doing something else entirely in ``submitStateAdvance`` passes 1-3 and
    # fails only here. A MISSING PIN is a refusal, never a pass.
    approved = _root(observation.approved_registry_code_hash)
    if len(approved) != 64 or any(c not in "0123456789abcdef" for c in approved):
        refuse(ROTATION_BYTECODE_NOT_APPROVED, "approved release runtime_code_hashes.registry",
               "a 32-byte keccak256 pin",
               "NOT PINNED" if observation.approved_registry_code_hash is None
               else str(observation.approved_registry_code_hash),
               f"the approved release {observation.approved_release_path} pins no usable code hash "
               f"for the successor registry {_norm(suc.address)}, so there is nothing to compare "
               "the deployed bytecode against. NOT PINNED is reported as a refusal and never as a "
               "pass: an operator who did not record what was audited has not audited it as far "
               "as this check can tell")
    elif _root(suc.code_hash) != approved:
        refuse(ROTATION_BYTECODE_NOT_APPROVED, "keccak256(code(successor))", approved,
               _root(suc.code_hash),
               f"the registry deployed at {_norm(suc.address)} carries runtime code hash "
               f"{_root(suc.code_hash)}, but the approved release "
               f"{observation.approved_release_path} pins {approved}. Nothing on chain constrains "
               "WHICH contract setCoreTexRegistry points at — a registry that answers every "
               "lineage getter exactly as expected and diverges only inside submitStateAdvance "
               "passes checks 1-3 and is caught only here")
    else:
        checks.append(
            f"4. keccak256(code({_norm(suc.address)})) == the approved release's pin {approved}")

    # ── 5. same verifier, same epoch clock ─────────────────────────────────────────────────
    #
    # Both bindings are ONE-SHOT on the registry, so this is a permanent property. A successor
    # bound to a DIFFERENT verifier satisfies 1-3 perfectly and then accepts nothing our verifier
    # submits (``OnlyCoreTexVerifier``): the lane stops at the first receipt, after the rotation is
    # irreversible. A different EPOCH CLOCK is quieter and worse — advances are accepted, but
    # ``finalizeEpoch`` is gated on ITS clock, so seals happen on an unrelated timeline.
    verifier_rebound = _norm(suc.core_tex_verifier) != _norm(inc.core_tex_verifier)
    clock_rebound = _norm(suc.epoch_clock) != _norm(inc.epoch_clock)
    if verifier_rebound or clock_rebound:
        parts: List[str] = []
        if verifier_rebound:
            parts.append(f"coreTexVerifier(): incumbent {_norm(inc.core_tex_verifier)} -> "
                         f"candidate {_norm(suc.core_tex_verifier)}")
        if clock_rebound:
            parts.append(f"epochClock(): incumbent {_norm(inc.epoch_clock)} -> candidate "
                         f"{_norm(suc.epoch_clock)}")
        if verifier_rebound and clock_rebound:
            checked = "successor.coreTexVerifier() + successor.epochClock()"
            expected = f"{_norm(inc.core_tex_verifier)} + {_norm(inc.epoch_clock)}"
            observed = f"{_norm(suc.core_tex_verifier)} + {_norm(suc.epoch_clock)}"
        elif verifier_rebound:
            checked, expected, observed = ("successor.coreTexVerifier()",
                                           _norm(inc.core_tex_verifier),
                                           _norm(suc.core_tex_verifier))
        else:
            checked, expected, observed = ("successor.epochClock()", _norm(inc.epoch_clock),
                                           _norm(suc.epoch_clock))
        refuse(ROTATION_VERIFIER_OR_CLOCK_REBOUND, checked, expected, observed,
               "the candidate registry is not bound to the same lane as the incumbent "
               f"({'; '.join(parts)}). Both bindings are ONE-SHOT and therefore permanent. A "
               "candidate bound to a different VERIFIER rejects every advance our verifier submits "
               "(OnlyCoreTexVerifier) and the lane stops at the first receipt after an "
               "irreversible rotation; a candidate bound to a different EPOCH CLOCK is quieter and "
               "worse — it accepts advances while sealing epochs on a timeline unrelated to the "
               "one receipts are validated against")
    else:
        checks.append(
            f"5. successor.coreTexVerifier() == {_norm(inc.core_tex_verifier)} and "
            f"successor.epochClock() == {_norm(inc.epoch_clock)} — same verifier, same epoch clock")

    # ── 6. the rotation landed at an unlocked epoch boundary ───────────────────────────────
    #
    # Deliberately the verifier's OWN definition, term for term
    # (``RigCoreTexVerifier._coreTexEpochLocked``, :465-468)::
    #
    #     locked ⇔ mining.totalCredits(e) != 0
    #            ∨ qualifiedScreenerPassesSinceLastStateAdvance[e] != 0
    #            ∨ coreTexRegistry.transitionCount(e) != 0
    #
    # The setter reverts ``ActiveEpochHasCredits`` when this holds, so on a healthy chain this
    # check CONFIRMS something the chain already enforced — which is exactly why it is worth
    # stating: it is the one of the six the contracts really do cover, so a reader can see which
    # five they do not.
    lock_terms: List[str] = []
    if ep.total_credits != 0:
        lock_terms.append(f"mining.totalCredits({ep.epoch}) == {ep.total_credits}")
    if ep.screener_passes != 0:
        lock_terms.append(
            f"verifier.currentDifficultyCount({ep.epoch}) == {ep.screener_passes} "
            "(qualifiedScreenerPassesSinceLastStateAdvance)")
    if ep.incumbent_transition_count != 0:
        lock_terms.append(
            f"incumbent.transitionCount({ep.epoch}) == {ep.incumbent_transition_count}")
    if lock_terms:
        refuse(ROTATION_EPOCH_LOCKED,
               f"_coreTexEpochLocked({ep.epoch}) at block {ep.rotation_block - 1}",
               "false (all three terms zero)", f"true ({'; '.join(lock_terms)})",
               f"the rotation in block {ep.rotation_block} did NOT land at an unlocked epoch "
               f"boundary: at block {ep.rotation_block - 1}, epoch {ep.epoch} was LOCKED by "
               f"{'; '.join(lock_terms)}. A rotation under live activity retracts authorization "
               "that was already granted — an in-flight receipt names a parentStateRoot the "
               "successor does not hold, and it cannot be re-issued for a later epoch. "
               "RigCoreTexVerifier.setCoreTexRegistry reverts ActiveEpochHasCredits on exactly "
               "this condition, so an observation that says otherwise also means these reads are "
               "not describing the transaction they claim to describe")
    else:
        checks.append(
            f"6. _coreTexEpochLocked({ep.epoch}) was false at block {ep.rotation_block - 1} — "
            "totalCredits, screener passes and incumbent transitionCount all zero (the verifier's "
            "own three terms)")

    return RotationVerdict(accepted=not refusals, refusals=refusals, checks=checks)


def format_rotation_verdict(observation: RotationObservation, verdict: RotationVerdict) -> str:
    """The whole verdict as one operator-facing block. Used by the CLI and by the refusal."""
    header = (f"CoreTex registry rotation {_norm(observation.incumbent.address)} -> "
              f"{_norm(observation.successor.address)} (rotation block "
              f"{observation.epoch.rotation_block}, observed at block "
              f"{observation.observation_block})")
    note = "\n\nNOTE — " + ROTATION_CONVENTION_LIMITATION["statement"]
    if verdict.accepted:
        return (f"{header}: ACCEPTED. All six continuity conditions hold:\n  - "
                + "\n  - ".join(verdict.checks) + note)
    body = "\n  - ".join(
        f"{r.code}: {r.checked} — expected {r.expected}, observed {r.observed}. {r.reason}"
        for r in verdict.refusals)
    held = ("\n\nThese held:\n  - " + "\n  - ".join(verdict.checks)) if verdict.checks else ""
    return (f"{header}: REFUSED. {len(verdict.refusals)} of the six continuity conditions "
            f"failed:\n  - {body}{held}{note}")


def assert_rotation_continuity(observation: RotationObservation) -> RotationVerdict:
    """Throwing wrapper. Returns the verdict when it is an ACCEPT."""
    verdict = evaluate_rotation_continuity(observation)
    if not verdict.accepted:
        raise RotationError(verdict.refusals[0].code,
                            format_rotation_verdict(observation, verdict))
    return verdict


# ── Reading the facts off chain ───────────────────────────────────────────────────────────── #


def read_rotation_observation(
    rpc,
    *,
    incumbent_registry: str,
    successor_registry: str,
    mining: str,
    verifier: str,
    rotation_block: int,
    observation_block: int,
    approved_registry_code_hash: Optional[str],
    approved_release_path: str,
) -> RotationObservation:
    """Assemble a :class:`RotationObservation` from block-pinned reads.

    TWO BLOCK TAGS, ON PURPOSE, and neither is ``"latest"``. Lineage facts are read at
    ``observation_block`` because they are immutable or one-shot and their current value is what a
    consumer would be trusting; the lock terms at ``rotation_block - 1`` because that is the state
    ``setCoreTexRegistry`` itself evaluated. Mixing them would ask about a chain state that never
    existed — the same rule :mod:`.rpc` states about pinning every read to a block.
    """
    from .keccak256 import keccak256_hex
    from .rpc import selector, _encode_uint  # noqa: PLC0415 - local, mirrors release.py's style

    if rotation_block < 1:
        raise RotationError(
            "ROTATION_BLOCK_INVALID",
            f"the declared rotation block {rotation_block} has no predecessor block to read the "
            "verifier's lock terms at; a rotation cannot be the genesis block")

    at = int(observation_block)
    pre = int(rotation_block) - 1

    def word(to: str, sig: str, block: int, arg: Optional[int] = None) -> bytes:
        data = selector(sig) + ("" if arg is None else _encode_uint(arg))
        return rpc.eth_call(to=to, data=data, block=block)

    def as_int(raw: bytes) -> int:
        return int.from_bytes(raw, "big")

    def as_bool(raw: bytes) -> bool:
        return as_int(raw) != 0

    def as_address(raw: bytes) -> str:
        return "0x" + raw[-20:].hex()

    retired = as_bool(word(incumbent_registry, "retired()", at))
    ceiling = as_int(word(incumbent_registry, "serviceCeilingEpoch()", at))
    has_any = as_bool(word(incumbent_registry, "hasAnyTransition()", at))
    incumbent_genesis = word(incumbent_registry, "GENESIS_STATE_ROOT()", at)[:32].hex()

    # The sealed head, read the way the successor's constructor reads it — and ONLY when there is
    # one. An unretired incumbent's ceiling is 0, and ``liveStateRoot(0)`` would either revert
    # (``EpochContextNotSet``) or answer about an unrelated epoch. The read is SKIPPED and check 3
    # refuses on ``retired()`` instead; an undeterminable head is never filled in with a
    # plausible-looking value.
    handover_finalized = False
    sealed_head = incumbent_genesis
    if retired and has_any:
        handover_finalized = as_bool(
            word(incumbent_registry, "epochFinalized(uint64)", at, ceiling))
        if handover_finalized:
            sealed_head = word(incumbent_registry, "liveStateRoot(uint64)", at, ceiling)[:32].hex()

    incumbent = IncumbentFacts(
        address=_norm(incumbent_registry), retired=retired, service_ceiling_epoch=ceiling,
        has_any_transition=has_any, handover_epoch_finalized=handover_finalized,
        sealed_head=sealed_head,
        core_tex_verifier=as_address(word(incumbent_registry, "coreTexVerifier()", at)),
        epoch_clock=as_address(word(incumbent_registry, "epochClock()", at)))

    successor = SuccessorFacts(
        address=_norm(successor_registry),
        predecessor_registry=as_address(word(successor_registry, "PREDECESSOR_REGISTRY()", at)),
        min_accepted_epoch=as_int(word(successor_registry, "MIN_ACCEPTED_EPOCH()", at)),
        genesis_state_root=word(successor_registry, "GENESIS_STATE_ROOT()", at)[:32].hex(),
        code_hash=keccak256_hex(rpc.code(successor_registry, block=at)),
        core_tex_verifier=as_address(word(successor_registry, "coreTexVerifier()", at)),
        epoch_clock=as_address(word(successor_registry, "epochClock()", at)))

    rotation_epoch = as_int(word(mining, "currentEpoch()", pre))
    epoch_facts = RotationEpochFacts(
        rotation_block=int(rotation_block),
        epoch=rotation_epoch,
        total_credits=as_int(word(mining, "totalCredits(uint64)", pre, rotation_epoch)),
        screener_passes=as_int(
            word(verifier, "currentDifficultyCount(uint64)", pre, rotation_epoch)),
        incumbent_transition_count=as_int(
            word(incumbent_registry, "transitionCount(uint64)", pre, rotation_epoch)))

    return RotationObservation(
        incumbent=incumbent, successor=successor, epoch=epoch_facts,
        approved_registry_code_hash=approved_registry_code_hash,
        approved_release_path=approved_release_path, observation_block=at)


@dataclass(frozen=True)
class RotationDeclaration:
    """A release's signed statement that its registry arrived by ROTATION.

    The successor address is deliberately NOT a member: it is ``addresses.registry``, so a
    declaration cannot describe a rotation onto a registry the rest of the release does not name.
    """

    predecessor_registry: str
    rotation_block: int


def parse_rotation_declaration(
    document: Mapping[str, Any], *, registry_address: str,
) -> Optional[RotationDeclaration]:
    """Parse ``registry_rotation`` from a release document.

    ABSENT is fine and means "no rotation is claimed". PRESENT AND MALFORMED is a refusal, never a
    silent downgrade to absent: an operator who wrote the block believes it is doing something.
    """
    raw = document.get("registry_rotation")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise RotationError("ROTATION_DECLARATION_MALFORMED",
                            "registry_rotation must be an object; a declaration that cannot be "
                            "read is refused rather than ignored")
    predecessor = raw.get("predecessor_registry")
    if (not isinstance(predecessor, str) or not predecessor.startswith("0x")
            or len(predecessor) != 42):
        raise RotationError(
            "ROTATION_DECLARATION_MALFORMED",
            f"registry_rotation.predecessor_registry must be an address, got {predecessor!r}. The "
            "predecessor is what binds the successor's on-chain lineage proof to THIS lane; "
            "without it the proof is about somebody's lineage and not demonstrably ours")
    block = raw.get("rotation_block")
    if not isinstance(block, int) or isinstance(block, bool) or block <= 0:
        raise RotationError(
            "ROTATION_DECLARATION_MALFORMED",
            f"registry_rotation.rotation_block must be a positive integer, got {block!r}. The "
            "block the CoreTexRegistryUpdated event landed in is the only height at which the "
            "verifier's own lock terms can be re-read as setCoreTexRegistry evaluated them")
    if predecessor.lower() == str(registry_address).lower():
        raise RotationError(
            "ROTATION_DECLARATION_MALFORMED",
            f"registry_rotation.predecessor_registry {predecessor.lower()} is the same address as "
            "addresses.registry. A registry cannot succeed itself, and a self-referential "
            "declaration would make the continuity check compare a value with itself")
    return RotationDeclaration(predecessor_registry=predecessor.lower(), rotation_block=int(block))
