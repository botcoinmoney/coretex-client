# SPDX-License-Identifier: Apache-2.0
"""Step 6: the law that applied AT that transition — not today's.

WHY THIS IS A SEPARATE MODULE AND NOT A LOOKUP AT THE CALL SITE. The single most common way to
get historical verification wrong is to check an old transition against the current rules and
conclude it was invalid. The rig lane makes that easy to do by accident, because both halves of
its law are versioned in ways that read like constants:

* the **epoch context** (``epochContextRoot``, ``coreVersionHash``) is set per epoch on the
  VERIFIER and frozen at the arm point; the manifest addressed by ``epochContextRoot`` contains
  the corpus, frontier, baseline, thresholds and law roots;
* the **scoring policy** (``rulesVersion``, screener/state-advance work bps) is SCHEDULED by
  ``effectiveEpoch`` — announced ahead of the epoch it starts applying at, and never retroactive.

So "the law" for a transition is a function of its EPOCH, and it is recoverable from confirmed
logs alone: :class:`rig_events.EpochContextSet` for the context, :class:`rig_events.PolicyScheduled`
for the policy. Neither needs the current chain state, which is exactly the property that makes
historical replay possible on a chain that has since moved on.

THE RECEIPT NAMES ITS OWN ``rulesVersion``, AND THAT IS NOT THE SAME AS THE LAW. The receipt says
which policy version it was priced under; the schedule says which one was IN FORCE at its epoch.
:func:`law_for_epoch` returns the schedule's answer and :func:`check_receipt_against_law` compares
the two, because a receipt claiming a version that was not yet effective is a real fault and
adopting the receipt's own claim would make it undetectable.

WHAT IS NOT RECONSTRUCTED HERE. ``workUnitsBps`` pricing tables are read from the scheduled policy
when the deployment emitted one, and are otherwise reported as UNAVAILABLE rather than filled in
from :mod:`.rig_receipt_binding`'s staged model. The staged table is a record of what one lane
believed; using it as a fallback would silently turn "we could not check the price" into "the
price was right".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import dispatch as dp
from . import rig_events as rig

LAW_FORMAT = "coretex.rig-historical-law/v1"


class LawError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class EpochLaw:
    """Everything that was law for one epoch, and where each piece came from."""

    epoch: int
    #: The two context values the registry enforces on every advance.
    epoch_context_root: str
    core_version_hash: str
    #: The epoch's CONTEXT PARENT. A head, not a pin — kept apart deliberately.
    context_parent_state_root: str
    #: The entropy commitment, and the secret if it has been revealed. A transition inside an
    #: epoch whose secret is still sealed is replayable structurally but not deterministically.
    entropy_commitment: Optional[str]
    revealed_secret: Optional[str]
    #: The scoring policy in force at this epoch, or ``None`` when the deployment scheduled none.
    rules_version: Optional[int]
    policy_hash: Optional[str]
    screener_work_bps: Optional[int]
    policy_effective_epoch: Optional[int]
    sources: Dict[str, Any] = field(default_factory=dict)

    def enforced_pins(self) -> Dict[str, str]:
        """Exactly what an advance carries and the registry checks. NOT the head, NOT the policy."""
        return {"epoch_context_root": self.epoch_context_root,
                "core_version_hash": self.core_version_hash}

    def as_dict(self) -> Dict[str, Any]:
        # A value that is not known is OMITTED, and its absence is stated explicitly by the
        # `revealed` / `available` booleans beside it. Emitting `null` instead would be refused
        # by the canonical grammar, and — worse — would make "sealed secret" and "no such field"
        # the same bytes.
        entropy: Dict[str, Any] = {"revealed": self.revealed_secret is not None}
        if self.entropy_commitment is not None:
            entropy["commitment"] = self.entropy_commitment
        if self.revealed_secret is not None:
            entropy["revealed_secret"] = self.revealed_secret
        policy: Dict[str, Any] = {"available": self.rules_version is not None}
        for key, value in (("rules_version", self.rules_version),
                           ("policy_hash", self.policy_hash),
                           ("screener_work_bps", self.screener_work_bps),
                           ("effective_epoch", self.policy_effective_epoch)):
            if value is not None:
                policy[key] = value
        return {
            "format": LAW_FORMAT, "epoch": self.epoch,
            "enforced_pins": self.enforced_pins(),
            "context_parent_state_root": self.context_parent_state_root,
            "entropy": entropy,
            "policy": policy,
            "sources": {k: v for k, v in sorted(self.sources.items()) if v is not None},
        }


def policy_in_force(policies: Sequence[rig.PolicyScheduled],
                    epoch: int) -> Optional[rig.PolicyScheduled]:
    """The scheduled policy with the greatest ``effectiveEpoch <= epoch``.

    Ties are impossible in practice (one schedule per version) but are resolved toward the HIGHER
    ``rulesVersion`` so the answer is deterministic rather than dependent on log order.
    """
    eligible = [p for p in policies if p.effective_epoch <= int(epoch)]
    if not eligible:
        return None
    return max(eligible, key=lambda p: (p.effective_epoch, p.rules_version))


def law_for_epoch(decoded: rig.DecodedLogs, epoch: int,
                  chain_policy: Optional[Mapping[str, Any]] = None) -> EpochLaw:
    """Assemble the epoch's law from confirmed logs. Refuses when the context is missing."""
    epoch = int(epoch)
    context = decoded.context_for(epoch)
    if context is None:
        raise LawError(
            "EPOCH_CONTEXT_UNAVAILABLE",
            f"no CoreTexEpochContextSet was observed for epoch {epoch}. The epoch's law is set on "
            "the VERIFIER, so a scan that watched only the registry will always land here — "
            "widen the address set rather than falling back to current state")
    commit = next((c for c in decoded.commits if c.epoch == epoch), None)
    reveal = next((r for r in decoded.reveals if r.epoch == epoch), None)
    # CHAIN STATE BEATS AN EVENT SCAN. A policy is scheduled once and stays in force, so its
    # announcing event can sit far below any sensible log window; reading it from the verifier at
    # the pinned block answers the question regardless of how wide the scan was.
    policy = policy_in_force(decoded.policies, epoch)
    if chain_policy is not None:
        policy = rig.PolicyScheduled(
            rules_version=int(chain_policy["rules_version"]),
            effective_epoch=int(chain_policy["effective_epoch"]),
            policy_hash=str(chain_policy["policy_hash"]),
            screener_work_bps=int(chain_policy["screener_work_bps"]),
            provenance=(policy.provenance if policy is not None
                        else dp.LogProvenance(None, None, None, False)))
    return EpochLaw(
        epoch=epoch,
        epoch_context_root=context.epoch_context_root,
        core_version_hash=context.core_version_hash,
        context_parent_state_root=context.parent_state_root,
        entropy_commitment=commit.entropy_commitment if commit else None,
        revealed_secret=reveal.revealed_secret if reveal else None,
        rules_version=policy.rules_version if policy else None,
        policy_hash=policy.policy_hash if policy else None,
        screener_work_bps=policy.screener_work_bps if policy else None,
        policy_effective_epoch=policy.effective_epoch if policy else None,
        sources={
            "context": {"block": context.provenance.block_number,
                        "tx": context.provenance.transaction_hash},
            "commit": ({"block": commit.provenance.block_number} if commit else None),
            "reveal": ({"block": reveal.provenance.block_number} if reveal else None),
            "policy": ({"source": ("verifier.activeCoreTexRulesVersion + getCoreTexPolicy"
                                   if chain_policy is not None else "CoreTexPolicyScheduled log"),
                        "effective_epoch": policy.effective_epoch} if policy else
                       "no CoreTexPolicyScheduled observed; the pricing table is UNAVAILABLE and "
                       "is deliberately NOT substituted from the staged model"),
        })


def check_advance_against_law(advance: rig.StateAdvanced, law: EpochLaw) -> List[str]:
    """The three pins the registry enforces, re-checked against INDEPENDENTLY read law.

    The point is the independence. Comparing the advance's roots to the advance's own roots agrees
    by construction and catches nothing; comparing them to the verifier's context event is what a
    substituted registry cannot survive.
    """
    problems: List[str] = []
    for name, expected in law.enforced_pins().items():
        observed = getattr(advance, name)
        if observed != expected:
            problems.append(
                f"advance {name}={observed} but epoch {law.epoch}'s independently-read verifier "
                f"context pins {expected}")
    return problems


def check_receipt_against_law(receipt_values: Mapping[str, Any], law: EpochLaw) -> List[str]:
    """The receipt's own claims about the law, against the law that was scheduled."""
    problems: List[str] = []
    claimed = receipt_values.get("rulesVersion")
    if law.rules_version is None:
        problems.append(
            f"the receipt claims rulesVersion {claimed}, but this deployment scheduled no policy "
            "that a validator can read, so the claim is UNCHECKED (not accepted)")
    elif int(claimed) != int(law.rules_version):
        problems.append(
            f"the receipt was priced under rulesVersion {claimed}, but the policy in force at "
            f"epoch {law.epoch} is version {law.rules_version} (effective from "
            f"{law.policy_effective_epoch})")
    for name, key in (("epochContextRoot", "epoch_context_root"),
                      ("coreVersionHash", "core_version_hash")):
        expected = law.enforced_pins()[key]
        if str(receipt_values.get(name)) != expected:
            problems.append(f"receipt {name}={receipt_values.get(name)} != epoch law {expected}")
    return problems
