# SPDX-License-Identifier: Apache-2.0
"""The rehearsal deployment addresses, and the superseded ones, named so they can be REFUSED.

WHY A MODULE RATHER THAN A CONSTANT SOMEWHERE
---------------------------------------------
The rehearsal deployment has moved twice already and will move again. Every address transcribed
into a check is an address that will one day be silently wrong — and a validator pinned to a
superseded deployment does not fail loudly, it passes against nothing.

So this module holds exactly two things, and neither is "the address to use":

1. :data:`SUPERSEDED_DEPLOYMENTS` — sets that are known DEAD. Naming them is the point: a run
   pointed at one gets a specific refusal ("this is the 2026-08-03 set, superseded on 2026-08-04")
   instead of a generic "no code at address", which reads like an RPC problem.
2. :func:`load_handoff` — the operator's own handoff file, read from disk, never retyped.

**THE ADDRESSES A RUN ACTUALLY USES COME FROM THE RELEASE ARTIFACT**, which is verified against
chain bytecode by :mod:`.release`. That is the whole design: the release is the deployment
authority and this module is a safety net, not a source. Nothing in the validation path imports a
constant from here.

THE COINCIDENCE THAT MUST NOT BECOME AN ASSUMPTION
--------------------------------------------------
In the current handoff, rig 2's authorized operator IS the coordinator signer
(``0x7aDC97D106eF8E511F2403b43F9aFDC8B262A85d``). That is a convenience of THIS deployment — it
saved moving a third key — and it is a trap: a validator that compared the recovered signature
address to the transaction's ``from`` would pass here and fail on every deployment where the
operator and the coordinator are different parties, which is all of them by design.
:func:`operator_signer_coincidence` states it as data so a test can assert the trap is not being
walked into. The join recovers against ``mining.coordinatorSigner()``, read from the chain.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, Mapping, Optional, Tuple

#: The operator's file. Root-owned, so a test runner may not be able to read it.
HANDOFF_PATH = ("/root/coretex-handoff/coretex-mainnet-rehearsal-handoff-20260804/"
                "deployment-values.json")

#: ``sha256`` of the handoff at the moment these values were recorded. A third witness: if the
#: operator re-issues the handoff, this stops matching and the mismatch is visible rather than
#: absorbed.
HANDOFF_SHA256 = "8df5080d7ff916a323019efe2c3d0e6af68396695e6a19e3f7d9ac72a9ab1655"

#: Base mainnet. The rehearsal is an ACCELERATED_DISPOSABLE_MAINNET_REHEARSAL — a real chain, a
#: disposable deployment. Neither half of that is optional context.
REHEARSAL_CHAIN_ID = 8453


class DeploymentError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


#: Deployment sets that are DEAD. Keyed by the date they were superseded.
#:
#: A run pointed at one of these should be told which one, not left to work it out from a bytecode
#: mismatch. Addresses are stored lowercased because that is the only comparison that is correct.
SUPERSEDED_DEPLOYMENTS: Dict[str, Dict[str, str]] = {
    "2026-08-03": {
        # The EIP-712 verifying contract observed in the generated receipt binding
        # (`rig_receipt_binding.EIP712_REHEARSAL_OBSERVED`). Superseded on 2026-08-04; the domain
        # separator moved with it, so every receipt digest computed against it is wrong now.
        "mining": "0x7302bcaba9a2f17447aea5ceb3dc1593681758f6",
    },
}

#: The live set, transcribed from the handoff ONLY so that a host without ``sudo`` can still run
#: the refusal check. :func:`load_handoff` is the authority when it is readable, and
#: :func:`check_against_handoff` refuses on any disagreement rather than preferring one.
LIVE_DEPLOYMENT: Dict[str, str] = {
    "access_manager": "0x8a76bf2f28d408c5535a09cff897400cfc9c2589",
    "mining": "0x7ce7ba1178f81eb88df89dda1b72b9f75b86cc96",
    "core_tex_verifier": "0x84472e32cc7c17447228887ab60c807510864d8a",
    "current_core_tex_registry": "0x45556811076a155e0a343b320b506bb0c72d49ed",
    "operator_registry": "0xe5a51bc1005d96a9340e133c7fcd935b40562d80",
    "mining_rig_nft": "0x6f2f53498102e89933d77f43b8c9290a1babcb7c",
    "eligibility_adapter": "0x3c4f70c814bd3a9101b4da74791af767c79d16f4",
    "epoch_settlement": "0x9db783ca4d4b111b5c77a1c304cee64bd8cf2163",
}

#: The handoff's ``identities.coordinatorAndRig2Operator``.
COORDINATOR_SIGNER = "0x7adc97d106ef8e511f2403b43f9afdc8b262a85d"

#: The live scoring policy at the block the handoff was cut. Recorded for cross-checking a
#: resolved snapshot's historical law, NEVER as a substitute for reading it from the chain.
POLICY_AT_BLOCK: Dict[str, Any] = {
    "block": 49513971,
    "rules_version": 193,
    "policy_hash": "0xe14663ecf01d62ee6d9c5fb087bd61191e7b791bc533012baa9c6509dbb8a0b3",
    "screener_work_bps": 20000,
    "state_advance_thresholds": [0, 2, 5, 10],
    "state_advance_work_bps": [100000, 150000, 200000, 300000],
}


def load_handoff(path: str = HANDOFF_PATH) -> Optional[Dict[str, Any]]:
    """The operator's handoff, or ``None`` when this host cannot read it.

    Tries a plain read first and falls back to ``sudo``. Returns ``None`` rather than raising when
    neither works: not being able to read a root-owned file is an ordinary condition on a
    validator host, and it must not be reported as a deployment problem.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.loads(fh.read())
    except (OSError, ValueError):
        pass
    try:
        result = subprocess.run(["sudo", "-n", "cat", path], capture_output=True, text=True,
                                timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:                                        # pragma: no cover - defensive
        return None


def check_against_handoff(handoff: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Compare :data:`LIVE_DEPLOYMENT` to the operator's file. A disagreement is a REFUSAL.

    The vendored copy exists so this check runs without ``sudo``, not so it can quietly drift from
    the operator's file. A mismatch means the operator re-issued the handoff and this package has
    not picked it up — exactly the state a validator should refuse to run in rather than paper
    over by preferring one source.
    """
    document = handoff if handoff is not None else load_handoff()
    if document is None:
        return {"checked": False,
                "reason": "the operator handoff is not readable on this host; the transcribed "
                          "addresses could not be cross-checked against it"}
    addresses = document.get("addresses") or {}
    expected = {
        "access_manager": addresses.get("accessManager"),
        "mining": addresses.get("mining"),
        "core_tex_verifier": addresses.get("coreTexVerifier"),
        "current_core_tex_registry": addresses.get("currentCoreTexRegistry"),
        "operator_registry": addresses.get("operatorRegistry"),
        "mining_rig_nft": addresses.get("miningRigNft"),
        "eligibility_adapter": addresses.get("eligibilityAdapter"),
        "epoch_settlement": addresses.get("epochSettlement"),
    }
    disagreements = {
        name: {"transcribed": LIVE_DEPLOYMENT[name], "handoff": str(value or "").lower()}
        for name, value in expected.items()
        if str(value or "").lower() != LIVE_DEPLOYMENT[name]}
    if disagreements:
        raise DeploymentError(
            "HANDOFF_DRIFT",
            f"the transcribed rehearsal addresses disagree with {HANDOFF_PATH}: {disagreements}. "
            "The operator has re-issued the handoff and this package has not picked it up")
    return {"checked": True, "handoff_generated_at": document.get("generatedAt"),
            "chain_id": document.get("chainId"),
            "deployment_kind": document.get("deploymentKind")}


def superseded_match(addresses: Mapping[str, str]) -> Optional[Tuple[str, Dict[str, str]]]:
    """Whether a set of addresses names a KNOWN-DEAD deployment, and which one.

    Matching on any single role is enough. A release that carries one superseded address and two
    live ones is not "mostly right" — it is a mixture that cannot correspond to any deployment
    that ever existed.
    """
    lowered = {role: str(value or "").lower() for role, value in addresses.items()}
    for date, dead in SUPERSEDED_DEPLOYMENTS.items():
        hits = {role: value for role, value in dead.items()
                if value in lowered.values()}
        if hits:
            return date, hits
    return None


def operator_signer_coincidence() -> Dict[str, Any]:
    """The rig-2 operator / coordinator-signer equality, stated so it cannot become an assumption."""
    return {
        "rig_id": 2,
        "operator": COORDINATOR_SIGNER,
        "coordinator_signer": COORDINATOR_SIGNER,
        "equal_in_this_deployment": True,
        "is_a_coincidence": True,
        "consequence": ("a validator that recovered the receipt signature and compared it to the "
                        "transaction's `from` would PASS on this deployment and FAIL on every "
                        "one where the operator and the coordinator are different parties — "
                        "which is all of them by design. The signer must be read from "
                        "mining.coordinatorSigner()"),
    }
