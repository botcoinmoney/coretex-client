# SPDX-License-Identifier: Apache-2.0
"""Versioned authorization-law dispatch for evaluation artifacts.

Prospective artifacts derive authority from their content roots and the
coordinator's on-chain EIP-712 receipt.  Historical v1 artifacts retain their
closed off-chain-signature replay path.  The artifact's own ``format`` selects
the law; callers cannot choose it as an argument.
"""
from __future__ import annotations

from typing import Any, Mapping

LAW_OFF_CHAIN_SIGNATURE_V1 = "coretex.authority/off-chain-signature/v1"
LAW_CHAIN_COMMITTED_V2 = "coretex.authority/chain-committed/v2"
LAWS = (LAW_OFF_CHAIN_SIGNATURE_V1, LAW_CHAIN_COMMITTED_V2)


class AuthorityLawError(Exception):
    """Base class for versioned-dispatch refusals."""


class UnknownLawError(AuthorityLawError):
    """A document declares a family this build has no law for."""


class WrongLawError(AuthorityLawError):
    """The selected path does not enforce the artifact's bound law."""

    def __init__(self, message: str, *, bound_law: str = "", required_law: str = "") -> None:
        super().__init__(message)
        self.bound_law = bound_law
        self.required_law = required_law


def law_of_artifact(artifact: Mapping[str, Any], *, families: Mapping[str, str],
                    what: str = "artifact") -> str:
    """Read the authorization law from ``artifact.format`` using a closed table."""
    if not isinstance(artifact, Mapping):
        raise UnknownLawError(
            f"{what} must be a mapping to carry a law binding, got "
            f"{type(artifact).__name__}")
    family = artifact.get("format")
    law = families.get(family) if isinstance(family, str) else None
    if law is None:
        raise UnknownLawError(
            f"{what} declares family {family!r}, which this build has no authorization law for; "
            f"known families are {sorted(families)}. An unrecognised family is refused rather "
            "than verified under whichever law happens to be reachable")
    return law


def require_prospective_law(bound: str, *, what: str = "artifact") -> str:
    """Require the chain-committed prospective law."""
    if bound != LAW_CHAIN_COMMITTED_V2:
        raise WrongLawError(
            f"{what} is bound to {bound!r}, but this is the PROSPECTIVE path, which enforces "
            f"{LAW_CHAIN_COMMITTED_V2!r}. A signed-era artifact must use the explicit historical "
            "evidence path",
            bound_law=bound, required_law=LAW_CHAIN_COMMITTED_V2)
    return bound


def require_historical_law(bound: str, *, what: str = "artifact") -> str:
    """Require the closed off-chain-signature historical law."""
    if bound != LAW_OFF_CHAIN_SIGNATURE_V1:
        raise WrongLawError(
            f"{what} is bound to {bound!r}, so it may not be replayed under "
            f"{LAW_OFF_CHAIN_SIGNATURE_V1!r}. The historical path cannot authorize a prospective "
            "artifact",
            bound_law=bound, required_law=LAW_OFF_CHAIN_SIGNATURE_V1)
    return bound
