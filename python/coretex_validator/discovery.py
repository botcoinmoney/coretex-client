# SPDX-License-Identifier: Apache-2.0
"""Scan the public rig lane from its paired activation coordinates.

The contract deployment predates the public CoreTex product, so a deployment block is not a
valid replay floor.  Every scan starts at the confirmed block recorded beside the activation
epoch.  Logs below that block are refused.  CoreTex-protocol epochs (contexts, advances,
CoreTex credits, finalizations) below the activation epoch are refused.

Mining-clock events on the reused mining contract — standard V4 credits, epoch commit, and
epoch reveal — are still consumed for shared receipt-chain continuity.  Their epoch field is
the mining clock, which is allowed to lag the CoreTex activation context.  At the public
activation block the mining clock was still on the prior epoch, so those events may appear
after the activation block with an epoch below the CoreTex activation epoch.  The block floor
still applies to them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from .activation import ActivationError, PublicActivation
from . import rig_events
from .release import ReleaseDirectory
from .rig_events import CoordinatorSignerUpdated, DecodedLogs, RigDeployment, scan
from .rpc import DEFAULT_CONFIRMATION_DEPTH, JsonRpc, PinnedBlock, RigViews, RpcError
from .keccak256 import keccak256_hex


class DiscoveryError(ValueError):
    """The confirmed public feed does not match the closed release and activation record."""


def deployment_from_authority(authority: Mapping[str, Any]) -> RigDeployment:
    contracts = authority.get("contracts")
    if not isinstance(contracts, Mapping):
        raise DiscoveryError("contract authority has no contracts object")
    try:
        return RigDeployment(
            chain_id=int(authority["chain_id"]),
            registry=str(contracts["coretex_registry"]),
            mining=str(contracts["mining"]),
            verifier=str(contracts["coretex_verifier"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DiscoveryError("contract authority does not identify the public rig lane") from exc


def verify_deployment_authority(*, rpc: JsonRpc, authority: Mapping[str, Any],
                                deployment: RigDeployment, block: int) -> None:
    """Verify the release-selected code and all four immutable CoreTex cross-links."""
    contracts = authority.get("contracts")
    code_hashes = authority.get("code_hashes")
    bindings = authority.get("coretex_bindings")
    eip712 = authority.get("eip712")
    if not all(isinstance(value, Mapping)
               for value in (contracts, code_hashes, bindings, eip712)):
        raise DiscoveryError("contract authority lacks code hashes or immutable bindings")
    selected = {
        "coretex_registry": deployment.registry,
        "coretex_verifier": deployment.verifier,
        "mining": deployment.mining,
    }
    for name, address in selected.items():
        expected = code_hashes.get(name)
        if not isinstance(expected, str) or not expected.startswith("0x") \
                or len(expected) != 66:
            raise DiscoveryError(f"contract authority has no exact {name} code hash")
        try:
            code = rpc.code(address, block=block)
        except Exception as exc:
            raise DiscoveryError(
                f"cannot read release-bound {name} code at block {block}: {exc}") from exc
        observed = "0x" + keccak256_hex(code)
        if not code or observed.lower() != expected.lower():
            raise DiscoveryError(
                f"{name} code hash {observed} != release authority {expected}")

    views = RigViews(rpc, deployment, block=block)
    expected_links = {
        "registry.coreTexVerifier": (
            views.core_tex_verifier(), bindings.get("registry_verifier"),
            contracts.get("coretex_verifier")),
        "registry.epochClock": (
            views.registry_epoch_clock(), bindings.get("registry_epoch_clock"),
            contracts.get("mining")),
        "verifier.coreTexRegistry": (
            views.verifier_registry(), bindings.get("verifier_registry"),
            contracts.get("coretex_registry")),
        "verifier.mining": (
            views.verifier_mining(), bindings.get("verifier_mining"),
            contracts.get("mining")),
        "mining.coreTexVerifier": (
            views.mining_core_tex_verifier(), contracts.get("coretex_verifier"),
            bindings.get("registry_verifier")),
    }
    for label, values in expected_links.items():
        if not all(isinstance(value, str) for value in values) \
                or len({value.lower() for value in values}) != 1:
            raise DiscoveryError(
                f"deployed immutable {label} does not match the release contract graph")
    initial_signer = authority.get("initial_coordinator_signer")
    if not isinstance(initial_signer, str) or not initial_signer.startswith("0x") \
            or len(initial_signer) != 42:
        raise DiscoveryError("contract authority has no deployment-bootstrap signer")
    domain = eip712.get("domain_separator")
    if not isinstance(domain, str) or ("0x" + views.domain_separator().hex()).lower() \
            != domain.lower():
        raise DiscoveryError("deployed EIP-712 domain does not match the release authority")


def _coretex_protocol_epochs(decoded: DecodedLogs) -> Sequence[tuple[str, int]]:
    """Epochs that are CoreTex protocol coordinates, not the reused mining clock.

    Standard credits, commits, and reveals share the mining contract with V4.  They must be
    present for receipt-chain continuity, but their epoch is ``currentEpoch`` on that
    contract — which lagged the public CoreTex activation context.
    """
    groups = (
        ("advance", decoded.advances),
        ("CoreTex credit", decoded.coretex_credits),
        ("finalization", decoded.finalizations),
        ("context", decoded.contexts),
    )
    return tuple((kind, int(item.epoch)) for kind, items in groups for item in items)


@dataclass(frozen=True)
class PublicScan:
    activation: PublicActivation
    head: PinnedBlock
    deployment: RigDeployment
    logs: tuple[Mapping[str, Any], ...]
    decoded: DecodedLogs
    signer_updates: tuple[CoordinatorSignerUpdated, ...] = ()


def coordinator_signer_at(*, initial_signer: str,
                          updates: Sequence[CoordinatorSignerUpdated],
                          position: Optional[tuple[int, int]] = None) -> str:
    """Replay the mutable mining signer from its deployment bootstrap through ``position``."""
    current = str(initial_signer).lower()
    if not current.startswith("0x") or len(current) != 42:
        raise DiscoveryError("initial coordinator signer is not an address")
    previous_position: Optional[tuple[int, int]] = None
    for update in sorted(updates, key=lambda item: item.provenance.position):
        observed_position = update.provenance.position
        if previous_position is not None and observed_position <= previous_position:
            raise DiscoveryError("coordinator signer updates are not uniquely chain-ordered")
        previous_position = observed_position
        if position is not None and observed_position >= position:
            break
        if update.old_signer.lower() != current:
            raise DiscoveryError(
                f"coordinator signer rotation at {observed_position} starts from "
                f"{update.old_signer}, expected {current}")
        current = update.new_signer.lower()
    return current


def validate_public_feed(*, logs: Sequence[Mapping[str, Any]], head: PinnedBlock,
                         activation: PublicActivation, release: ReleaseDirectory,
                         signer_updates: Sequence[CoordinatorSignerUpdated] = ()) -> PublicScan:
    """Validate already-fetched logs, including the exact activation context event."""
    if head.number < activation.confirmed_block:
        raise DiscoveryError(
            f"confirmed head {head.number} is below activation block "
            f"{activation.confirmed_block}")
    activation.require_logs(logs)
    deployment = deployment_from_authority(release.authority)
    decoded = scan(logs, deployment)
    for kind, epoch in _coretex_protocol_epochs(decoded):
        try:
            activation.require_epoch(epoch, what=f"{kind} epoch")
        except ActivationError as exc:
            raise DiscoveryError(str(exc)) from exc

    contexts = [item for item in decoded.contexts if item.epoch == activation.epoch]
    if len(contexts) != 1:
        raise DiscoveryError(
            "the feed must contain exactly one context event for the activation epoch")
    context = contexts[0]
    if context.provenance.block_number != activation.confirmed_block:
        raise DiscoveryError(
            "activation.confirmed_block must be the activation context event block")
    if context.parent_state_root != release.genesis_frontier_root:
        raise DiscoveryError(
            "the activation context does not start at the release genesis frontier")
    if context.core_version_hash != release.release.raw["compatibility_lock_root"]:
        raise DiscoveryError(
            "the activation context does not bind the release compatibility lock")
    for item in decoded.contexts:
        if item.core_version_hash != release.release.raw["compatibility_lock_root"]:
            raise DiscoveryError(
                f"epoch {item.epoch} context does not bind the release compatibility lock")
    return PublicScan(
        activation, head, deployment, tuple(logs), decoded, tuple(signer_updates))


def scan_public_feed(rpc: JsonRpc, *, activation: PublicActivation,
                     release: ReleaseDirectory, to_block: Optional[int] = None,
                     confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH) -> PublicScan:
    """Fetch and validate one reorg-detectable public feed from the activation floor."""
    deployment = deployment_from_authority(release.authority)
    rpc.assert_chain(deployment.chain_id)
    if type(confirmation_depth) is not int or confirmation_depth < 0:
        raise DiscoveryError("confirmation_depth must be a nonnegative integer")
    confirmed = rpc.confirmed_head(confirmation_depth)
    end = confirmed if to_block is None else int(to_block)
    if end > confirmed:
        raise DiscoveryError(
            f"requested end block {end} is above confirmed head {confirmed} at depth "
            f"{confirmation_depth}")
    if end < activation.confirmed_block:
        raise DiscoveryError(
            f"requested end block {end} is below activation block {activation.confirmed_block}")
    head = rpc.block(end)
    start_hash = rpc.block_hash_at(activation.confirmed_block)
    verify_deployment_authority(
        rpc=rpc, authority=release.authority, deployment=deployment, block=head.number)
    deployment_block = release.authority.get("deployment_block")
    if isinstance(deployment_block, bool) or not isinstance(deployment_block, int) \
            or deployment_block <= 0 or deployment_block > activation.confirmed_block:
        raise DiscoveryError("contract authority deployment_block is invalid")
    signer_logs = rpc.get_logs(
        addresses=(deployment.mining,), topics=(rig_events.COORDINATOR_SIGNER_UPDATED_TOPIC0,),
        from_block=deployment_block, to_block=end,
    )
    signer_updates = tuple(scan(signer_logs, deployment).signer_updates)
    observed_signer = coordinator_signer_at(
        initial_signer=str(release.authority.get("initial_coordinator_signer")),
        updates=signer_updates)
    current_signer = RigViews(rpc, deployment, block=head.number).coordinator_signer().lower()
    if observed_signer != current_signer:
        raise DiscoveryError(
            f"coordinator signer event history resolves to {observed_signer}, but confirmed "
            f"chain state is {current_signer}")
    logs = rpc.get_logs(
        addresses=deployment.addresses,
        topics=(),
        from_block=activation.confirmed_block,
        to_block=end,
    )
    result = validate_public_feed(
        logs=logs, head=head, activation=activation, release=release,
        signer_updates=signer_updates)
    if rpc.block_hash_at(activation.confirmed_block) != start_hash \
            or rpc.block_hash_at(end) != head.hash:
        raise RpcError("the chain changed while the public feed was read")
    return result


__all__ = [
    "DiscoveryError", "PublicScan", "deployment_from_authority", "scan_public_feed",
    "coordinator_signer_at", "validate_public_feed", "verify_deployment_authority",
]
