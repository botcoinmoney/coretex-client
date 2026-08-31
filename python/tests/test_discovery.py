from __future__ import annotations

from types import SimpleNamespace

import pytest

from coretex_validator import discovery
from coretex_validator.activation import PublicActivation
from coretex_validator.dispatch import LogProvenance
from coretex_validator.rig_events import (
    CoreTexCreditAccepted, DecodedLogs, EpochCommitSet, EpochContextSet, EpochSecretRevealed,
)
from coretex_validator.rpc import PinnedBlock
from coretex_validator.keccak256 import keccak256_hex


ROOT = "1" * 64
LOCK = "2" * 64
CONTRACTS = {
    "coretex_registry": "0x" + "11" * 20,
    "mining": "0x" + "22" * 20,
    "coretex_verifier": "0x" + "33" * 20,
}


def release():
    return SimpleNamespace(
        authority={"chain_id": 8453, "contracts": CONTRACTS},
        genesis_frontier_root=ROOT,
        release=SimpleNamespace(raw={"compatibility_lock_root": LOCK}),
    )


def decoded(epoch=9, block=100, parent=ROOT, lock=LOCK):
    context = EpochContextSet(
        epoch=epoch,
        parent_state_root=parent,
        epoch_context_root="3" * 64,
        core_version_hash=lock,
        provenance=LogProvenance(block_number=block, log_index=0),
    )
    return DecodedLogs([], [], [], [], [context], [], [], [])


def test_feed_starts_at_exact_activation_context(monkeypatch):
    monkeypatch.setattr(discovery, "scan", lambda logs, deployment: decoded())
    result = discovery.validate_public_feed(
        logs=[{"blockNumber": "0x64"}],
        head=PinnedBlock(120, "0x" + "44" * 32, 1),
        activation=PublicActivation(9, 100),
        release=release(),
    )
    assert result.deployment.addresses == (
        CONTRACTS["coretex_registry"], CONTRACTS["mining"], CONTRACTS["coretex_verifier"])


def _mining_clock_decoded():
    """Activation-epoch context plus mining-clock events from the prior mining epoch."""
    base = decoded()
    provenance = LogProvenance(block_number=100, log_index=1)
    return DecodedLogs(
        base.advances,
        base.coretex_credits,
        [CoreTexCreditAccepted(
            epoch=8, rig_id=1, operator="0x" + "11" * 20, solve_index=0,
            receipt_hash="a" * 64, challenge_id="b" * 64, work_units_bps=0,
            credits_earned=1, provenance=provenance, coretex=False)],
        base.finalizations,
        base.contexts,
        [EpochCommitSet(epoch=8, entropy_commitment="c" * 64, provenance=provenance)],
        [EpochSecretRevealed(epoch=8, revealed_secret="d" * 64, provenance=provenance)],
        base.policies,
    )


def test_feed_accepts_mining_clock_events_below_the_coretex_activation_epoch(monkeypatch):
    monkeypatch.setattr(discovery, "scan", lambda logs, deployment: _mining_clock_decoded())
    result = discovery.validate_public_feed(
        logs=[{"blockNumber": "0x64"}],
        head=PinnedBlock(120, "0x" + "44" * 32, 1),
        activation=PublicActivation(9, 100),
        release=release(),
    )
    assert len(result.decoded.standard_credits) == 1
    assert result.decoded.standard_credits[0].epoch == 8
    assert result.decoded.commits[0].epoch == 8
    assert result.decoded.reveals[0].epoch == 8


def test_feed_still_refuses_a_coretex_credit_below_the_activation_epoch(monkeypatch):
    base = decoded()
    credit = CoreTexCreditAccepted(
        epoch=8, rig_id=1, operator="0x" + "11" * 20, solve_index=0,
        receipt_hash="a" * 64, challenge_id="b" * 64, work_units_bps=10_000,
        credits_earned=1, provenance=LogProvenance(block_number=100, log_index=1),
        coretex=True)
    below = DecodedLogs(
        base.advances, [credit], base.standard_credits, base.finalizations,
        base.contexts, base.commits, base.reveals, base.policies)
    monkeypatch.setattr(discovery, "scan", lambda logs, deployment: below)
    with pytest.raises(discovery.DiscoveryError, match="BELOW_PUBLIC_ACTIVATION_EPOCH"):
        discovery.validate_public_feed(
            logs=[{"blockNumber": "0x64"}],
            head=PinnedBlock(120, "0x" + "44" * 32, 1),
            activation=PublicActivation(9, 100),
            release=release(),
        )


@pytest.mark.parametrize("item", [
    decoded(epoch=8),
    decoded(block=101),
    decoded(parent="4" * 64),
    decoded(lock="4" * 64),
])
def test_feed_refuses_wrong_activation_binding(monkeypatch, item):
    monkeypatch.setattr(discovery, "scan", lambda logs, deployment: item)
    with pytest.raises(discovery.DiscoveryError):
        discovery.validate_public_feed(
            logs=[{"blockNumber": "0x64"}],
            head=PinnedBlock(120, "0x" + "44" * 32, 1),
            activation=PublicActivation(9, 100),
            release=release(),
        )


def test_explicit_scan_end_cannot_claim_more_confirmations_than_it_has():
    class Rpc:
        def assert_chain(self, expected):
            assert expected == 8453

        def confirmed_head(self, depth):
            assert depth == 12
            return 120

    with pytest.raises(discovery.DiscoveryError, match="above confirmed head"):
        discovery.scan_public_feed(
            Rpc(), activation=PublicActivation(9, 100), release=release(),
            to_block=121, confirmation_depth=12)


def test_negative_confirmation_depth_is_refused_before_any_head_claim():
    class Rpc:
        def assert_chain(self, expected):
            assert expected == 8453

    with pytest.raises(discovery.DiscoveryError, match="nonnegative"):
        discovery.scan_public_feed(
            Rpc(), activation=PublicActivation(9, 100), release=release(),
            confirmation_depth=-1)


def test_deployed_code_and_immutable_coretex_graph_are_release_bound(monkeypatch):
    code = {
        name: (name + "-runtime").encode()
        for name in ("coretex_registry", "coretex_verifier", "mining")
    }
    authority = {
        "contracts": CONTRACTS,
        "code_hashes": {
            name: "0x" + keccak256_hex(raw) for name, raw in code.items()},
        "coretex_bindings": {
            "registry_epoch_clock": CONTRACTS["mining"],
            "registry_verifier": CONTRACTS["coretex_verifier"],
            "verifier_mining": CONTRACTS["mining"],
            "verifier_registry": CONTRACTS["coretex_registry"],
        },
        "initial_coordinator_signer": "0x" + "44" * 20,
        "eip712": {"domain_separator": "0x" + "55" * 32},
    }
    deployment = discovery.deployment_from_authority({"chain_id": 8453, **authority})

    class Rpc:
        def code(self, address, *, block):
            assert block == 120
            key = next(name for name, value in CONTRACTS.items() if value == address)
            return code[key]

    class Views:
        def __init__(self, rpc, deployment_, *, block):
            assert deployment_ == deployment and block == 120

        core_tex_verifier = lambda self: CONTRACTS["coretex_verifier"]
        registry_epoch_clock = lambda self: CONTRACTS["mining"]
        verifier_registry = lambda self: CONTRACTS["coretex_registry"]
        verifier_mining = lambda self: CONTRACTS["mining"]
        mining_core_tex_verifier = lambda self: CONTRACTS["coretex_verifier"]
        domain_separator = lambda self: bytes.fromhex("55" * 32)

    monkeypatch.setattr(discovery, "RigViews", Views)
    discovery.verify_deployment_authority(
        rpc=Rpc(), authority=authority, deployment=deployment, block=120)

    authority["coretex_bindings"]["verifier_registry"] = CONTRACTS["mining"]
    with pytest.raises(discovery.DiscoveryError, match="verifier.coreTexRegistry"):
        discovery.verify_deployment_authority(
            rpc=Rpc(), authority=authority, deployment=deployment, block=120)
