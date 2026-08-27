from __future__ import annotations

from types import SimpleNamespace

import pytest

from coretex_validator import discovery
from coretex_validator.activation import PublicActivation
from coretex_validator.dispatch import LogProvenance
from coretex_validator.rig_events import DecodedLogs, EpochContextSet
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
