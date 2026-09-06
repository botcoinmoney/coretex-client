from __future__ import annotations

from pathlib import Path


PACKAGE = Path(__file__).parents[1] / "coretex_validator"
PYTHON_MEMBERS = {
    "__init__.py", "abi.py", "activation.py", "benchmark_replay.py", "canonical_suite.py",
    "cli.py", "compat_lock.py",
    "discovery.py", "dispatch.py", "epoch_law.py", "eval_artifact.py", "frontier.py",
    "join.py", "keccak256.py", "parent_execution.py", "publication.py",
    "receipt_chain.py", "release.py", "release_schema.py", "replay.py", "rig_events.py",
    "rig_receipt_binding.py", "rpc.py", "secp256k1.py", "snapshot.py",
}
DATA_MEMBERS = {
    "CANONICAL-SUITE.v1.json", "COUNTER_RESOURCE_LAW.v1.json", "LAW.md",
    "RELEASE-CONTRACT.v1.json", "RIG-CONTRACT-AUTHORITY.base-mainnet.json",
    "RIG-WIRE-BINDING.v1.json",
}


def test_source_package_has_one_exact_current_inventory():
    members = {path.name for path in PACKAGE.iterdir() if path.is_file()}
    assert members == PYTHON_MEMBERS | DATA_MEMBERS


def test_package_carries_no_private_key_material():
    prohibited = {".env", "id_rsa", "id_ed25519", "operator.key", "secret.key"}
    assert not ({path.name for path in PACKAGE.rglob("*")} & prohibited)
