# SPDX-License-Identifier: Apache-2.0
"""Descriptor-v3 resolver locks and artifact references; all fixtures are local bytes."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from coretex_validator import resolver_snapshot as rs
from coretex_validator import resolver_schema_constants as schema_constants
from coretex_validator import rig_events as rig
from coretex_validator.keccak256 import keccak256_hex


PUBLIC_SNAPSHOT = Path("/tmp/coretex-resolver-snapshot-public-readback-20260808.json")
PUBLIC_LOCK = Path("/home/ubuntu/botcoin-coordinator-v5/v5/COMPATIBILITY-LOCK.v1.json")
PUBLIC_SNAPSHOT_BYTES = 28_471
PUBLIC_SNAPSHOT_SHA256 = "49dac6c1237c49430b07b89aa7ef13e8af0487157c24cd781450cfeb21e60e3f"


def _seal(body: dict) -> dict:
    root = keccak256_hex(rs.COMPATIBILITY_LOCK_DOMAIN + rs.cn.canonical_bytes(body))
    return {**body, "lock_root": root}


def _lock() -> dict:
    roots = {
        name: {"hash_rule": rule, "kind": "root", "root": f"{index:02x}" * 32}
        for index, (name, rule) in enumerate(
            rs.COMPATIBILITY_LOCK_ROOT_RULES.items(), start=1)
    }
    literals = {
        name: {"kind": "literal", "schema": f"fixture/{name}", "version": index}
        for index, name in enumerate(rs.COMPATIBILITY_LOCK_LITERAL_NAMES, start=1)
    }
    return _seal({
        "format": rs.COMPATIBILITY_LOCK_SCHEMA,
        "legacy_aliases": [{
            "artifact": "coretex.memory-frontier.v1",
            "field": "runtime_abi_root",
            "resolves_to": "miner_module_abi_root",
        }],
        "locks": {**roots, **literals},
    })


def _fieldless_manifest(lock: dict) -> dict:
    return {
        "benchmark_law_root": lock["locks"]["benchmark_law_root"]["root"],
        "runtime_abi_root": "f1" * 32,
    }


def test_public_fieldless_snapshot_lock_block_is_byte_exact() -> None:
    """Pin the operational closeout target without making a network request."""
    if not PUBLIC_SNAPSHOT.exists() or not PUBLIC_LOCK.exists():
        pytest.skip("the 20260808 local public-readback evidence is not installed")
    raw = PUBLIC_SNAPSHOT.read_bytes()
    assert len(raw) == PUBLIC_SNAPSHOT_BYTES
    assert hashlib.sha256(raw).hexdigest() == PUBLIC_SNAPSHOT_SHA256
    target = json.loads(raw)
    lock = json.loads(PUBLIC_LOCK.read_text(encoding="utf-8"))
    manifest = {
        "benchmark_law_root": target["locks"]["cross_checked_against_manifest"][0]["root"],
        "runtime_abi_root": target["locks"]["legacy_manifest_non_lock_identities"][0]["root"],
    }
    block, findings = rs.build_locks_v3(
        manifest, lock, core_version_hash="0x" + lock["lock_root"])
    assert block == target["locks"]
    assert findings == target["findings"]
    assert len(block["locks"]) == 14
    assert {entry["binding"] for entry in block["locks"].values()} == {"chain"}


def test_public_v3_schema_constants_are_exact_and_version_isolated() -> None:
    if not PUBLIC_SNAPSHOT.exists():
        pytest.skip("the 20260808 local public-readback evidence is not installed")
    target = json.loads(PUBLIC_SNAPSHOT.read_bytes())
    assert schema_constants.DERIVATION_V3 == target["derivation"]
    assert schema_constants.DISCLOSURE_V3 == target["disclosure"]

    # V3 is a separate transcription, not an in-place mutation of either historical schema.
    assert schema_constants.DERIVATION_V1 is not schema_constants.DERIVATION_V3
    assert schema_constants.DERIVATION_V2 is not schema_constants.DERIVATION_V3
    assert schema_constants.DERIVATION_V2["receipt_layout"][
        "transition_descriptor_version"] == "0x20"
    assert schema_constants.DERIVATION_V2["receipt_layout"][
        "artifact_hash_member_ordinal"] == 15
    assert "activeFrontierRoot" in schema_constants.DERIVATION_V2["join_recipe"]["fields"]
    assert "stateWordCount" in schema_constants.DERIVATION_V1["join_recipe"]["fields"]
    assert schema_constants.DISCLOSURE != schema_constants.DISCLOSURE_V3
    assert "signed by a QUALIFIED" in schema_constants.DISCLOSURE
    assert "It is UNSIGNED" in schema_constants.DISCLOSURE_V3


def test_served_lock_bytes_are_canonical_and_readdressed() -> None:
    lock = _lock()
    encoded = rs.cn.canonical_bytes(lock)
    assert rs.verify_compatibility_lock_bytes(
        encoded, expected_root="0x" + lock["lock_root"]) == lock

    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.verify_compatibility_lock_bytes(
            encoded + b"\n", expected_root="0x" + lock["lock_root"])
    assert excinfo.value.code == "COMPATIBILITY_LOCK_NON_CANONICAL"

    changed_body = copy.deepcopy(lock)
    changed_body["locks"]["benchmark_law_root"]["root"] = "fe" * 32
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.verify_compatibility_lock_bytes(
            rs.cn.canonical_bytes(changed_body), expected_root="0x" + lock["lock_root"])
    assert excinfo.value.code == "COMPATIBILITY_LOCK_ROOT_MISMATCH"

    changed_root = {**lock, "lock_root": "ef" * 32}
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.verify_compatibility_lock_bytes(
            rs.cn.canonical_bytes(changed_root), expected_root="0x" + lock["lock_root"])
    assert excinfo.value.code == "COMPATIBILITY_LOCK_ROOT_MISMATCH"


def test_lock_shape_is_closed_and_benchmark_cross_check_is_strict() -> None:
    lock = _lock()
    malformed = {**lock, "unvalidated_extension": True}
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.validate_compatibility_lock(malformed, expected_root=lock["lock_root"])
    assert excinfo.value.code == "COMPATIBILITY_LOCK_MALFORMED"

    manifest = _fieldless_manifest(lock)
    manifest["benchmark_law_root"] = "aa" * 32
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.build_locks_v3(manifest, lock, core_version_hash=lock["lock_root"])
    assert excinfo.value.code == "V3_MANIFEST_BENCHMARK_LOCK_MISMATCH"


def test_explicit_manifest_binds_lock_root_and_runtime_abi_to_miner_module_abi() -> None:
    lock = _lock()
    manifest = {
        "benchmark_law_root": lock["locks"]["benchmark_law_root"]["root"],
        "compatibility_lock_root": lock["lock_root"],
        "runtime_abi_root": "aa" * 32,
    }
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.build_locks_v3(manifest, lock, core_version_hash=lock["lock_root"])
    assert excinfo.value.code == "V3_MANIFEST_RUNTIME_ABI_LOCK_MISMATCH"

    manifest["runtime_abi_root"] = lock["locks"]["miner_module_abi_root"]["root"]
    block, findings = rs.build_locks_v3(
        manifest, lock, core_version_hash=lock["lock_root"])
    assert findings == []
    assert "legacy_manifest_non_lock_identities" not in block
    assert block["cross_checked_against_manifest"][-1]["resolves_to"] == \
        "miner_module_abi_root"

    manifest["compatibility_lock_root"] = "bb" * 32
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.build_locks_v3(manifest, lock, core_version_hash=lock["lock_root"])
    assert excinfo.value.code == "V3_MANIFEST_COMPATIBILITY_LOCK_MISMATCH"


def test_runtime_record_has_no_influence_on_v3() -> None:
    lock = _lock()
    manifest = _fieldless_manifest(lock)
    plain = rs.build_locks_v3(manifest, lock, core_version_hash=lock["lock_root"])
    supplied = rs.build_locks_v3(
        manifest, lock,
        {"format": "malformed-and-deliberately-ignored", "identities": None},
        core_version_hash=lock["lock_root"], record_root="ee" * 32)
    assert supplied == plain


def test_public_descriptor_artifact_reference_is_exact_and_mutations_fail_closed() -> None:
    if not PUBLIC_SNAPSHOT.exists():
        pytest.skip("the 20260808 local public-readback evidence is not installed")
    target = json.loads(PUBLIC_SNAPSHOT.read_bytes())
    event = target["transitions"]["lineage"][0]["registry_event"]
    advance = SimpleNamespace(
        compact_patch_bytes=bytes.fromhex(event["compact_patch_bytes"][2:]),
        parent_state_root=event["parent_state_root"],
        new_state_root=event["new_state_root"],
        patch_hash=event["patch_hash"],
        transition_format_version=event["transition_format_version"],
        transition_index=event["transition_index"],
    )
    expected = next(
        artifact for artifact in target["artifacts"]
        if artifact["kind"] == "coretex.transition-artifact/v3")
    assert rs.build_artifacts([rs.build_transition_artifact_ref_v3(advance)]) == [expected]

    mutated = bytearray(advance.compact_patch_bytes)
    mutated[1] ^= 1
    with pytest.raises(rig.TransitionDescriptorError) as excinfo:
        rs.build_transition_artifact_ref_v3(
            SimpleNamespace(**{**vars(advance), "compact_patch_bytes": bytes(mutated)}))
    assert excinfo.value.code == rig.DESCRIPTOR_HASH_MISMATCH

    rebound = SimpleNamespace(
        **{**vars(advance), "compact_patch_bytes": bytes(mutated),
           "patch_hash": "0x" + rig.transition_descriptor_hash(bytes(mutated))})
    assert rs.build_transition_artifact_ref_v3(rebound)["root"] != expected["root"]
