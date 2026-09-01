from __future__ import annotations

import copy
import hashlib
import json

import pytest

from coretex_validator import release_schema as schema


def _root(char: str) -> str:
    return char * 64


def release_document():
    contract = schema._CONTRACT  # executable test of the packaged schema contract
    objects = {}
    for index, name in enumerate(contract["object_names"], start=1):
        value = f"{index:064x}"[-64:]
        objects[name] = {
            "hash_rule": schema._OBJECT_RULES[name],
            "media_type": "application/octet-stream",
            "path": f"objects/{name}",
            "raw_sha256": value,
            "root": value,
            "size": 1,
        }
        if name in schema._AUTHORITY_PATH_OBJECTS:
            role = name.removeprefix("rig_").removesuffix("_abi_root")
            objects[name]["authority_path"] = \
                f"v5/contract-authority/base-mainnet/{role}.abi.json"
    artifacts = {}
    distributions = {
        "adapter_wheel": "coretex-memory-agent",
        "runtime_wheel": "coretex-memory",
        "validator_wheel": "coretex-validator",
        "wasmtime_aarch64_wheel": "wasmtime",
        "wasmtime_amd64_wheel": "wasmtime",
    }
    filenames = {
        "adapter_wheel": "coretex_memory_agent-1.0.0-py3-none-any.whl",
        "miner_validator_kit": "coretex-miner-validator-kit-1.0.0.tar",
        "portability_evidence": "portability-evidence.json",
        "runtime_wheel": "coretex_memory-1.0.0-py3-none-any.whl",
        "validator_wheel": "coretex_validator-1.0.0-py3-none-any.whl",
        "wasmtime_aarch64_wheel":
            "wasmtime-46.0.1-py3-none-manylinux2014_aarch64.whl",
        "wasmtime_amd64_wheel":
            "wasmtime-46.0.1-py3-none-manylinux1_x86_64.whl",
    }
    for index, name in enumerate(contract["artifact_names"], start=100):
        entry = {
            "filename": filenames[name], "path": f"artifacts/{filenames[name]}",
            "sha256": f"{index:064x}"[-64:], "size": 1,
        }
        if name in distributions:
            version = "46.0.1" if name.startswith("wasmtime_") else "1.0.0"
            entry.update(distribution=distributions[name], version=version)
            if name == "wasmtime_aarch64_wheel":
                entry["tag"] = "py3-none-manylinux2014_aarch64"
            elif name == "wasmtime_amd64_wheel":
                entry["tag"] = "py3-none-manylinux1_x86_64"
        elif name == "portability_evidence":
            entry["format"] = "benchmark-v2/portability-matrix/v1"
        artifacts[name] = entry
    law = {
        **contract["law"],
        "benchmark_law_root": objects["benchmark_law_root"]["root"],
        "canonical_suite_root": objects["canonical_suite_root"]["root"],
        "evaluation_law_root": objects["evaluation_law_root"]["root"],
    }
    document = {
        "artifacts": artifacts,
        "compatibility_lock_root": _root("a"),
        "format": contract["release_format"],
        "genesis": {
            "baseline_root": _root("b"), "composition_root": _root("c"),
            "frontier_root": _root("d"),
            "profile_releases": {
                profile: {
                    "path": f"reference-releases/{_root(char)}.json", "root": _root(char)}
                for profile, char in zip(contract["profiles"], "ef1")},
        },
        "law": law,
        "name": "coretex",
        "objects": objects,
        "predecessor": None,
        "release_root": _root("0"),
        "rig_contract_authority_root": objects["rig_contract_authority_root"]["root"],
        "runtime_config_root": objects["runtime_config_root"]["root"],
        "sequence": 1,
        "version": "1.0.0",
    }
    body = {key: value for key, value in document.items() if key != "release_root"}
    document["release_root"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return document


def test_release_schema_accepts_only_first_public_product():
    parsed = schema.parse_release(release_document())
    assert parsed.raw["sequence"] == 1 and parsed.raw["predecessor"] is None


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(sequence=2),
    lambda value: value.update(sequence=True),
    lambda value: value.update(predecessor="1" * 64),
    lambda value: value.update(history=[]),
    lambda value: value["law"].update(revision="v1"),  # the withdrawn zero-tolerance recut
    lambda value: value["artifacts"]["validator_wheel"].update(distribution="other"),
    lambda value: value["objects"]["counter_resource_law_root"].update(
        hash_rule="sha256-bytes"),
    lambda value: value["objects"]["rig_mining_abi_root"].update(
        authority_path="v5/contract-authority/base-mainnet/verifier.abi.json"),
])
def test_release_schema_refuses_other_identity_or_open_fields(mutation):
    value = copy.deepcopy(release_document())
    mutation(value)
    with pytest.raises(schema.ReleaseSchemaError):
        schema.parse_release(value)
