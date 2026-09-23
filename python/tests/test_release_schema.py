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
    # DERIVED from the packaged contract, like the schema under test. A fixture that types the
    # version builds a release for whichever cut the fixture was written in, and then asserts
    # that the CURRENT schema accepts it -- which is a test of the fixture, not of the schema.
    version = schema.PRODUCT_VERSION
    filenames = {
        "adapter_wheel": f"coretex_memory_agent-{version}-py3-none-any.whl",
        "miner_validator_kit": f"coretex-miner-validator-kit-{version}.tar",
        "portability_evidence": "portability-evidence.json",
        "numeric_runtime_amd64": "numeric-runtime-amd64.tar",
        "numeric_runtime_aarch64": "numeric-runtime-aarch64.tar",
        "runtime_wheel": f"coretex_memory-{version}-py3-none-any.whl",
        "validator_wheel": f"coretex_validator-{version}-py3-none-any.whl",
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
            entry_version = "46.0.1" if name.startswith("wasmtime_") else version
            entry.update(distribution=distributions[name], version=entry_version)
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
        "predecessor": contract["product"]["predecessor"],
        "release_root": _root("0"),
        "rig_contract_authority_root": objects["rig_contract_authority_root"]["root"],
        "runtime_config_root": objects["runtime_config_root"]["root"],
        "sequence": contract["product"]["sequence"],
        "version": version,
    }
    body = {key: value for key, value in document.items() if key != "release_root"}
    document["release_root"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return document


def test_release_schema_accepts_only_the_pinned_prospective_product():
    parsed = schema.parse_release(release_document())
    assert parsed.raw["sequence"] == schema._CONTRACT["product"]["sequence"] \
        and parsed.raw["predecessor"] == schema._CONTRACT["product"]["predecessor"]


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(sequence=1),
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


def judged_release_document():
    """The same release, binding a sealed `cap.judge.v1` table.

    1.1.2 is the first release to bind one. The block is OPTIONAL by construction: a release with
    no table produces the byte-identical document -- and therefore the identical release root -- it
    produced before the capability existed, which is why this fixture recomputes the root rather
    than reusing the unjudged one.
    """
    document = copy.deepcopy(release_document())
    document["judge"] = {
        "capability": "cap.judge.v1",
        "descriptor": {"model_id": "jev-1.13.0", "battery": "need.m1"},
        "descriptor_mapping": {
            "product_descriptor_root": _root("a"),
            "release_descriptor_root": _root("b"),
        },
        "table": {
            "filename": "sealed-table.jsonl",
            "rows": 352658,
            "sha256": _root("c"),
            "table_root": _root("d"),
        },
        "tariff_id": "judge-tariff.model-token-equivalent.v2",
    }
    body = {key: value for key, value in document.items() if key != "release_root"}
    document["release_root"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    return document


def test_a_judged_release_document_is_accepted_and_still_reproduces_its_root():
    parsed = schema.parse_release(judged_release_document())
    judge = parsed.raw["judge"]
    assert judge["capability"] == "cap.judge.v1"
    assert judge["table"]["filename"] == "sealed-table.jsonl" and judge["table"]["rows"] == 352658
    # The unjudged document is unchanged by the capability existing.
    assert "judge" not in schema.parse_release(release_document()).raw


@pytest.mark.parametrize("mutation", [
    lambda value: value["judge"].update(capability="cap.text.v1"),
    lambda value: value["judge"].update(tariff_id=""),
    lambda value: value["judge"].update(descriptor={}),
    lambda value: value["judge"].pop("tariff_id"),
    lambda value: value["judge"].update(enabled=True),
    lambda value: value["judge"]["table"].update(filename="sub/sealed-table.jsonl"),
    lambda value: value["judge"]["table"].update(filename=".."),
    lambda value: value["judge"]["table"].update(rows=0),
    lambda value: value["judge"]["table"].update(rows=True),
    lambda value: value["judge"]["table"].update(sha256="not-a-root"),
    lambda value: value["judge"]["table"].update(table_root="0" * 64),
    lambda value: value["judge"]["table"].pop("table_root"),
    lambda value: value["judge"]["table"].update(path="release-cut/sealed-table.jsonl"),
    lambda value: value["judge"]["descriptor_mapping"].pop("product_descriptor_root"),
])
def test_a_malformed_judge_binding_refuses(mutation):
    value = judged_release_document()
    mutation(value)
    # The mutations above change the body, so the root has to follow or every case would refuse
    # for the wrong reason: what is under test is the judge block, not the hash.
    body = {key: item for key, item in value.items() if key != "release_root"}
    value["release_root"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    with pytest.raises(schema.ReleaseSchemaError):
        schema.parse_release(value)


def test_an_unknown_top_level_key_is_still_fatal_beside_the_optional_one():
    value = judged_release_document()
    value["history"] = []
    with pytest.raises(schema.ReleaseSchemaError):
        schema.parse_release(value)
