# SPDX-License-Identifier: Apache-2.0
"""Closed schemas for the first-public CoreTex release.

``RELEASE.json`` is supplied to the validator and binds this wheel as one of its artifacts.  The
wheel deliberately does not embed that final document: doing so would make the wheel hash depend
on a release root which itself depends on the wheel hash.  Instead it ships this closed schema and
the immutable law inputs, then verifies the supplied release and every reachable object.

The public activation epoch and confirmed block are deployment coordinates in a separate
``coretex.public-activation/v1`` record.  They are neither product identity nor release ancestry.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, Mapping

_CONTRACT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "RELEASE-CONTRACT.v1.json")


def _reject_duplicates(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = member
    return value


def _decode_json(raw: bytes, where: str) -> Mapping[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON value {token!r}")))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"{where} is not duplicate-free UTF-8 JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError(f"{where} must contain one JSON object")
    return value


def _load_contract() -> Mapping[str, Any]:
    with open(_CONTRACT_PATH, "rb") as handle:
        value = _decode_json(handle.read(), "RELEASE-CONTRACT.v1.json")
    fields = {
        "artifact_names", "format", "integration_format", "law", "object_names", "product",
        "profiles", "release_format"}
    if not isinstance(value, Mapping) or set(value) != fields \
            or value.get("format") != "coretex.validator-release-contract/v1":
        raise RuntimeError("RELEASE-CONTRACT.v1.json has another or open schema")
    return value


_CONTRACT = _load_contract()
RELEASE_FORMAT = str(_CONTRACT["release_format"])
INTEGRATION_FORMAT = str(_CONTRACT["integration_format"])
BASELINE_FORMAT = "coretex.genesis-baseline/v1"
LAW_ID = str(_CONTRACT["law"]["id"])
PRODUCT_VERSION = str(_CONTRACT["product"]["version"])

_ROOT = re.compile(r"^[0-9a-f]{64}$")
_PROFILES = frozenset(_CONTRACT["profiles"])
_RELEASE_FIELDS = frozenset((
    "artifacts", "compatibility_lock_root", "format", "genesis", "law", "name", "objects",
    "predecessor", "release_root", "rig_contract_authority_root", "runtime_config_root",
    "sequence", "version"))
_LAW_FIELDS = frozenset((
    "benchmark_law_root", "canonical_suite_root", "decision_engine_id",
    "evaluation_law_root", "family", "id", "revision"))
_GENESIS_FIELDS = frozenset((
    "baseline_root", "composition_root", "frontier_root", "profile_releases"))
_PUBLIC_GENESIS_FIELDS = frozenset((
    "genesis_frontier_root", "predecessor", "release_root", "sequence"))
_OBJECT_FIELDS = frozenset((
    "hash_rule", "media_type", "path", "raw_sha256", "root", "size"))
_OBJECT_FIELDS_WITH_AUTHORITY = _OBJECT_FIELDS | {"authority_path"}
_ARTIFACT_NAMES = frozenset(_CONTRACT["artifact_names"])
_REQUIRED_OBJECTS = frozenset(_CONTRACT["object_names"])
_HASH_RULES = frozenset((
    "sha256-bytes", "sha256-frontier-canonical-json", "sha256-benchmark-canonical-json"))
_OBJECT_RULES = {
    "benchmark_law_root": "sha256-bytes",
    "canonical_suite_root": "sha256-bytes",
    "counter_resource_law_root": "sha256-frontier-canonical-json",
    "counter_root": "sha256-benchmark-canonical-json",
    "evaluation_law_root": "sha256-benchmark-canonical-json",
    "evaluation_law_scorer_root": "sha256-benchmark-canonical-json",
    "miner_module_abi_root": "sha256-frontier-canonical-json",
    "renderer_root": "sha256-benchmark-canonical-json",
    "rig_contract_authority_root": "sha256-bytes",
    "rig_mining_abi_root": "sha256-bytes",
    "rig_registry_abi_root": "sha256-bytes",
    "rig_verifier_abi_root": "sha256-bytes",
    "runtime_config_root": "sha256-benchmark-canonical-json",
    "runtime_protocol_abi_root": "sha256-frontier-canonical-json",
    "validator_wheel_payload_root": "sha256-frontier-canonical-json",
    "public_candidate_isolation": "sha256-bytes",
    "public_candidate_reference": "sha256-bytes",
    "public_evaluation_ports_module": "sha256-bytes",
    "public_miner_abi_guide": "sha256-bytes",
    "public_miner_submission_terms": "sha256-bytes",
    "public_profile_law": "sha256-bytes",
    "public_resource_envelope": "sha256-bytes",
    "public_resource_envelope_guide": "sha256-bytes",
    "public_submission_reference": "sha256-bytes",
    "public_submit_guide": "sha256-bytes",
}
_AUTHORITY_PATH_OBJECTS = frozenset((
    "rig_mining_abi_root", "rig_registry_abi_root", "rig_verifier_abi_root"))
if set(_OBJECT_RULES) != _REQUIRED_OBJECTS:  # pragma: no cover - package build invariant
    raise RuntimeError("release object hash-rule contract does not cover the exact object set")
_WHEEL_DISTRIBUTIONS = {
    "adapter_wheel": "coretex-memory-agent",
    "runtime_wheel": "coretex-memory",
    "validator_wheel": "coretex-validator",
    "wasmtime_aarch64_wheel": "wasmtime",
    "wasmtime_amd64_wheel": "wasmtime",
}


class ReleaseSchemaError(ValueError):
    """A release document is malformed or cross-binds two different products."""


def _closed(value: Any, fields: frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseSchemaError(f"{where} must be an object")
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing or unknown:
        raise ReleaseSchemaError(
            f"{where} is not closed (missing={missing}, unknown={unknown})")
    return value


def root(value: Any, where: str) -> str:
    if not isinstance(value, str) or _ROOT.fullmatch(value) is None:
        raise ReleaseSchemaError(f"{where} must be 64 lowercase hexadecimal characters")
    if value == "0" * 64:
        raise ReleaseSchemaError(f"{where} must not be the zero root")
    return value


def _relative_path(value: Any, where: str, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix) or "\\" in value:
        raise ReleaseSchemaError(f"{where} must be below {prefix!r}")
    if "\x00" in value or unicodedata.normalize("NFC", value) != value:
        raise ReleaseSchemaError(f"{where} is not a canonical Unicode path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ReleaseSchemaError(f"{where} is not a canonical relative path")
    return value


def _size(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 64 * 1024 * 1024:
        raise ReleaseSchemaError(f"{where} must be an integer in 1..67108864")
    return value


def _validate_objects(value: Any) -> Dict[str, Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != _REQUIRED_OBJECTS:
        raise ReleaseSchemaError(
            f"runtime release objects must be exactly {sorted(_REQUIRED_OBJECTS)}")
    result: Dict[str, Mapping[str, Any]] = {}
    paths: set[str] = set()
    for name, raw in value.items():
        if not isinstance(name, str) or not name:
            raise ReleaseSchemaError("runtime release has an empty object name")
        allowed = (_OBJECT_FIELDS_WITH_AUTHORITY if name in _AUTHORITY_PATH_OBJECTS
                   else _OBJECT_FIELDS)
        entry = dict(_closed(raw, frozenset(allowed), f"objects.{name}"))
        if entry["hash_rule"] != _OBJECT_RULES[name]:
            raise ReleaseSchemaError(
                f"objects.{name}.hash_rule must be {_OBJECT_RULES[name]!r}")
        if not isinstance(entry["media_type"], str) or not entry["media_type"]:
            raise ReleaseSchemaError(f"objects.{name}.media_type must be non-empty")
        path = _relative_path(entry["path"], f"objects.{name}.path", "objects/")
        if path in paths:
            raise ReleaseSchemaError(f"two release objects use path {path!r}")
        paths.add(path)
        root(entry["root"], f"objects.{name}.root")
        root(entry["raw_sha256"], f"objects.{name}.raw_sha256")
        _size(entry["size"], f"objects.{name}.size")
        if "authority_path" in entry:
            role = name.removeprefix("rig_").removesuffix("_abi_root")
            expected = f"v5/contract-authority/base-mainnet/{role}.abi.json"
            if _relative_path(
                    entry["authority_path"], f"objects.{name}.authority_path", "v5/") != expected:
                raise ReleaseSchemaError(
                    f"objects.{name}.authority_path must be {expected!r}")
        result[name] = entry
    return result


def _validate_artifacts(value: Any) -> Dict[str, Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != _ARTIFACT_NAMES:
        raise ReleaseSchemaError(
            f"runtime release artifacts must be exactly {sorted(_ARTIFACT_NAMES)}")
    result: Dict[str, Mapping[str, Any]] = {}
    paths: set[str] = set()
    for name, raw in value.items():
        required = {"filename", "path", "sha256", "size"}
        if name.endswith("_wheel"):
            required |= {"distribution", "version"}
            if name.startswith("wasmtime_"):
                required.add("tag")
        elif name == "portability_evidence":
            required |= {"format"}
        entry = dict(_closed(raw, frozenset(required), f"artifacts.{name}"))
        path = _relative_path(entry["path"], f"artifacts.{name}.path", "artifacts/")
        if path in paths:
            raise ReleaseSchemaError(f"two release artifacts use path {path!r}")
        paths.add(path)
        if entry["filename"] != path.split("/")[-1]:
            raise ReleaseSchemaError(f"artifacts.{name}.filename disagrees with its path")
        root(entry["sha256"], f"artifacts.{name}.sha256")
        _size(entry["size"], f"artifacts.{name}.size")
        if name.endswith("_wheel"):
            expected_version = "46.0.1" if name.startswith("wasmtime_") else PRODUCT_VERSION
            if entry["version"] != expected_version:
                raise ReleaseSchemaError(
                    f"artifacts.{name}.version must be {expected_version}")
            if entry["distribution"] != _WHEEL_DISTRIBUTIONS[name]:
                raise ReleaseSchemaError(
                    f"artifacts.{name}.distribution must be {_WHEEL_DISTRIBUTIONS[name]!r}")
            expected_filename = {
                "adapter_wheel": "coretex_memory_agent-1.0.0-py3-none-any.whl",
                "runtime_wheel": "coretex_memory-1.0.0-py3-none-any.whl",
                "validator_wheel": "coretex_validator-1.0.0-py3-none-any.whl",
                "wasmtime_aarch64_wheel":
                    "wasmtime-46.0.1-py3-none-manylinux2014_aarch64.whl",
                "wasmtime_amd64_wheel":
                    "wasmtime-46.0.1-py3-none-manylinux1_x86_64.whl",
            }[name]
            if entry["filename"] != expected_filename:
                raise ReleaseSchemaError(
                    f"artifacts.{name}.filename must be {expected_filename!r}")
            if name.startswith("wasmtime_"):
                expected_tag = ("py3-none-manylinux2014_aarch64"
                                if name == "wasmtime_aarch64_wheel"
                                else "py3-none-manylinux1_x86_64")
                if entry["tag"] != expected_tag:
                    raise ReleaseSchemaError(
                        f"artifacts.{name}.tag must be {expected_tag!r}")
        elif name == "portability_evidence":
            if entry["format"] != "benchmark-v2/portability-matrix/v1" \
                    or entry["filename"] != "portability-evidence.json":
                raise ReleaseSchemaError("portability evidence has another format or filename")
        elif name == "miner_validator_kit" \
                and entry["filename"] != "coretex-miner-validator-kit-1.0.0.tar":
            raise ReleaseSchemaError("miner validator kit has another filename")
        result[name] = entry
    return result


def _json_root(document: Mapping[str, Any], self_field: str) -> str:
    body = {key: value for key, value in document.items() if key != self_field}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RuntimeRelease:
    raw: Mapping[str, Any]

    @property
    def release_root(self) -> str:
        return str(self.raw["release_root"])

    @property
    def genesis_frontier_root(self) -> str:
        return str(self.raw["genesis"]["frontier_root"])


def parse_release(value: Any) -> RuntimeRelease:
    document = dict(_closed(value, _RELEASE_FIELDS, "runtime release"))
    if document["format"] != RELEASE_FORMAT:
        raise ReleaseSchemaError(f"runtime release format must be {RELEASE_FORMAT!r}")
    product = _CONTRACT["product"]
    if document["name"] != product["name"] or document["version"] != PRODUCT_VERSION:
        raise ReleaseSchemaError("the first public runtime release must be coretex 1.0.0")
    if type(document["sequence"]) is not int \
            or document["sequence"] != product["sequence"] \
            or document["predecessor"] != product["predecessor"]:
        raise ReleaseSchemaError("public genesis requires sequence=1 and predecessor=null")
    law = _closed(document["law"], _LAW_FIELDS, "runtime release law")
    if any(law[field] != _CONTRACT["law"][field] for field in (
            "id", "family", "revision", "decision_engine_id")):
        raise ReleaseSchemaError("runtime release does not bind the one public fixed-suite law")
    for field in ("benchmark_law_root", "canonical_suite_root", "evaluation_law_root"):
        root(law[field], f"law.{field}")
    root(document["compatibility_lock_root"], "compatibility_lock_root")
    root(document["runtime_config_root"], "runtime_config_root")
    root(document["rig_contract_authority_root"], "rig_contract_authority_root")
    genesis = _closed(document["genesis"], _GENESIS_FIELDS, "runtime release genesis")
    for field in ("baseline_root", "composition_root", "frontier_root"):
        root(genesis[field], f"genesis.{field}")
    releases = genesis["profile_releases"]
    if not isinstance(releases, Mapping) or set(releases) != _PROFILES:
        raise ReleaseSchemaError(
            f"genesis.profile_releases must cover exactly {sorted(_PROFILES)}")
    for profile, binding in releases.items():
        binding = _closed(binding, frozenset(("path", "root")),
                          f"genesis.profile_releases[{profile!r}]")
        root(binding["root"], f"genesis.profile_releases[{profile!r}].root")
        expected_path = f"reference-releases/{binding['root']}.json"
        if _relative_path(
                binding["path"], f"genesis.profile_releases[{profile!r}].path",
                "reference-releases/") != expected_path:
            raise ReleaseSchemaError(
                f"genesis.profile_releases[{profile!r}].path must be {expected_path!r}")
    objects = _validate_objects(document["objects"])
    artifacts = _validate_artifacts(document["artifacts"])
    for field, object_name in (
            ("runtime_config_root", "runtime_config_root"),
            ("rig_contract_authority_root", "rig_contract_authority_root")):
        if document[field] != objects[object_name]["root"]:
            raise ReleaseSchemaError(f"{field} disagrees with objects.{object_name}.root")
    for field in ("benchmark_law_root", "canonical_suite_root", "evaluation_law_root"):
        if law[field] != objects[field]["root"]:
            raise ReleaseSchemaError(f"law.{field} disagrees with objects.{field}.root")
    expected = _json_root(document, "release_root")
    if root(document["release_root"], "release_root") != expected:
        raise ReleaseSchemaError(
            f"release_root does not reproduce from the canonical release body ({expected})")
    document["objects"] = objects
    document["artifacts"] = artifacts
    return RuntimeRelease(document)


def validate_public_genesis(value: Any, release: RuntimeRelease) -> Dict[str, Any]:
    block = dict(_closed(value, _PUBLIC_GENESIS_FIELDS, "public_genesis"))
    if type(block["sequence"]) is not int or block["sequence"] != 1 \
            or block["predecessor"] is not None:
        raise ReleaseSchemaError("public_genesis requires sequence=1 and predecessor=null")
    if root(block["release_root"], "public_genesis.release_root") != release.release_root:
        raise ReleaseSchemaError("public_genesis.release_root does not name RELEASE.json")
    if root(block["genesis_frontier_root"], "public_genesis.genesis_frontier_root") \
            != release.genesis_frontier_root:
        raise ReleaseSchemaError(
            "public_genesis.genesis_frontier_root does not name RELEASE.json genesis")
    return block


def parse_integration(value: Any, release: RuntimeRelease) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseSchemaError("runtime integration must be an object")
    required = frozenset((
        "artifacts", "code_roots", "compatibility_lock", "evaluation_law", "format", "genesis",
        "integration_root", "law", "objects", "product_version", "public_genesis", "release_root",
        "rig_contract_authority_root", "runtime_config"))
    document = dict(_closed(value, required, "runtime integration"))
    if document["format"] != INTEGRATION_FORMAT or document["product_version"] != PRODUCT_VERSION:
        raise ReleaseSchemaError("runtime integration is not the 1.0.0 public format")
    if document["release_root"] != release.release_root:
        raise ReleaseSchemaError("runtime integration and RELEASE.json name different releases")
    validate_public_genesis(document["public_genesis"], release)
    if document["law"] != release.raw["law"] or document["genesis"] != release.raw["genesis"]:
        raise ReleaseSchemaError("runtime integration restates different law or genesis values")
    if document["artifacts"] != release.raw["artifacts"] \
            or document["objects"] != release.raw["objects"]:
        raise ReleaseSchemaError("runtime integration restates a different object graph")
    if document["rig_contract_authority_root"] != release.raw["rig_contract_authority_root"]:
        raise ReleaseSchemaError("runtime integration names another contract authority")
    lock = _closed(document["compatibility_lock"], frozenset(("core_version_hash", "lock_root")),
                   "runtime integration compatibility_lock")
    if lock["lock_root"] != release.raw["compatibility_lock_root"] \
            or lock["core_version_hash"] != "0x" + lock["lock_root"]:
        raise ReleaseSchemaError("runtime integration compatibility lock does not bind release")
    if _json_root(document, "integration_root") != root(
            document["integration_root"], "integration_root"):
        raise ReleaseSchemaError("integration_root does not reproduce from its canonical body")
    return document
