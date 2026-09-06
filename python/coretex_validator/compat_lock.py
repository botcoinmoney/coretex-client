# SPDX-License-Identifier: Apache-2.0
"""Closed verifier for the release's compatibility-lock serialization format."""
from __future__ import annotations

from typing import Any, Mapping

from . import frontier
from .keccak256 import keccak256

FORMAT = "coretex.compatibility-lock/v1"
DOMAIN = b"\x19coretex.compatibility-lock/v1\n"
ROOT_RULES = {
    "benchmark_law_root": "sha256-bytes",
    "counter_resource_law_root": "sha256-frontier-canonical-json",
    "counter_root": "sha256-benchmark-canonical-json",
    "evaluation_law_root": "sha256-benchmark-canonical-json",
    "evaluation_law_scorer_root": "sha256-benchmark-canonical-json",
    "miner_module_abi_root": "sha256-frontier-canonical-json",
    "renderer_root": "sha256-benchmark-canonical-json",
    "rig_contract_authority_root": "sha256-bytes",
    "runtime_artifact_root": "sha256-file-tree",
    "runtime_protocol_abi_root": "sha256-frontier-canonical-json",
    "runtime_wheel_root": "sha256-bytes",
    "wasmtime_aarch64_wheel_root": "sha256-bytes",
    "wasmtime_amd64_wheel_root": "sha256-bytes",
}
LITERALS = frozenset({
    "input_envelope_schema", "module_manifest_schema", "store_schema",
    "transition_descriptor_schema",
})
FIELDS = frozenset(ROOT_RULES) | LITERALS


class CompatibilityLockError(ValueError):
    """The supplied lock is not the sole closed current format."""


def _closed(value: Mapping[str, Any], expected, where: str) -> None:
    if set(value) != set(expected):
        raise CompatibilityLockError(
            f"{where} is not closed (missing={sorted(set(expected)-set(value))}, "
            f"unknown={sorted(set(value)-set(expected))})")


def verify_lock(document: Mapping[str, Any]) -> str:
    if not isinstance(document, Mapping):
        raise CompatibilityLockError("compatibility lock must be an object")
    _closed(document, {"format", "lock_root", "locks"}, "compatibility lock")
    if document["format"] != FORMAT:
        raise CompatibilityLockError(f"format must be {FORMAT!r}")
    locks = document["locks"]
    if not isinstance(locks, Mapping):
        raise CompatibilityLockError("locks must be an object")
    _closed(locks, FIELDS, "locks")
    for name, rule in ROOT_RULES.items():
        entry = locks[name]
        if not isinstance(entry, Mapping):
            raise CompatibilityLockError(f"locks.{name} must be an object")
        _closed(entry, {"hash_rule", "kind", "root"}, f"locks.{name}")
        try:
            frontier.check_root(entry["root"], f"locks.{name}.root")
        except frontier.FrontierError as exc:
            raise CompatibilityLockError(str(exc)) from exc
        if entry["kind"] != "root" or entry["hash_rule"] != rule \
                or entry["root"] == frontier.ZERO_ROOT:
            raise CompatibilityLockError(f"locks.{name} is not the declared nonzero {rule} root")
    for name in LITERALS:
        entry = locks[name]
        if not isinstance(entry, Mapping):
            raise CompatibilityLockError(f"locks.{name} must be an object")
        _closed(entry, {"kind", "schema", "version"}, f"locks.{name}")
        version = entry["version"]
        if entry["kind"] != "literal" or not isinstance(entry["schema"], str) \
                or not entry["schema"] or isinstance(version, bool) \
                or not isinstance(version, int) or not 0 <= version <= 2 ** 53 - 1:
            raise CompatibilityLockError(f"locks.{name} is not a portable literal schema")
    recorded = document["lock_root"]
    try:
        frontier.check_root(recorded, "lock_root")
        canonical = frontier.canonical_bytes(
            {key: value for key, value in document.items() if key != "lock_root"})
    except frontier.FrontierError as exc:
        raise CompatibilityLockError(str(exc)) from exc
    observed = keccak256(DOMAIN + canonical).hex()
    if recorded != observed:
        raise CompatibilityLockError(
            f"lock_root {recorded} does not recompute; body hashes to {observed}")
    return observed


__all__ = ["CompatibilityLockError", "verify_lock"]
