#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Resolve the exact parent release that Benchmark-v2 must execute.

The coordinator's job objects are only transport.  This module derives one descriptor from
content-addressed composition, release, and module bytes; both the worker and public replay use
the same closed validation without trusting object labels or a claimed incumbent identity.
"""
from __future__ import annotations

from collections import abc
import hashlib
import os
import sys
from typing import Any, Callable, Dict, Mapping, Optional

class ParentExecutionError(ValueError):
    """The parent release graph is present but cannot identify one exact executable."""


GENESIS_REFERENCE_RELEASE_FORMAT = "coretex.genesis-reference-release/v1"
GENESIS_COMPOSITION_FORMAT = "coretex.genesis-composition/v1"
CONTENT_ADDRESSED_COMPOSITION_FORMAT = "coretex-memory/deployment-content-addressed/v2"
CONTENT_ADDRESSED_COMPOSITION_FIELDS = frozenset({
    "format", "content_authority", "composition", "bundles",
    "delegation_candidate_hashes", "profile_bindings", "manifest_self_sha256",
})


def _sealed_genesis_reference_roots() -> Dict[str, str]:
    """Read initial roots from the suite floor authority; there is no second root registry."""
    from . import canonical_suite

    source = canonical_suite.genesis_floor_authority().get("source")
    profiles = source.get("profiles") if isinstance(source, Mapping) else None
    if not isinstance(profiles, Mapping):  # pragma: no cover - image invariant
        raise RuntimeError("the sealed suite has no genesis reference profile authority")
    roots = {profile_id: row.get("release_root")
             for profile_id, row in profiles.items() if isinstance(row, Mapping)}
    if set(roots) != set(canonical_suite.PROTECTED_QUALITY_VOCABULARY):
        raise RuntimeError("the sealed suite genesis reference roots are incomplete")
    for profile_id, root in roots.items():
        if not (isinstance(root, str) and len(root) == 64
                and all(char in "0123456789abcdef" for char in root)):
            raise RuntimeError(
                f"suite genesis reference for {profile_id!r} is not a sha256 root")
    return roots


PRODUCTION_REFERENCE_RELEASE_ROOTS = _sealed_genesis_reference_roots()


def _root_of_manifest(value: Mapping[str, Any], *, where: str,
                      pub_module: Any) -> str:
    try:
        return pub_module.root_of(
            pub_module.encode(dict(value), pub_module.HASH_RULE_MANIFEST_BODY),
            pub_module.HASH_RULE_MANIFEST_BODY)
    except Exception as exc:
        raise ParentExecutionError(f"{where} is not a canonical manifest body: {exc}") \
            from exc


def _root_of_frontier_document(value: Mapping[str, Any], *, where: str,
                               fr_module: Any, self_field: Optional[str] = None) -> str:
    """Hash one closed genesis document by the release builder's canonical rule."""
    try:
        body = dict(value)
        if self_field is not None:
            body.pop(self_field, None)
        return fr_module.sha256_hex(fr_module.canonical_bytes(body))
    except Exception as exc:
        raise ParentExecutionError(
            f"{where} is not canonical frontier JSON: {exc}") from exc


def _require_root(value: Any, *, where: str) -> str:
    if not (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value)):
        raise ParentExecutionError(f"{where} must be a 32-byte hex root")
    return value


def _validate_runtime_release(release_manifest: Mapping[str, Any], module_bytes: bytes,
                              release_root: str) -> None:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    runtime_tree = os.path.join(repo_root, "coretex-memory")
    if runtime_tree not in sys.path:
        sys.path.insert(0, runtime_tree)
    try:
        from coretex_memory import release as runtime_release  # noqa: WPS433

        runtime_release.load_content_addressed_release(
            dict(release_manifest), expected_manifest_root=release_root, runtime_checks=True)
        runtime_release.recompute_admission(module_bytes, dict(release_manifest))
    except Exception as exc:
        raise ParentExecutionError(
            "non-initial parent release fails the shipped release compatibility/admission law: "
            f"{type(exc).__name__}: {exc}") from exc


def _validate_composition_graph(parent_composition: Mapping[str, Any],
                                parent_manifest: Mapping[str, Any], *, fr_module: Any) -> None:
    """Close every declared composition slot over its frontier/delegation identities."""
    if set(parent_composition) != CONTENT_ADDRESSED_COMPOSITION_FIELDS:
        raise ParentExecutionError(
            "parent composition does not have the closed current composition schema")
    bindings = parent_composition.get("profile_bindings")
    delegation = parent_composition.get("delegation_candidate_hashes")
    bundles = parent_composition.get("bundles")
    composition = parent_composition.get("composition")
    if not all(isinstance(value, abc.Mapping)
               for value in (bindings, delegation, bundles, composition)):
        raise ParentExecutionError("parent composition lacks a required profile map")
    full_sets = (set(bindings), set(bundles), set(composition))
    if len({frozenset(value) for value in full_sets}) != 1:
        raise ParentExecutionError(
            "parent composition profile_bindings, bundles, and composition maps disagree")
    declared = full_sets[0]
    profiles = parent_manifest.get("profiles")
    if not isinstance(profiles, abc.Mapping):
        raise ParentExecutionError("parent frontier profiles must be an object")
    if declared != set(profiles):
        raise ParentExecutionError(
            "parent composition must declare exactly the public frontier profiles")
    if not set(delegation) <= declared:
        raise ParentExecutionError("parent composition delegation names an undeclared profile")

    for profile_id in sorted(declared):
        binding = bindings.get(profile_id)
        if not isinstance(binding, abc.Mapping):
            raise ParentExecutionError(
                f"parent composition binding for {profile_id!r} must be an object")
        if binding.get("is_baseline") is True:
            forbidden = (
                "release_id", "bundle_manifest_sha256", "candidate_hash", "module_sha256",
                "miner_sha256", "bundle_dir", "miner_id")
            if any(binding.get(field) is not None for field in forbidden) \
                    or bundles.get(profile_id) is not None \
                    or composition.get(profile_id) is not None \
                    or delegation.get(profile_id) is not None:
                raise ParentExecutionError(
                    f"baseline composition slot {profile_id!r} installs release bytes")
            continue
        candidate_hash = _require_root(
            delegation.get(profile_id),
            where=f"parent delegation_candidate_hashes[{profile_id!r}]")
        if binding.get("candidate_hash") != candidate_hash \
                or binding.get("bundle_dir") in (None, "") \
                or binding.get("bundle_dir") != bundles.get(profile_id) \
                or binding.get("miner_id") in (None, "") \
                or binding.get("miner_id") != composition.get(profile_id):
            raise ParentExecutionError(
                f"parent composition delegation/bundle/miner binding for {profile_id!r} "
                "is internally inconsistent")
        release_id = _require_root(
            binding.get("release_id"),
            where=f"parent profile_bindings[{profile_id!r}].release_id")
        if binding.get("bundle_manifest_sha256") != release_id:
            raise ParentExecutionError(
                f"parent composition release roots disagree for {profile_id!r}")
        if profile_id in profiles and profiles[profile_id] != release_id:
            raise ParentExecutionError(
                f"parent composition release for {profile_id!r} disagrees with the frontier")
        _require_root(
            binding.get("module_sha256"),
            where=f"parent profile_bindings[{profile_id!r}].module_sha256")
        _require_root(
            binding.get("miner_sha256"),
            where=f"parent profile_bindings[{profile_id!r}].miner_sha256")


def _validate_genesis_composition(parent_composition: Mapping[str, Any],
                                  parent_manifest: Mapping[str, Any], *,
                                  fr_module: Any) -> None:
    """Validate the public genesis composition without inventing private G6 bindings."""
    expected_fields = {"format", "profiles", "composition_root"}
    if set(parent_composition) != expected_fields:
        raise ParentExecutionError(
            "genesis composition must contain exactly format, profiles, and composition_root")
    if parent_composition.get("format") != GENESIS_COMPOSITION_FORMAT:
        raise ParentExecutionError("genesis composition format is unsupported")
    claimed_root = _require_root(
        parent_composition.get("composition_root"), where="genesis composition_root")
    derived_root = _root_of_frontier_document(
        parent_composition, where="genesis composition", fr_module=fr_module,
        self_field="composition_root")
    if claimed_root != derived_root:
        raise ParentExecutionError(
            f"genesis composition hashes to {derived_root}, not claimed {claimed_root}")
    if parent_manifest.get("default_composition_root") != derived_root:
        raise ParentExecutionError(
            "genesis composition does not equal the frontier default_composition_root")
    profiles = parent_composition.get("profiles")
    frontier_profiles = parent_manifest.get("profiles")
    if not isinstance(profiles, abc.Mapping) or not isinstance(frontier_profiles, abc.Mapping) \
            or set(profiles) != set(frontier_profiles):
        raise ParentExecutionError(
            "genesis composition profiles must exactly equal the frontier profiles")
    for profile_id, entry in profiles.items():
        if not isinstance(entry, abc.Mapping) or set(entry) != {"exec", "release_root"} \
                or entry.get("exec") != "reference" \
                or entry.get("release_root") != frontier_profiles.get(profile_id):
            raise ParentExecutionError(
                f"genesis composition entry {profile_id!r} is not the frontier-bound "
                "reference release")


def _validate_reference_slot_in_modern_composition(
        parent_composition: Mapping[str, Any], parent_manifest: Mapping[str, Any], *,
        target_profile: str, fr_module: Any) -> None:
    """Validate a still-reference slot after another profile has publicly advanced."""
    _validate_composition_graph(parent_composition, parent_manifest, fr_module=fr_module)
    binding = parent_composition["profile_bindings"].get(target_profile)
    if not isinstance(binding, abc.Mapping) or binding.get("is_baseline") is not True:
        raise ParentExecutionError(
            f"reference parent slot {target_profile!r} is not routed to builtin reference "
            "execution by the content-addressed composition")
    for field in ("bundles", "composition"):
        if parent_composition[field].get(target_profile) is not None:
            raise ParentExecutionError(
                f"reference parent slot {target_profile!r} unexpectedly installs {field}")
    if parent_composition["delegation_candidate_hashes"].get(target_profile) is not None:
        raise ParentExecutionError(
            f"reference parent slot {target_profile!r} unexpectedly carries a delegation hash")


def _resolve_genesis_reference_execution(*, parent_manifest: Mapping[str, Any],
                                         target_profile: str,
                                         parent_composition: Mapping[str, Any],
                                         descriptor: Mapping[str, Any],
                                         release_root: str,
                                         fr_module: Any, pub_module: Any) -> Dict[str, Any]:
    expected_fields = {"format", "profile_id", "exec", "reference_runtime", "abi"}
    if set(descriptor) != expected_fields \
            or descriptor.get("format") != GENESIS_REFERENCE_RELEASE_FORMAT \
            or descriptor.get("profile_id") != target_profile \
            or descriptor.get("exec") != "reference":
        raise ParentExecutionError(
            "genesis reference release has an unknown schema, profile, or execution kind")
    runtime = descriptor.get("reference_runtime")
    if not isinstance(runtime, abc.Mapping) or set(runtime) != {"id", "protocol"} \
            or runtime.get("id") != "reference-runtime" \
            or runtime.get("protocol") != "rrm1":
        raise ParentExecutionError(
            "genesis reference release does not bind the builtin reference runtime")
    abi = descriptor.get("abi")
    if not isinstance(abi, abc.Mapping) or set(abi) != {
            "id", "module_version", "policy_version", "hooks", "capabilities"} \
            or abi.get("id") != "coretex-memory/miner-module/v1" \
            or not isinstance(abi.get("module_version"), int) \
            or isinstance(abi.get("module_version"), bool) \
            or not isinstance(abi.get("policy_version"), int) \
            or isinstance(abi.get("policy_version"), bool) \
            or not isinstance(abi.get("hooks"), list) \
            or not all(isinstance(value, str) for value in abi.get("hooks", ())) \
            or not isinstance(abi.get("capabilities"), list) \
            or not all(isinstance(value, str) for value in abi.get("capabilities", ())):
        raise ParentExecutionError("genesis reference release ABI descriptor is malformed")
    derived_release = _root_of_frontier_document(
        descriptor, where="genesis reference release", fr_module=fr_module)
    if derived_release != release_root:
        raise ParentExecutionError(
            f"genesis reference release hashes to {derived_release}, not frontier-bound "
            f"{release_root}")

    composition_format = parent_composition.get("format")
    if composition_format == GENESIS_COMPOSITION_FORMAT:
        _validate_genesis_composition(parent_composition, parent_manifest, fr_module=fr_module)
    elif composition_format == CONTENT_ADDRESSED_COMPOSITION_FORMAT:
        composition_root = _require_root(
            parent_manifest.get("default_composition_root"),
            where="parent default_composition_root")
        derived_composition = _root_of_manifest(
            parent_composition, where="parent composition manifest", pub_module=pub_module)
        if derived_composition != composition_root \
                or parent_composition.get("manifest_self_sha256") != composition_root \
                or parent_composition.get("content_authority") != "ONCHAIN_COMMITTED_ROOT":
            raise ParentExecutionError(
                "content-addressed reference composition does not equal the frontier-bound root "
                "or carries ambiguous authority")
        _validate_reference_slot_in_modern_composition(
            parent_composition, parent_manifest, target_profile=target_profile,
            fr_module=fr_module)
    else:
        raise ParentExecutionError(
            f"reference release cannot be served by composition format {composition_format!r}")

    return {
        "exec": "reference",
        "id": "reference-runtime",
        "candidate_hash": None,
        "release_root": release_root,
        "release_manifest": dict(descriptor),
    }


def resolve_parent_execution(*, parent_manifest: Mapping[str, Any], target_profile: str,
                             parent_composition: Mapping[str, Any],
                             parent_release_manifest: Mapping[str, Any],
                             parent_module_bytes: Optional[bytes],
                             fr_module: Any, pub_module: Any,
                             reference_release_roots: Optional[Mapping[str, str]] = None,
                             validate_runtime: bool = True,
                             runtime_validator: Optional[
                                 Callable[[Mapping[str, Any]], None]] = None) -> Dict[str, Any]:
    """Validate and return the executable descriptor for ``target_profile``'s parent slot."""
    reference_roots = (PRODUCTION_REFERENCE_RELEASE_ROOTS if reference_release_roots is None
                       else dict(reference_release_roots))
    if not isinstance(parent_manifest, abc.Mapping):
        raise ParentExecutionError("parent frontier manifest must be an object")
    if not isinstance(target_profile, str) or not target_profile:
        raise ParentExecutionError("target profile must be a non-empty string")
    profiles = parent_manifest.get("profiles")
    if not isinstance(profiles, abc.Mapping) or target_profile not in profiles:
        raise ParentExecutionError(
            f"parent frontier carries no release for target profile {target_profile!r}")
    release_root = _require_root(
        profiles[target_profile], where=f"parent profiles[{target_profile!r}]")
    composition_root = _require_root(
        parent_manifest.get("default_composition_root"),
        where="parent default_composition_root")
    is_reference = reference_roots.get(target_profile) == release_root

    if not isinstance(parent_release_manifest, abc.Mapping):
        raise ParentExecutionError("parent release manifest must be an object")
    if parent_release_manifest.get("format") == GENESIS_REFERENCE_RELEASE_FORMAT:
        if not is_reference:
            raise ParentExecutionError(
                "a genesis reference descriptor is permitted only at the profile's sealed "
                "genesis release root")
        if parent_module_bytes is not None:
            raise ParentExecutionError(
                "genesis reference execution is builtin and must not carry private module bytes")
        return _resolve_genesis_reference_execution(
            parent_manifest=parent_manifest, target_profile=target_profile,
            parent_composition=parent_composition, descriptor=parent_release_manifest,
            release_root=release_root, fr_module=fr_module, pub_module=pub_module)

    if not isinstance(parent_composition, abc.Mapping):
        raise ParentExecutionError("parent composition manifest must be an object")
    derived_composition = _root_of_manifest(
        parent_composition, where="parent composition manifest", pub_module=pub_module)
    if derived_composition != composition_root:
        raise ParentExecutionError(
            f"parent composition hashes to {derived_composition}, not frontier-bound "
            f"{composition_root}")
    if parent_composition.get("manifest_self_sha256") != composition_root:
        raise ParentExecutionError(
            "parent composition manifest_self_sha256 does not equal its canonical root")
    composition_format = parent_composition.get("format")
    modern_composition = composition_format == CONTENT_ADDRESSED_COMPOSITION_FORMAT
    if not modern_composition:
        raise ParentExecutionError(
            f"unsupported parent composition format {composition_format!r}")
    if parent_composition.get("content_authority") != "ONCHAIN_COMMITTED_ROOT":
        raise ParentExecutionError(
            "content-addressed parent composition has ambiguous or missing chain authority")
    _validate_composition_graph(parent_composition, parent_manifest, fr_module=fr_module)

    derived_release = _root_of_manifest(
        parent_release_manifest, where="parent release manifest", pub_module=pub_module)
    if derived_release != release_root:
        raise ParentExecutionError(
            f"parent release hashes to {derived_release}, not frontier-bound {release_root}")
    if parent_release_manifest.get("manifest_self_sha256") != release_root:
        raise ParentExecutionError(
            "parent release manifest_self_sha256 does not equal its canonical root")

    if not isinstance(parent_module_bytes, (bytes, bytearray)):
        raise ParentExecutionError("parent module must be raw bytes")
    module_bytes = bytes(parent_module_bytes)
    if not module_bytes:
        raise ParentExecutionError("parent module is empty")
    module_sha256 = hashlib.sha256(module_bytes).hexdigest()
    expected_module = _require_root(
        parent_release_manifest.get("module_sha256"), where="parent release module_sha256")
    if module_sha256 != expected_module:
        raise ParentExecutionError(
            f"parent module bytes hash to {module_sha256}, not release-bound {expected_module}")
    try:
        module_source = module_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParentExecutionError("parent module is not UTF-8 Python source") from exc

    bindings = parent_composition["profile_bindings"]
    delegation = parent_composition["delegation_candidate_hashes"]
    bundles = parent_composition["bundles"]
    composition = parent_composition["composition"]
    binding = bindings.get(target_profile)
    if not isinstance(binding, abc.Mapping):
        raise ParentExecutionError(
            f"parent composition carries no binding for {target_profile!r}")
    candidate_hash = _require_root(
        delegation.get(target_profile),
        where=f"parent delegation_candidate_hashes[{target_profile!r}]")
    expected_binding = {
        "release_id": release_root,
        "bundle_manifest_sha256": release_root,
        "candidate_hash": candidate_hash,
        "module_sha256": module_sha256,
        "bundle_dir": bundles.get(target_profile),
        "miner_id": composition.get(target_profile),
    }
    for field, expected in expected_binding.items():
        if expected in (None, "") or binding.get(field) != expected:
            raise ParentExecutionError(
                f"parent composition binding {field} for {target_profile!r} does not equal "
                f"the release/delegation it serves")
    provenance = parent_release_manifest.get("source_provenance")
    if not isinstance(provenance, abc.Mapping) \
            or provenance.get("profile_id") != target_profile:
        raise ParentExecutionError(
            f"parent release provenance does not bind profile {target_profile!r}")
    if provenance.get("miner") not in (None, binding.get("miner_id")):
        raise ParentExecutionError(
            "parent release miner provenance disagrees with the composition binding")

    if is_reference:
        raise ParentExecutionError(
            "the sealed genesis release root must be served by its public genesis-reference "
            "descriptor, never by a private wrapper manifest/module pair")
    if binding.get("miner_sha256") != module_sha256:
        raise ParentExecutionError(
            "post-genesis parent composition miner_sha256 does not equal its direct module")
    exec_kind = "candidate_module"
    incumbent_id = release_root
    execution_candidate_hash = candidate_hash
    execution = {
        "exec": exec_kind,
        "id": incumbent_id,
        "candidate_hash": execution_candidate_hash,
        "release_root": release_root,
        "release_manifest": dict(parent_release_manifest),
        "module": {"source": module_source, "sha256": module_sha256},
    }
    if validate_runtime:
        if runtime_validator is None:
            _validate_runtime_release(parent_release_manifest, module_bytes, release_root)
        else:
            runtime_validator(execution)
    return execution


def compact_identity(execution: Mapping[str, Any]) -> Dict[str, Any]:
    """Project a verified parent into its closed public execution identity."""
    if not isinstance(execution, abc.Mapping):
        raise ParentExecutionError("parent execution must be an object")
    release_root = _require_root(execution.get("release_root"), where="release_root")
    if execution.get("exec") == "reference":
        descriptor = execution.get("release_manifest")
        runtime = descriptor.get("reference_runtime") if isinstance(descriptor, abc.Mapping) \
            else None
        if execution.get("id") != "reference-runtime" \
                or execution.get("candidate_hash") is not None \
                or not isinstance(runtime, abc.Mapping) \
                or runtime != {"id": "reference-runtime", "protocol": "rrm1"}:
            raise ParentExecutionError("reference parent lacks its exact builtin runtime identity")
        return {
            "exec": "reference",
            "id": "reference-runtime",
            "candidate_hash": None,
            "release_root": release_root,
            "protocol": "rrm1",
        }
    if execution.get("exec") != "candidate_module":
        raise ParentExecutionError(
            f"unsupported parent execution {execution.get('exec')!r}")
    module = execution.get("module")
    if not isinstance(module, abc.Mapping):
        raise ParentExecutionError("parent execution carries no verified module")
    return {
        "exec": execution.get("exec"),
        "id": execution.get("id"),
        "candidate_hash": execution.get("candidate_hash"),
        "release_root": release_root,
        "module_sha256": _require_root(module.get("sha256"), where="module.sha256"),
    }


def fetch_parent_execution(*, store: Any, parent_manifest: Mapping[str, Any],
                           target_profile: str,
                           fr_module: Any, pub_module: Any,
                           reference_release_roots: Optional[Mapping[str, str]] = None,
                           validate_runtime: bool = True,
                           runtime_validator: Optional[
                               Callable[[Mapping[str, Any]], None]] = None) -> Dict[str, Any]:
    """Independently fetch, re-hash, and resolve the parent execution from a public CAS."""
    profiles = parent_manifest.get("profiles") if isinstance(parent_manifest, abc.Mapping) else None
    if not isinstance(profiles, abc.Mapping) or target_profile not in profiles:
        raise ParentExecutionError(
            f"parent frontier carries no release for target profile {target_profile!r}")
    release_root = _require_root(
        profiles[target_profile], where=f"parent profiles[{target_profile!r}]")
    composition_root = _require_root(
        parent_manifest.get("default_composition_root"),
        where="parent default_composition_root")
    def raw_json(root: str, where: str) -> Mapping[str, Any]:
        try:
            raw = store.get(root)
            value = fr_module.parse_json(raw.decode("utf-8"))
        except Exception as exc:
            raise ParentExecutionError(f"cannot fetch/parse {where} {root}: {exc}") from exc
        if not isinstance(value, abc.Mapping):
            raise ParentExecutionError(f"{where} is not an object")
        return value

    composition_probe = raw_json(composition_root, "parent composition")
    if composition_probe.get("format") == GENESIS_COMPOSITION_FORMAT:
        derived = _root_of_frontier_document(
            composition_probe, where="genesis composition", fr_module=fr_module,
            self_field="composition_root")
        if composition_probe.get("composition_root") != derived or derived != composition_root:
            raise ParentExecutionError(
                "genesis composition does not rehash to the frontier-bound root")
        composition = composition_probe
    else:
        composition = pub_module.fetch_json(
            composition_root, hash_rule=pub_module.HASH_RULE_MANIFEST_BODY, store=store)

    release_probe = raw_json(release_root, "parent release")
    if release_probe.get("format") == GENESIS_REFERENCE_RELEASE_FORMAT:
        derived = _root_of_frontier_document(
            release_probe, where="genesis reference release", fr_module=fr_module)
        if derived != release_root:
            raise ParentExecutionError(
                "genesis reference descriptor does not rehash to the frontier-bound root")
        release_manifest = release_probe
    else:
        release_manifest = pub_module.fetch_json(
            release_root, hash_rule=pub_module.HASH_RULE_MANIFEST_BODY, store=store)
    if not isinstance(release_manifest, abc.Mapping):
        raise ParentExecutionError("parent release manifest is not an object")
    module_bytes = None
    if release_manifest.get("format") != GENESIS_REFERENCE_RELEASE_FORMAT:
        module_root = _require_root(
            release_manifest.get("module_sha256"), where="parent release module_sha256")
        module_bytes = pub_module.read_back(
            module_root, hash_rule=pub_module.HASH_RULE_BYTES, store=store)
    return resolve_parent_execution(
        parent_manifest=parent_manifest, target_profile=target_profile,
        parent_composition=composition, parent_release_manifest=release_manifest,
        parent_module_bytes=module_bytes, fr_module=fr_module, pub_module=pub_module,
        reference_release_roots=reference_release_roots,
        validate_runtime=validate_runtime, runtime_validator=runtime_validator)
