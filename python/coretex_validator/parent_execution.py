# SPDX-License-Identifier: Apache-2.0
"""Resolve the exact parent release from public content-addressed bytes.

The coordinator's worker package is transport, never replay authority. This zero-dependency
public implementation derives the incumbent from the confirmed parent frontier, composition,
release manifest and module bytes. Runtime execution remains in :mod:`replay`'s pinned
networkless child; this module authenticates the graph and the exact bytes sent to that child.
"""
from __future__ import annotations

from collections import abc
import hashlib
import json
import os
from typing import Any, Dict, Mapping

from . import frontier as fr
from . import publication as pub
from . import release_graph as rg


class ParentExecutionError(ValueError):
    """The parent release graph cannot identify one exact executable."""


_AUTHORITY_FORMAT = "benchmark-v2/exact-parent-authority/v1"
_AUTHORITY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "EXACT-PARENT-AUTHORITY.production.json",
)


def _root(value: Any, where: str) -> str:
    try:
        return fr.check_root(value, where)
    except fr.FrontierError as exc:
        raise ParentExecutionError(str(exc)) from exc


def _load_authority() -> Dict[str, Any]:
    try:
        with open(_AUTHORITY_PATH, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:  # pragma: no cover - wheel invariant
        raise RuntimeError(f"cannot load exact-parent authority: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {
            "format", "pre_exact_parent_code_root_sets",
            "production_reference_release_roots"}:
        raise RuntimeError("exact-parent authority has an unknown or open schema")
    if document.get("format") != _AUTHORITY_FORMAT:
        raise RuntimeError("exact-parent authority format is unsupported")
    reference = document.get("production_reference_release_roots")
    if not isinstance(reference, dict) or set(reference) != set(fr.PROFILE_IDS):
        raise RuntimeError("exact-parent authority does not cover exactly the live profiles")
    for profile_id, release_root in reference.items():
        if not isinstance(profile_id, str):
            raise RuntimeError("exact-parent authority carries a non-string profile id")
        try:
            fr.check_root(release_root, f"reference release {profile_id}")
        except fr.FrontierError as exc:
            raise RuntimeError(str(exc)) from exc
    old_sets = document.get("pre_exact_parent_code_root_sets")
    if not isinstance(old_sets, list) or not old_sets:
        raise RuntimeError("exact-parent authority has no pre-cut code-root set")
    for entry in old_sets:
        code_roots = entry.get("code_roots") if isinstance(entry, dict) else None
        if set(entry or {}) != {"code_roots", "id"} \
                or not isinstance(entry.get("id"), str) or not entry["id"] \
                or not isinstance(code_roots, dict) or not code_roots:
            raise RuntimeError("exact-parent authority has a malformed pre-cut entry")
        for name, digest in code_roots.items():
            if not isinstance(name, str) or not name:
                raise RuntimeError("exact-parent authority has an invalid code-root name")
            try:
                fr.check_root(digest, f"pre-cut code root {name}")
            except fr.FrontierError as exc:
                raise RuntimeError(str(exc)) from exc
    return document


EXACT_PARENT_AUTHORITY = _load_authority()
PRODUCTION_REFERENCE_RELEASE_ROOTS = dict(
    EXACT_PARENT_AUTHORITY["production_reference_release_roots"])
PRE_EXACT_PARENT_CODE_ROOT_SETS = tuple(
    dict(entry["code_roots"])
    for entry in EXACT_PARENT_AUTHORITY["pre_exact_parent_code_root_sets"])


def is_pre_exact_parent_code_roots(value: Any) -> bool:
    """Whether addressed report bytes bind one exact frozen pre-cut law tree."""
    return isinstance(value, abc.Mapping) and any(
        dict(value) == frozen for frozen in PRE_EXACT_PARENT_CODE_ROOT_SETS)


def _signed_manifest_root(value: Mapping[str, Any], where: str) -> str:
    try:
        encoded = pub.encode(dict(value), pub.HASH_RULE_SIGNED_MANIFEST_BODY)
        return pub.root_of(encoded, pub.HASH_RULE_SIGNED_MANIFEST_BODY)
    except pub.PublicationError as exc:
        raise ParentExecutionError(
            f"{where} is not a canonical signed-manifest body: {exc}") from exc


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, abc.Mapping):
        raise ParentExecutionError(f"{where} must be an object")
    return value


def _validate_composition_graph(parent_composition: Mapping[str, Any],
                                parent_manifest: Mapping[str, Any]) -> None:
    bindings = _mapping(parent_composition.get("profile_bindings"),
                        "parent composition profile_bindings")
    delegation = _mapping(parent_composition.get("delegation_candidate_hashes"),
                          "parent composition delegation_candidate_hashes")
    bundles = _mapping(parent_composition.get("bundles"), "parent composition bundles")
    composition = _mapping(parent_composition.get("composition"),
                           "parent composition composition")
    if not (set(bindings) == set(bundles) == set(composition)):
        raise ParentExecutionError("parent composition profile maps disagree")
    declared = set(bindings)
    profiles = _mapping(parent_manifest.get("profiles"), "parent frontier profiles")
    if not declared <= set(profiles) | {fr.LEGACY_PROFILE_ID}:
        raise ParentExecutionError("parent composition declares a profile outside the frontier")
    if not set(delegation) <= declared:
        raise ParentExecutionError("parent composition delegation names an undeclared profile")
    for profile_id in sorted(declared):
        binding = _mapping(bindings[profile_id], f"parent binding {profile_id}")
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
        candidate_hash = _root(
            delegation.get(profile_id), f"delegation_candidate_hashes[{profile_id!r}]")
        if binding.get("candidate_hash") != candidate_hash \
                or not binding.get("bundle_dir") \
                or binding.get("bundle_dir") != bundles.get(profile_id) \
                or not binding.get("miner_id") \
                or binding.get("miner_id") != composition.get(profile_id):
            raise ParentExecutionError(
                f"parent composition delegation/bundle/miner binding for {profile_id!r} "
                "is internally inconsistent")
        release_root = _root(binding.get("release_id"), f"binding[{profile_id}].release_id")
        if binding.get("bundle_manifest_sha256") != release_root:
            raise ParentExecutionError(
                f"parent composition release roots disagree for {profile_id!r}")
        if profile_id in profiles and profiles[profile_id] != release_root:
            raise ParentExecutionError(
                f"parent composition release for {profile_id!r} disagrees with the frontier")
        _root(binding.get("module_sha256"), f"binding[{profile_id}].module_sha256")
        _root(binding.get("miner_sha256"), f"binding[{profile_id}].miner_sha256")


def resolve_parent_execution(*, parent_manifest: Mapping[str, Any], target_profile: str,
                             parent_composition: Mapping[str, Any],
                             parent_release_manifest: Mapping[str, Any],
                             parent_module_bytes: bytes) -> Dict[str, Any]:
    """Validate and return the executable descriptor for the parent's target slot."""
    parent_manifest = _mapping(parent_manifest, "parent frontier manifest")
    if target_profile not in fr.PROFILE_IDS:
        raise ParentExecutionError(f"unsupported target profile {target_profile!r}")
    profiles = _mapping(parent_manifest.get("profiles"), "parent frontier profiles")
    release_root = _root(profiles.get(target_profile), f"profiles[{target_profile!r}]")
    composition_root = _root(
        parent_manifest.get("default_composition_root"), "default_composition_root")
    is_reference = PRODUCTION_REFERENCE_RELEASE_ROOTS.get(target_profile) == release_root

    parent_composition = _mapping(parent_composition, "parent composition manifest")
    derived_composition = _signed_manifest_root(parent_composition, "parent composition")
    if derived_composition != composition_root \
            or parent_composition.get("manifest_self_sha256") != composition_root:
        raise ParentExecutionError(
            "parent composition bytes do not match the frontier-bound composition root")
    composition_format = parent_composition.get("format")
    modern = composition_format == rg.COMPOSITION_FORMAT
    initial = composition_format == "benchmark-v2/g8-deployment-signed/v1"
    if not (modern or initial):
        raise ParentExecutionError(
            f"unsupported parent composition format {composition_format!r}")
    if modern and (
            parent_composition.get("content_authority") != rg.CONTENT_AUTHORITY
            or any(field in parent_composition
                   for field in ("operator_key_id", "operator_signature"))):
        raise ParentExecutionError("parent composition has ambiguous content authority")
    if initial and not is_reference:
        raise ParentExecutionError(
            "a non-initial parent release cannot use the initial composition")
    _validate_composition_graph(parent_composition, parent_manifest)

    parent_release_manifest = _mapping(parent_release_manifest, "parent release manifest")
    derived_release = _signed_manifest_root(parent_release_manifest, "parent release")
    if derived_release != release_root \
            or parent_release_manifest.get("manifest_self_sha256") != release_root:
        raise ParentExecutionError(
            "parent release bytes do not match the frontier-bound release root")
    if not isinstance(parent_module_bytes, (bytes, bytearray)) or not parent_module_bytes:
        raise ParentExecutionError("parent module must be non-empty raw bytes")
    module_bytes = bytes(parent_module_bytes)
    module_sha256 = hashlib.sha256(module_bytes).hexdigest()
    expected_module = _root(
        parent_release_manifest.get("module_sha256"), "parent release module_sha256")
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
    binding = _mapping(bindings.get(target_profile), f"parent binding {target_profile}")
    candidate_hash = _root(
        delegation.get(target_profile), f"delegation_candidate_hashes[{target_profile!r}]")
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
                f"parent composition binding {field} does not match the target release")
    provenance = _mapping(
        parent_release_manifest.get("source_provenance"), "parent release provenance")
    if provenance.get("profile_id") != target_profile:
        raise ParentExecutionError("parent release provenance does not bind the target profile")
    if provenance.get("miner") not in (None, binding.get("miner_id")):
        raise ParentExecutionError(
            "parent release miner provenance disagrees with the composition")

    if is_reference:
        exec_kind = "reference"
        incumbent_id = "reference-runtime"
        execution_candidate_hash = None
    else:
        if binding.get("miner_sha256") != module_sha256:
            raise ParentExecutionError(
                "non-initial parent miner_sha256 does not equal its direct module")
        try:
            rg.validate_schema4_release(
                parent_release_manifest, expected_root=release_root,
                profile_id=target_profile)
        except rg.ReleaseGraphError as exc:
            raise ParentExecutionError(
                f"non-initial parent release fails the public schema-4 law: {exc}") from exc
        exec_kind = "candidate_module"
        incumbent_id = release_root
        execution_candidate_hash = candidate_hash

    return {
        "exec": exec_kind,
        "id": incumbent_id,
        "candidate_hash": execution_candidate_hash,
        "release_root": release_root,
        "release_manifest": dict(parent_release_manifest),
        "module": {"source": module_source, "sha256": module_sha256},
    }


def compact_identity(execution: Mapping[str, Any]) -> Dict[str, Any]:
    """Project a byte-verified execution into the signed five-field identity."""
    execution = _mapping(execution, "parent execution")
    module = _mapping(execution.get("module"), "parent execution module")
    return {
        "candidate_hash": execution.get("candidate_hash"),
        "exec": execution.get("exec"),
        "id": execution.get("id"),
        "module_sha256": _root(module.get("sha256"), "module.sha256"),
        "release_root": _root(execution.get("release_root"), "release_root"),
    }


def fetch_parent_execution(*, store: pub.ContentStore,
                           parent_manifest: Mapping[str, Any],
                           target_profile: str) -> Dict[str, Any]:
    """Fetch, re-hash and resolve the exact parent execution from a public CAS."""
    profiles = _mapping(parent_manifest.get("profiles"), "parent frontier profiles")
    release_root = _root(profiles.get(target_profile), f"profiles[{target_profile!r}]")
    composition_root = _root(
        parent_manifest.get("default_composition_root"), "default_composition_root")
    composition = pub.fetch_json(
        composition_root, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    release_manifest = pub.fetch_json(
        release_root, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    module_root = _root(release_manifest.get("module_sha256"), "parent release module_sha256")
    module_bytes = pub.read_back(module_root, hash_rule=pub.HASH_RULE_BYTES, store=store)
    return resolve_parent_execution(
        parent_manifest=parent_manifest, target_profile=target_profile,
        parent_composition=composition, parent_release_manifest=release_manifest,
        parent_module_bytes=module_bytes)
