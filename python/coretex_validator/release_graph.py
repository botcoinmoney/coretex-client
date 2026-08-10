# SPDX-License-Identifier: Apache-2.0
"""Fail-closed verification of a prospective schema-v3 CoreTex release graph.

The frontier root is only the first content address.  A usable state also requires its
composition, all three profile release manifests, and every module byte string named by those
manifests.  This module follows that complete graph without importing the CoreTex runtime: the
public validator remains a zero-dependency package and treats runtime execution as a separate,
pinned replay stage.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from . import frontier as fr
from . import publication as pub


CONTENT_ADDRESSED_RELEASE_SCHEMA = 3
CONTENT_AUTHORITY = "ONCHAIN_COMMITTED_ROOT"
COMPOSITION_FORMAT = "coretex-memory/deployment-content-addressed/v2"
MAY_AFFECT_HOOKS: Tuple[str, ...] = (
    "m1_ingest_transform", "m2_organize", "m3_consolidate",
    "m4_candidates", "m5_rank", "m6_pack",
)
CAPABILITY_IDS: Tuple[str, ...] = ("cap.text.v1", "cap.lexicon.v1")
LEGACY_PROFILE_ID = "legacy.structured.v1"


class ReleaseGraphError(ValueError):
    """A fetched prospective release graph is incomplete or internally inconsistent."""


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseGraphError(f"{where} must be an object")
    return value


def _root(value: Any, where: str) -> str:
    try:
        return fr.check_root(value, where)
    except fr.FrontierError as exc:
        raise ReleaseGraphError(str(exc)) from exc


def bundle_file_bindings(manifest: Mapping[str, Any]) -> Dict[str, str]:
    """Return every file root a schema-v3 release manifest binds."""
    files = {"module.py": _root(manifest.get("module_sha256"), "module_sha256")}
    provenance = _mapping(manifest.get("source_provenance"), "source_provenance")
    base_modules = _mapping(provenance.get("base_modules"),
                            "source_provenance.base_modules")
    if "miner_module.py" not in base_modules:
        raise ReleaseGraphError(
            "source_provenance.base_modules must bind miner_module.py; the evaluated module "
            "cannot be reconstructed otherwise")
    for name, digest in base_modules.items():
        if not isinstance(name, str) or not name or name.startswith(("/", "\\")):
            raise ReleaseGraphError(f"base module path {name!r} is not a safe relative path")
        parts = name.replace("\\", "/").split("/")
        if any(part in ("", ".", "..") for part in parts) or ":" in name:
            raise ReleaseGraphError(f"base module path {name!r} traverses its release bundle")
        if name in ("manifest.json", "module.py"):
            raise ReleaseGraphError(f"base module {name!r} collides with a reserved bundle file")
        files[name] = _root(digest, f"base_modules[{name!r}]")
    return files


def validate_schema3_release(manifest: Any, *, expected_root: str,
                             profile_id: str) -> Dict[str, Any]:
    """Validate the prospective content-authority and conservative M1--M6 declaration."""
    document = dict(_mapping(manifest, f"release[{profile_id}]"))
    if document.get("manifest_schema_version") != CONTENT_ADDRESSED_RELEASE_SCHEMA:
        raise ReleaseGraphError(
            f"release[{profile_id}] is schema {document.get('manifest_schema_version')!r}; "
            "prospective production state requires schema 3")
    if document.get("content_authority") != CONTENT_AUTHORITY:
        raise ReleaseGraphError(
            f"release[{profile_id}] does not declare {CONTENT_AUTHORITY} authority")
    if any(field in document for field in
           ("operator_key_id", "operator_signature", "approval")):
        raise ReleaseGraphError(
            f"release[{profile_id}] carries a second off-chain authorization path")
    if document.get("manifest_self_sha256") != expected_root:
        raise ReleaseGraphError(
            f"release[{profile_id}] self root {document.get('manifest_self_sha256')!r} != "
            f"frontier-bound root {expected_root}")
    expected_hooks = {name: "1" for name in MAY_AFFECT_HOOKS}
    if document.get("hooks") != expected_hooks:
        raise ReleaseGraphError(
            f"release[{profile_id}] must conservatively declare the complete M1-M6 may-affect "
            "roster; an arbitrary Python module cannot prove a narrower behavioral scope")
    capabilities = document.get("capabilities")
    if capabilities != list(CAPABILITY_IDS):
        raise ReleaseGraphError(
            f"release[{profile_id}] must declare the full frozen capability roster "
            f"{list(CAPABILITY_IDS)}")
    provenance = _mapping(document.get("source_provenance"),
                          f"release[{profile_id}].source_provenance")
    if provenance.get("profile_id") != profile_id:
        raise ReleaseGraphError(
            f"release[{profile_id}] provenance names profile {provenance.get('profile_id')!r}")
    bundle_file_bindings(document)
    return document


def verify_materializable_release_state(
        *, releases: Mapping[str, str], composition_root: str, store: pub.ContentStore,
        expected_candidate_hashes: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Fetch and verify every byte needed to activate the resulting state.

    Missing bytes raise :class:`publication.ObjectNotFoundError` so a caller can distinguish a
    temporary publication backlog from a malformed/substituted graph.  Every other discrepancy
    raises :class:`ReleaseGraphError` or another :class:`publication.PublicationError` and is a
    permanent refusal.
    """
    expected_candidate_hashes = dict(expected_candidate_hashes or {})
    profile_ids = set(fr.PROFILE_IDS)
    if set(releases) != profile_ids:
        raise ReleaseGraphError(
            f"resulting frontier covers {sorted(releases)}; expected exactly "
            f"{sorted(profile_ids)}")
    if not set(expected_candidate_hashes).issubset(profile_ids):
        raise ReleaseGraphError("candidate bindings name a non-frontier profile")
    composition_root = _root(composition_root, "composition_root")
    composition = pub.fetch_json(
        composition_root, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    composition = dict(_mapping(composition, "composition manifest"))
    if (composition.get("format") != COMPOSITION_FORMAT
            or composition.get("content_authority") != CONTENT_AUTHORITY
            or composition.get("manifest_self_sha256") != composition_root):
        raise ReleaseGraphError(
            "composition is not a self-addressed, on-chain-authorized v2 deployment manifest")
    if any(field in composition for field in
           ("operator_key_id", "operator_signature", "approval")):
        raise ReleaseGraphError("composition carries a second off-chain authorization path")

    bindings = _mapping(composition.get("profile_bindings"), "composition.profile_bindings")
    delegation = _mapping(composition.get("delegation_candidate_hashes"),
                          "composition.delegation_candidate_hashes")
    bundles = _mapping(composition.get("bundles"), "composition.bundles")
    composition_map = _mapping(composition.get("composition"), "composition.composition")
    # The runtime composition family still carries one frozen reference-only entry. It is not a
    # mineable profile and may not point at a bundle. The canonical state itself remains exactly
    # the three PROFILE_IDS above.
    extended_ids = profile_ids | {LEGACY_PROFILE_ID}
    for field, value, expected in (
            ("profile_bindings", bindings, extended_ids),
            ("delegation_candidate_hashes", delegation, profile_ids),
            ("bundles", bundles, extended_ids),
            ("composition", composition_map, extended_ids)):
        if set(value) != expected:
            raise ReleaseGraphError(
                f"composition.{field} covers {sorted(value)}; expected exactly {sorted(expected)}")
    legacy = _mapping(bindings.get(LEGACY_PROFILE_ID),
                      f"profile_bindings[{LEGACY_PROFILE_ID!r}]")
    if legacy.get("is_baseline") is not True or bundles.get(LEGACY_PROFILE_ID) is not None:
        raise ReleaseGraphError("frozen reference entry is not baseline-bound and bundle-free")

    verified: Dict[str, Any] = {}
    for profile_id in fr.PROFILE_IDS:
        release_root = _root(releases[profile_id], f"release[{profile_id}]")
        manifest = pub.fetch_json(
            release_root, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
        document = validate_schema3_release(
            manifest, expected_root=release_root, profile_id=profile_id)
        binding = _mapping(bindings.get(profile_id), f"profile_bindings[{profile_id!r}]")
        if (binding.get("release_id") != release_root
                or binding.get("bundle_manifest_sha256") != release_root
                or binding.get("bundle_dir") != bundles.get(profile_id)
                or binding.get("miner_id") != composition_map.get(profile_id)):
            raise ReleaseGraphError(
                f"composition binding for {profile_id} does not install release {release_root}")
        candidate_hash = _root(binding.get("candidate_hash"),
                               f"profile_bindings[{profile_id!r}].candidate_hash")
        if delegation.get(profile_id) != candidate_hash:
            raise ReleaseGraphError(
                f"composition candidate binding for {profile_id} is internally inconsistent")
        expected = expected_candidate_hashes.get(profile_id)
        if expected is not None and candidate_hash != expected:
            raise ReleaseGraphError(
                f"composition candidate for {profile_id} is {candidate_hash}, evaluated code is "
                f"{expected}")
        files = bundle_file_bindings(document)
        if binding.get("miner_sha256") != files["miner_module.py"]:
            raise ReleaseGraphError(
                f"composition miner_sha256 for {profile_id} does not bind miner_module.py")
        if binding.get("module_sha256") != files["module.py"]:
            raise ReleaseGraphError(
                f"composition module_sha256 for {profile_id} does not bind module.py")
        for _filename, digest in sorted(files.items()):
            pub.read_back(digest, hash_rule=pub.HASH_RULE_BYTES, store=store)
        verified[profile_id] = {"manifest": document, "files": files}
    return {"composition": composition, "releases": verified}
