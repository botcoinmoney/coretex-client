# SPDX-License-Identifier: Apache-2.0
"""Fail-closed verification of the prospective CoreTex release graph.

Prospective state has one release shape: schema 4, direct wrapper format 3, and a two-file bundle
(``manifest.json`` plus ``module.py``). The module object is byte-for-byte the admitted miner
submission; there is no generated adapter and ``source_provenance.base_modules`` is exactly the
empty object. A usable state requires its composition, all three profile release manifests, and
the module bytes named by each manifest.

This module follows that complete graph without importing the CoreTex runtime. The public
validator remains a zero-dependency package and treats analyzer/evaluator execution as a separate,
pinned replay stage. It can therefore verify that the admission report, analyzer ruleset and
inferred-capability commitments are present and internally well-shaped here; the later
deterministic-admission stage re-executes the committed law.

Schema 3 is retained only in :func:`validate_historical_schema3_release` for explicit historical
inspection. Prospective materialization never calls it and always refuses a schema-3 release.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Tuple

from . import frontier as fr
from . import publication as pub


SANDBOXED_RELEASE_SCHEMA = 4
DIRECT_WRAPPER_FORMAT = 3
HISTORICAL_CONTENT_ADDRESSED_RELEASE_SCHEMA = 3
CONTENT_AUTHORITY = "ONCHAIN_COMMITTED_ROOT"
COMPOSITION_FORMAT = "coretex-memory/deployment-content-addressed/v2"
BUNDLE_FILES = frozenset(("manifest.json", "module.py"))
MAY_AFFECT_HOOKS: Tuple[str, ...] = (
    "m1_ingest_transform", "m2_organize", "m3_consolidate",
    "m4_candidates", "m5_rank", "m6_pack",
)
CAPABILITY_IDS: Tuple[str, ...] = ("cap.text.v1", "cap.lexicon.v1")
LEGACY_PROFILE_ID = "legacy.structured.v1"

_COMMON_REQUIRED_FIELDS: Tuple[str, ...] = (
    "schema", "manifest_schema_version", "policy_id", "module_sha256",
    "source_provenance", "abi_version", "runtime_version_min", "runtime_version_max",
    "candidate_provider", "counter", "store_schema_version", "deployment_profile",
    "rollback_id", "manifest_self_sha256",
)
_V4_REQUIRED_FIELDS: Tuple[str, ...] = (
    "hooks", "capabilities", "capabilities_used", "content_authority",
    "admission_report_hash", "analyzer_ruleset_root", "wrapper_format",
)
_OFFCHAIN_AUTHORIZATION_FIELDS: Tuple[str, ...] = (
    "operator_key_id", "operator_signature", "approval",
)


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


def _unique_known_list(value: Any, *, where: str, known: Tuple[str, ...]) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise ReleaseGraphError(f"{where} must be a list")
    if any(not isinstance(item, str) for item in value):
        raise ReleaseGraphError(f"{where} entries must be strings")
    if len(set(value)) != len(value):
        raise ReleaseGraphError(f"{where} contains duplicates")
    unknown = sorted(set(value) - set(known))
    if unknown:
        raise ReleaseGraphError(f"{where} names unknown values {unknown}")
    return tuple(value)


def bundle_file_bindings(manifest: Mapping[str, Any]) -> Dict[str, str]:
    """Return the sole non-manifest file bound by a prospective schema-4 release.

    The manifest itself is fetched by its release root. An explicitly empty ``base_modules`` map
    means the resulting directory shape is exactly ``manifest.json`` + ``module.py``.
    """
    provenance = _mapping(manifest.get("source_provenance"), "source_provenance")
    if "base_modules" not in provenance:
        raise ReleaseGraphError("source_provenance.base_modules must be explicitly present")
    base_modules = provenance.get("base_modules")
    if not isinstance(base_modules, Mapping) or dict(base_modules) != {}:
        raise ReleaseGraphError(
            "source_provenance.base_modules must be exactly the empty object {}; "
            "schema-4 bundles contain only manifest.json and module.py")
    return {"module.py": _root(manifest.get("module_sha256"), "module_sha256")}


def validate_schema4_release(manifest: Any, *, expected_root: str,
                             profile_id: str) -> Dict[str, Any]:
    """Validate the one prospective release shape without executing miner code."""
    document = dict(_mapping(manifest, f"release[{profile_id}]"))
    schema_version = document.get("manifest_schema_version")
    if type(schema_version) is not int or schema_version != SANDBOXED_RELEASE_SCHEMA:
        raise ReleaseGraphError(
            f"release[{profile_id}] is schema {schema_version!r}; prospective production state "
            f"requires the exact integer {SANDBOXED_RELEASE_SCHEMA}")
    missing = [field for field in _COMMON_REQUIRED_FIELDS + _V4_REQUIRED_FIELDS
               if field not in document]
    if missing:
        raise ReleaseGraphError(
            f"release[{profile_id}] is missing required schema-4 fields {missing}")
    if document.get("schema") != "coretex-memory/release-manifest":
        raise ReleaseGraphError(f"release[{profile_id}] has an unknown release schema")
    if document.get("content_authority") != CONTENT_AUTHORITY:
        raise ReleaseGraphError(
            f"release[{profile_id}] does not declare {CONTENT_AUTHORITY} authority")
    if any(field in document for field in _OFFCHAIN_AUTHORIZATION_FIELDS):
        raise ReleaseGraphError(
            f"release[{profile_id}] carries a second off-chain authorization path")
    if document.get("manifest_self_sha256") != expected_root:
        raise ReleaseGraphError(
            f"release[{profile_id}] self root {document.get('manifest_self_sha256')!r} != "
            f"frontier-bound root {expected_root}")
    wrapper_format = document.get("wrapper_format")
    if type(wrapper_format) is not int or wrapper_format != DIRECT_WRAPPER_FORMAT:
        raise ReleaseGraphError(
            f"release[{profile_id}] wrapper_format must be the exact integer "
            f"{DIRECT_WRAPPER_FORMAT}; got {wrapper_format!r}")

    hooks = document.get("hooks")
    if not isinstance(hooks, Mapping) or not hooks:
        raise ReleaseGraphError(
            f"release[{profile_id}].hooks must be a non-empty exact hook map")
    unknown_hooks = sorted(set(hooks) - set(MAY_AFFECT_HOOKS))
    if unknown_hooks:
        raise ReleaseGraphError(
            f"release[{profile_id}].hooks names unknown hooks {unknown_hooks}")
    bad_versions = sorted(name for name, version in hooks.items()
                          if not isinstance(version, str) or not version)
    if bad_versions:
        raise ReleaseGraphError(
            f"release[{profile_id}].hooks has invalid ABI versions for {bad_versions}")

    capabilities = _unique_known_list(
        document.get("capabilities"), where=f"release[{profile_id}].capabilities",
        known=CAPABILITY_IDS)
    capabilities_used = _unique_known_list(
        document.get("capabilities_used"),
        where=f"release[{profile_id}].capabilities_used", known=CAPABILITY_IDS)
    extra = sorted(set(capabilities_used) - set(capabilities))
    if extra:
        raise ReleaseGraphError(
            f"release[{profile_id}].capabilities_used {extra} are not granted by capabilities")
    for field in ("admission_report_hash", "analyzer_ruleset_root"):
        _root(document.get(field), f"release[{profile_id}].{field}")

    provenance = _mapping(document.get("source_provenance"),
                          f"release[{profile_id}].source_provenance")
    if provenance.get("profile_id") != profile_id:
        raise ReleaseGraphError(
            f"release[{profile_id}] provenance names profile {provenance.get('profile_id')!r}")
    bundle_file_bindings(document)
    return document


def validate_historical_schema3_release(manifest: Any, *, expected_root: str,
                                        profile_id: str) -> Dict[str, Any]:
    """Inspect a historical schema-3 release; never authorize prospective materialization.

    This preserves auditability of already-addressed evidence. It is intentionally not called by
    :func:`verify_materializable_release_state` and does not turn schema 3 into a supported live
    mint, serve, or activation path.
    """
    document = dict(_mapping(manifest, f"historical release[{profile_id}]"))
    if document.get("manifest_schema_version") != HISTORICAL_CONTENT_ADDRESSED_RELEASE_SCHEMA:
        raise ReleaseGraphError(
            f"historical release[{profile_id}] is not schema "
            f"{HISTORICAL_CONTENT_ADDRESSED_RELEASE_SCHEMA}")
    if document.get("content_authority") != CONTENT_AUTHORITY:
        raise ReleaseGraphError(
            f"historical release[{profile_id}] does not declare {CONTENT_AUTHORITY} authority")
    if any(field in document for field in _OFFCHAIN_AUTHORIZATION_FIELDS):
        raise ReleaseGraphError(
            f"historical release[{profile_id}] carries a second off-chain authorization path")
    if document.get("manifest_self_sha256") != expected_root:
        raise ReleaseGraphError(
            f"historical release[{profile_id}] self root does not match its addressed root")
    provenance = _mapping(document.get("source_provenance"),
                          f"historical release[{profile_id}].source_provenance")
    if provenance.get("profile_id") != profile_id:
        raise ReleaseGraphError(
            f"historical release[{profile_id}] provenance names "
            f"{provenance.get('profile_id')!r}")
    return document


def verify_materializable_release_state(
        *, releases: Mapping[str, str], composition_root: str, store: pub.ContentStore,
        expected_candidate_hashes: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Fetch and verify every byte needed to activate the resulting schema-4 state.

    Missing bytes raise :class:`publication.ObjectNotFoundError` so a caller can distinguish a
    temporary publication backlog from a malformed/substituted graph. Every other discrepancy
    raises :class:`ReleaseGraphError` or another :class:`publication.PublicationError` and is a
    permanent refusal. Historical schema-3 releases are always refused here.
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
    if any(field in composition for field in _OFFCHAIN_AUTHORIZATION_FIELDS):
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
        document = validate_schema4_release(
            manifest, expected_root=release_root, profile_id=profile_id)
        binding = _mapping(bindings.get(profile_id), f"profile_bindings[{profile_id!r}]")
        if binding.get("is_baseline") is not False:
            raise ReleaseGraphError(
                f"composition binding for {profile_id} must install a non-baseline release")
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
        module_root = files["module.py"]
        if binding.get("module_sha256") != module_root:
            raise ReleaseGraphError(
                f"composition module_sha256 for {profile_id} does not bind module.py")
        if binding.get("miner_sha256") != module_root:
            raise ReleaseGraphError(
                f"composition miner_sha256 for {profile_id} does not equal module.py; "
                "schema-4 miner bytes must be the executed module bytes")
        pub.read_back(module_root, hash_rule=pub.HASH_RULE_BYTES, store=store)
        verified[profile_id] = {
            "manifest": document,
            "files": files,
            "bundle_files": tuple(sorted(BUNDLE_FILES)),
        }
    return {"composition": composition, "releases": verified}
