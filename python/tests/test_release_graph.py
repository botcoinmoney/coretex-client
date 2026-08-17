from __future__ import annotations

import copy

import pytest

from coretex_validator import frontier as fr
from coretex_validator import publication as pub
from coretex_validator import release_graph as rg


def _publish_bytes(store, data: bytes) -> str:
    return pub.publish_item(data, hash_rule=pub.HASH_RULE_BYTES, store=store)["root"]


def _publish_manifest(store, manifest):
    root = fr.sha256_hex(pub.benchmark_canonical_bytes(manifest))
    manifest["manifest_self_sha256"] = root
    assert pub.publish_item(
        manifest, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)["root"] == root
    return root


def _release(store, profile: str):
    module = _publish_bytes(store, f"miner-and-module:{profile}".encode())
    manifest = {
        "abi_version": 2,
        "admission_report_hash": fr.sha256_hex(f"admission:{profile}".encode()),
        "analyzer_ruleset_root": fr.sha256_hex(b"ruleset"),
        "candidate_provider": {"id": "coretex", "version": 1},
        "capabilities": list(rg.CAPABILITY_IDS),
        "capabilities_used": [rg.CAPABILITY_IDS[0]],
        "content_authority": rg.CONTENT_AUTHORITY,
        "counter": {"id": "counter", "version": 1},
        "deployment_profile": "balanced",
        "hooks": {"m6_pack": "1"},
        "manifest_schema_version": rg.SANDBOXED_RELEASE_SCHEMA,
        "module_sha256": module,
        "policy_id": f"fixture/{profile}",
        "rollback_id": "fixture",
        "runtime_version_max": "0.1.5",
        "runtime_version_min": "0.1.5",
        "schema": "coretex-memory/release-manifest",
        "source_provenance": {
            "base_modules": {}, "miner": f"miner-{profile}", "profile_id": profile,
        },
        "store_schema_version": 1,
        "wrapper_format": rg.DIRECT_WRAPPER_FORMAT,
    }
    root = _publish_manifest(store, manifest)
    candidate = fr.sha256_hex(f"candidate:{profile}".encode())
    return root, manifest, module, candidate


def _historical_release(store, profile: str):
    adapter = _publish_bytes(store, f"adapter:{profile}".encode())
    miner = _publish_bytes(store, f"miner:{profile}".encode())
    manifest = {
        "capabilities": list(rg.CAPABILITY_IDS),
        "content_authority": rg.CONTENT_AUTHORITY,
        "hooks": {name: "1" for name in rg.MAY_AFFECT_HOOKS},
        "manifest_schema_version": rg.HISTORICAL_CONTENT_ADDRESSED_RELEASE_SCHEMA,
        "module_sha256": adapter,
        "source_provenance": {
            "base_modules": {"miner_module.py": miner}, "entry": "Champion",
            "profile_id": profile,
        },
        "wrapper_format": 2,
    }
    root = _publish_manifest(store, manifest)
    return root, manifest


def _graph():
    store = pub.InMemoryCAS()
    releases = {}
    records = {}
    for profile in fr.PROFILE_IDS:
        root, manifest, module, candidate = _release(store, profile)
        releases[profile] = root
        records[profile] = (manifest, module, candidate)
    bundles = {p: f"releases/{p}" for p in fr.PROFILE_IDS}
    bundles[rg.LEGACY_PROFILE_ID] = None
    labels = {p: f"release-{p}" for p in fr.PROFILE_IDS}
    labels[rg.LEGACY_PROFILE_ID] = None
    bindings = {
        p: {
            "bundle_dir": bundles[p], "bundle_manifest_sha256": releases[p],
            "candidate_hash": records[p][2], "is_baseline": False,
            "miner_id": labels[p], "release_id": releases[p],
            "module_sha256": records[p][1], "miner_sha256": records[p][1],
        } for p in fr.PROFILE_IDS
    }
    bindings[rg.LEGACY_PROFILE_ID] = {
        "bundle_dir": None, "is_baseline": True, "miner_id": None,
    }
    composition = {
        "bundles": bundles,
        "composition": labels,
        "content_authority": rg.CONTENT_AUTHORITY,
        "delegation_candidate_hashes": {p: records[p][2] for p in fr.PROFILE_IDS},
        "format": rg.COMPOSITION_FORMAT,
        "profile_bindings": bindings,
    }
    composition_root = _publish_manifest(store, composition)
    return store, releases, records, composition_root


def test_complete_schema4_graph_fetches_three_profiles_and_exact_two_file_bundles():
    store, releases, records, composition = _graph()
    target = fr.PROFILE_IDS[1]
    result = rg.verify_materializable_release_state(
        releases=releases, composition_root=composition, store=store,
        expected_candidate_hashes={target: records[target][2]})
    assert tuple(sorted(result["releases"])) == tuple(sorted(fr.PROFILE_IDS))
    assert all(set(item["files"]) == {"module.py"}
               for item in result["releases"].values())
    assert all(set(item["bundle_files"]) == {"manifest.json", "module.py"}
               for item in result["releases"].values())


def test_missing_any_manifest_bound_module_is_not_materializable():
    store, releases, records, composition = _graph()
    missing = records[fr.PROFILE_IDS[2]][1]
    del store._objects[missing]
    with pytest.raises(pub.ObjectNotFoundError):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store)


def test_exact_inferred_hook_subset_is_allowed_but_empty_or_unknown_is_refused():
    _store, releases, records, _composition = _graph()
    profile = fr.PROFILE_IDS[0]
    manifest = copy.deepcopy(records[profile][0])
    assert rg.validate_schema4_release(
        manifest, expected_root=releases[profile], profile_id=profile)["hooks"] == {"m6_pack": "1"}
    manifest["hooks"] = {}
    with pytest.raises(rg.ReleaseGraphError, match="non-empty exact hook map"):
        rg.validate_schema4_release(manifest, expected_root=releases[profile], profile_id=profile)
    manifest["hooks"] = {"prepare": "1"}
    with pytest.raises(rg.ReleaseGraphError, match="unknown hooks"):
        rg.validate_schema4_release(manifest, expected_root=releases[profile], profile_id=profile)


@pytest.mark.parametrize("version", [3, 4.0, True])
def test_only_exact_integer_schema4_is_prospectively_materializable(version):
    store, releases, records, composition = _graph()
    profile = fr.PROFILE_IDS[0]
    manifest = copy.deepcopy(records[profile][0])
    manifest["manifest_schema_version"] = version
    root = _publish_manifest(store, {k: v for k, v in manifest.items()
                                     if k != "manifest_self_sha256"})
    releases[profile] = root
    composed = pub.fetch_json(
        composition, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    composed["profile_bindings"][profile]["release_id"] = root
    composed["profile_bindings"][profile]["bundle_manifest_sha256"] = root
    composed.pop("manifest_self_sha256")
    composition = _publish_manifest(store, composed)
    with pytest.raises(rg.ReleaseGraphError, match="exact integer 4"):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store)


def test_schema3_is_explicitly_historical_and_never_materializable():
    store, releases, _records, composition = _graph()
    profile = fr.PROFILE_IDS[0]
    root, manifest = _historical_release(store, profile)
    inspected = rg.validate_historical_schema3_release(
        manifest, expected_root=root, profile_id=profile)
    assert inspected["manifest_schema_version"] == 3

    releases[profile] = root
    composed = pub.fetch_json(
        composition, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    composed["profile_bindings"][profile]["release_id"] = root
    composed["profile_bindings"][profile]["bundle_manifest_sha256"] = root
    composed.pop("manifest_self_sha256")
    composition = _publish_manifest(store, composed)
    with pytest.raises(rg.ReleaseGraphError, match="requires the exact integer 4"):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store)


@pytest.mark.parametrize("mutation, message", [
    (lambda m: m.update(wrapper_format=2), "wrapper_format"),
    (lambda m: m["source_provenance"].update(
        base_modules={"miner_module.py": "a" * 64}), "empty object"),
    (lambda m: m.pop("admission_report_hash"), "required schema-4 fields"),
    (lambda m: m.pop("analyzer_ruleset_root"), "required schema-4 fields"),
    (lambda m: m.pop("capabilities_used"), "required schema-4 fields"),
])
def test_one_shape_and_admission_bindings_are_required(mutation, message):
    _store, releases, records, _composition = _graph()
    profile = fr.PROFILE_IDS[0]
    manifest = copy.deepcopy(records[profile][0])
    mutation(manifest)
    with pytest.raises(rg.ReleaseGraphError, match=message):
        rg.validate_schema4_release(manifest, expected_root=releases[profile], profile_id=profile)


def test_capabilities_used_must_be_known_unique_and_granted():
    _store, releases, records, _composition = _graph()
    profile = fr.PROFILE_IDS[0]
    manifest = copy.deepcopy(records[profile][0])
    manifest["capabilities"] = [rg.CAPABILITY_IDS[1]]
    with pytest.raises(rg.ReleaseGraphError, match="not granted"):
        rg.validate_schema4_release(manifest, expected_root=releases[profile], profile_id=profile)
    manifest["capabilities"] = list(rg.CAPABILITY_IDS)
    manifest["capabilities_used"] *= 2
    with pytest.raises(rg.ReleaseGraphError, match="duplicates"):
        rg.validate_schema4_release(manifest, expected_root=releases[profile], profile_id=profile)


def test_composition_miner_and_module_must_bind_the_same_bytes():
    store, releases, _records, composition = _graph()
    profile = fr.PROFILE_IDS[0]
    composed = pub.fetch_json(
        composition, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    composed["profile_bindings"][profile]["miner_sha256"] = "f" * 64
    composed.pop("manifest_self_sha256")
    composition = _publish_manifest(store, composed)
    with pytest.raises(rg.ReleaseGraphError, match="miner bytes must be the executed module bytes"):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store)


def test_evaluated_candidate_must_be_the_composition_delegation():
    store, releases, _records, composition = _graph()
    with pytest.raises(rg.ReleaseGraphError, match="evaluated code"):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store,
            expected_candidate_hashes={fr.PROFILE_IDS[0]: "f" * 64})
