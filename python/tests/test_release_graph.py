from __future__ import annotations

import copy

import pytest

from coretex_validator import frontier as fr
from coretex_validator import publication as pub
from coretex_validator import release_graph as rg


def _publish_bytes(store, data: bytes) -> str:
    return pub.publish_item(data, hash_rule=pub.HASH_RULE_BYTES, store=store)["root"]


def _release(store, profile: str):
    adapter = _publish_bytes(store, f"adapter:{profile}".encode())
    miner = _publish_bytes(store, f"miner:{profile}".encode())
    manifest = {
        "abi_version": 2,
        "candidate_provider": {"id": "coretex", "version": 1},
        "capabilities": list(rg.CAPABILITY_IDS),
        "content_authority": rg.CONTENT_AUTHORITY,
        "counter": {"id": "counter", "version": 1},
        "deployment_profile": "balanced",
        "hooks": {name: "1" for name in rg.MAY_AFFECT_HOOKS},
        "manifest_schema_version": 3,
        "module_sha256": adapter,
        "policy_id": f"fixture/{profile}",
        "rollback_id": "fixture",
        "runtime_version_max": "0.1.3",
        "runtime_version_min": "0.1.3",
        "schema": "coretex-memory/release-manifest",
        "source_provenance": {
            "base_modules": {"miner_module.py": miner}, "entry": "Champion",
            "profile_id": profile,
        },
        "store_schema_version": 1,
        "wrapper_format": 2,
    }
    # Signed-manifest-body excludes this field, so first compute then publish the exact document.
    root = fr.sha256_hex(pub.benchmark_canonical_bytes(manifest))
    manifest["manifest_self_sha256"] = root
    assert pub.publish_item(manifest, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY,
                            store=store)["root"] == root
    candidate = fr.sha256_hex(f"candidate:{profile}".encode())
    return root, manifest, adapter, miner, candidate


def _graph():
    store = pub.InMemoryCAS()
    releases = {}
    records = {}
    for profile in fr.PROFILE_IDS:
        root, manifest, adapter, miner, candidate = _release(store, profile)
        releases[profile] = root
        records[profile] = (manifest, adapter, miner, candidate)
    bundles = {p: f"releases/{p}" for p in fr.PROFILE_IDS}
    bundles[rg.LEGACY_PROFILE_ID] = None
    labels = {p: f"release-{p}" for p in fr.PROFILE_IDS}
    labels[rg.LEGACY_PROFILE_ID] = None
    bindings = {
        p: {
            "bundle_dir": bundles[p], "bundle_manifest_sha256": releases[p],
            "candidate_hash": records[p][3], "is_baseline": False,
            "miner_id": labels[p], "release_id": releases[p],
            "module_sha256": records[p][1], "miner_sha256": records[p][2],
        } for p in fr.PROFILE_IDS
    }
    bindings[rg.LEGACY_PROFILE_ID] = {
        "bundle_dir": None, "is_baseline": True, "miner_id": None,
    }
    composition = {
        "bundles": bundles,
        "composition": labels,
        "content_authority": rg.CONTENT_AUTHORITY,
        "delegation_candidate_hashes": {p: records[p][3] for p in fr.PROFILE_IDS},
        "format": rg.COMPOSITION_FORMAT,
        "profile_bindings": bindings,
    }
    composition_root = fr.sha256_hex(pub.benchmark_canonical_bytes(composition))
    composition["manifest_self_sha256"] = composition_root
    pub.publish_item(composition, hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=store)
    return store, releases, records, composition_root


def test_complete_schema3_graph_fetches_all_three_profiles_and_files():
    store, releases, records, composition = _graph()
    target = fr.PROFILE_IDS[1]
    result = rg.verify_materializable_release_state(
        releases=releases, composition_root=composition, store=store,
        expected_candidate_hashes={target: records[target][3]})
    assert tuple(sorted(result["releases"])) == tuple(sorted(fr.PROFILE_IDS))
    assert all(set(item["files"]) == {"module.py", "miner_module.py"}
               for item in result["releases"].values())


def test_missing_any_manifest_bound_file_is_not_materializable():
    store, releases, records, composition = _graph()
    missing = records[fr.PROFILE_IDS[2]][2]
    del store._objects[missing]
    with pytest.raises(pub.ObjectNotFoundError):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store)


def test_narrow_hook_claim_is_refused_for_arbitrary_schema3_python():
    store, releases, records, composition = _graph()
    profile = fr.PROFILE_IDS[0]
    manifest = copy.deepcopy(records[profile][0])
    manifest["hooks"].pop("m1_ingest_transform")
    # Direct validation isolates the semantic refusal from the inevitable content-root mismatch.
    with pytest.raises(rg.ReleaseGraphError, match="complete M1-M6 may-affect"):
        rg.validate_schema3_release(manifest, expected_root=releases[profile], profile_id=profile)


def test_partial_capability_roster_is_refused():
    store, releases, records, _composition = _graph()
    profile = fr.PROFILE_IDS[0]
    manifest = copy.deepcopy(records[profile][0])
    manifest["capabilities"] = [rg.CAPABILITY_IDS[0]]
    with pytest.raises(rg.ReleaseGraphError, match="full frozen capability roster"):
        rg.validate_schema3_release(manifest, expected_root=releases[profile], profile_id=profile)


def test_evaluated_candidate_must_be_the_composition_delegation():
    store, releases, _records, composition = _graph()
    with pytest.raises(rg.ReleaseGraphError, match="evaluated code"):
        rg.verify_materializable_release_state(
            releases=releases, composition_root=composition, store=store,
            expected_candidate_hashes={fr.PROFILE_IDS[0]: "f" * 64})
