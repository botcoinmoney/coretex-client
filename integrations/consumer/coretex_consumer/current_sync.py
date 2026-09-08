# SPDX-License-Identifier: Apache-2.0
"""Adopt confirmed chain-selected modules without replaying admission history.

RPC is the consumer's chain authority. CAS is untrusted transport. This is not an
independent lawfulness proof; that remains the standalone validator's full replay.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from urllib.parse import urlencode

from coretex_memory_agent.authority import (CurrentReleaseAuthority, PROFILE_IDS, _canonical_bytes, _json_bytes,
                        _parse_json_bytes, _root, _strict_object)
from .chain_reader import ChainReader, SyncError, Transport, validate_url, PUBLIC_RPC
from .current_state import CURRENT_STATE_FORMAT, CurrentState, authority_from_current

FRONTIER_RULE = "sha256-frontier-canonical-json"
MANIFEST_RULE = "sha256-manifest-body"
BYTES_RULE = "sha256-bytes"


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _root_of(raw, rule):
    if rule == BYTES_RULE:
        return _sha(raw)
    value = _parse_json_bytes(raw, "CAS object")
    if rule == FRONTIER_RULE:
        return _sha(_canonical_bytes(value))
    if rule == MANIFEST_RULE and isinstance(value, dict):
        observed = _sha(_json_bytes({k: v for k, v in value.items()
                                    if k != "manifest_self_sha256"}))
        if value.get("manifest_self_sha256") == observed:
            return observed
    raise SyncError("CAS manifest does not reproduce its self root")


def _atomic_write(path, raw, *, replace=True):
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, path)
        else:
            os.link(name, path)  # atomic no-clobber publication of a new configuration
    finally:
        if os.path.exists(name):
            os.unlink(name)


class ObjectReader:
    def __init__(self, url, cache):
        validate_url(url)
        if "?" in url:
            raise SyncError("object base URL cannot have a query")
        self.url, self.cache = url.rstrip("/") + "/", cache
        self.transport = Transport(interval=1)

    def __call__(self, root, rule):
        _root(root, "object root")
        if rule not in (FRONTIER_RULE, MANIFEST_RULE, BYTES_RULE):
            raise SyncError("unsupported object hash rule")
        path = self.cache / (rule + "-" + root)
        if path.is_symlink():
            raise SyncError("linked CAS cache entry refused")
        if path.exists():
            with path.open("rb") as stream:
                raw = stream.read(2 * 1024 * 1024 + 1)
        else:
            raw = self.transport.read(self.url + root + "?" + urlencode({"hashRule": rule}))
        if len(raw) > 2 * 1024 * 1024 or _root_of(raw, rule) != root:
            raise SyncError(f"object {root} fails its declared hash rule")
        if not path.exists():
            _atomic_write(path, raw)
        return raw


def _pointer(rpc, addresses, block):
    mining, registry, verifier = (addresses[k] for k in ("mining", "registry", "verifier"))
    epoch = rpc.uint(mining, "currentEpoch()", block, bits=64)
    if rpc.uint(verifier, "coreTexEpochContextSet(uint64)", block, epoch, bits=1) != 1:
        raise SyncError(f"confirmed epoch {epoch} has no CoreTex context; retry after context setup")
    context = {name: rpc.view(registry, sig, block, epoch)[0].hex() for name, sig in (
        ("core_version_hash", "epochCoreVersionHash(uint64)"),
        ("epoch_context_root", "epochContextRoot(uint64)"),
        ("parent_state_root", "epochParentStateRoot(uint64)"))}
    return {"id": epoch, "context": context,
            "live_state_root": rpc.view(registry, "liveStateRoot(uint64)", block, epoch)[0].hex()}


def _verify_context(raw, pointer, authority):
    value = _parse_json_bytes(raw, "epoch context")
    release = authority.release
    expected = {
        "active_frontier_root": pointer["context"]["parent_state_root"],
        "baseline_manifest_hash": release["genesis"]["baseline_root"],
        "benchmark_law_root": release["law"]["benchmark_law_root"],
        "corpus_root": release["law"]["canonical_suite_root"],
        "counter_resource_law_root": release["objects"]["counter_resource_law_root"]["root"],
        "runtime_abi_root": release["objects"]["miner_module_abi_root"]["root"],
        "selection_law_root": release["law"]["evaluation_law_root"],
        "epoch": pointer["id"], "format": "coretex.epoch-context/v1",
        "seed_commitment": {
            "binding_rule": "revealed secret S is admitted iff keccak256(S) == epochCommit(epochId)",
            "commitment_source": "mining.epochCommit(epochId)", "scheme": "keccak256-hidden-seed/v1"},
    }
    if value != expected or type(value["epoch"]) is not int:
        raise SyncError("current epoch context does not bind this release and parent")


def _materialize(directory, document, fetch, authority, release_dir):
    front = document["frontier"]["manifest"]
    composition_root = _root(front["default_composition_root"], "frontier composition")
    raw_composition = fetch(composition_root, MANIFEST_RULE)
    composition = _parse_json_bytes(raw_composition, "composition")
    _strict_object(composition, ("format", "content_authority", "composition", "bundles",
        "delegation_candidate_hashes", "profile_bindings", "manifest_self_sha256"), "composition")
    if composition["format"] != "coretex-memory/deployment-content-addressed/v2" \
            or composition["content_authority"] != "ONCHAIN_COMMITTED_ROOT":
        raise SyncError("unsupported frontier composition")
    for name in ("composition", "bundles", "profile_bindings"):
        _strict_object(composition[name], PROFILE_IDS, f"composition.{name}")
    delegated = set()
    for profile in PROFILE_IDS:
        root = _root(front["profiles"][profile], "profile release root")
        binding = composition["profile_bindings"][profile]
        if binding == {"is_baseline": True}:
            genesis = authority.composition.binding(profile)
            if genesis.exec != "reference" or root != genesis.release_root \
                    or composition["bundles"][profile] is not None \
                    or composition["composition"][profile] is not None:
                raise SyncError("reference slot does not match the sealed release")
            document["profiles"][profile] = {"exec": "reference", "release_root": root}
            continue
        _strict_object(binding, ("is_baseline", "bundle_dir", "bundle_manifest_sha256",
            "candidate_hash", "miner_id", "miner_sha256", "module_sha256", "release_id"),
            "profile composition binding")
        if binding["is_baseline"] is not False:
            raise SyncError("module slot has an invalid baseline flag")
        delegated.add(profile)
        manifest_raw = fetch(root, MANIFEST_RULE)
        manifest = _parse_json_bytes(manifest_raw, "module manifest")
        module_root = _root(manifest["module_sha256"], "module root")
        module_raw = fetch(module_root, BYTES_RULE)
        bundle = f"bundles/{profile}"
        (directory / bundle).mkdir(parents=True)
        (directory / bundle / "manifest.json").write_bytes(manifest_raw)
        (directory / bundle / "module.py").write_bytes(module_raw)
        provenance = f"provenance/{profile}.composition.json"
        (directory / "provenance").mkdir(exist_ok=True)
        (directory / provenance).write_bytes(raw_composition)
        document["profiles"][profile] = {
            "exec": "candidate_module", "release_root": root,
            "candidate_hash": binding["candidate_hash"],
            "bundle": {"directory": bundle, "manifest": "manifest.json", "module": "module.py",
                       "manifest_sha256": _sha(manifest_raw), "manifest_size": len(manifest_raw),
                       "module_sha256": module_root, "module_size": len(module_raw)},
            "provenance": {"composition": provenance, "composition_root": composition_root,
                           "composition_sha256": _sha(raw_composition),
                           "composition_size": len(raw_composition)}}
    _strict_object(composition["delegation_candidate_hashes"], delegated, "delegated profiles")
    snapshot = CurrentState.parse(document, base_dir=directory)
    # This rechecks every frontier/profile/composition edge and the module's source provenance.
    bound = authority_from_current(release_dir, snapshot)
    from coretex_memory.current_state import verify_bundle
    for profile in PROFILE_IDS:
        binding = bound.binding(profile)
        if binding.exec == "candidate_module":
            provider = binding.retrieval_descriptor
            # Static capability/ABI analysis only, not a benchmark or historical evaluation.
            verify_bundle(str(binding.bundle_dir), expected_manifest_root=binding.release_root,
                          expected_provider={"id": provider["id"], "version": provider["version"]})
    (directory / "current-state.json").write_bytes(_json_bytes(document))


def sync_current(*, release_dir, expected_release_root, output_dir, rpc_url=PUBLIC_RPC,
                 object_url="https://coordinator.agentmoney.net/coretex/v5/object/",
                 confirmations=12, progress=None, rpc=None, fetch=None):
    """Return one immutable, freshly checked consumer snapshot. Existing stores are never opened."""
    if type(confirmations) is not int or not 1 <= confirmations <= 256:
        raise SyncError("confirmation depth must be in 1..256")
    progress = progress or (lambda _message: None)
    progress("verify release and deployment")
    authority = CurrentReleaseAuthority.load(release_dir, expected_release_root=expected_release_root)
    declaration = authority.release["objects"]["rig_contract_authority_root"]
    contract = _parse_json_bytes((Path(release_dir) / declaration["path"]).read_bytes(),
                                "contract authority")
    rpc = rpc or ChainReader(rpc_url)
    output = Path(output_dir).expanduser().absolute()
    if output.is_symlink():
        raise SyncError("sync output must not be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    cache = output / "objects"
    if cache.is_symlink():
        raise SyncError("sync object cache must not be a symlink")
    cache.mkdir(exist_ok=True)
    reader = fetch or ObjectReader(object_url, cache)
    def fetch(root, rule):
        _root(root, "requested object root")
        raw = reader(root, rule)
        if len(raw) > 2 * 1024 * 1024 or _root_of(raw, rule) != root:
            raise SyncError(f"object {root} fails its declared hash rule")
        return raw
    lock_fd = os.open(output / ".sync.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = output / "LAST-OBSERVATION.json"
        minimum_block = 0
        if previous.exists():
            minimum_block = json.loads(previous.read_bytes())["block_number"]
        for _attempt in range(3):
            head = rpc.head(confirmations)
            if head["number"] < minimum_block:
                raise SyncError("RPC confirmed head is behind the last successful sync")
            addresses = rpc.deployment(contract, head["number"])
            pointer = _pointer(rpc, addresses, head["number"])
            if pointer["context"]["core_version_hash"] != authority.compatibility_lock_root:
                raise SyncError("current chain uses another compatibility lock; bootstrap its release")
            progress(f"confirmed epoch {pointer['id']}, block {head['number']}; fetch current modules")
            _verify_context(fetch(pointer["context"]["epoch_context_root"], FRONTIER_RULE),
                            pointer, authority)
            live_root = _root(pointer["live_state_root"], "chain frontier")
            manifest = _parse_json_bytes(fetch(live_root, FRONTIER_RULE), "frontier")
            # An injected/custom fetch must satisfy exactly the same hash checks as HTTP.
            if _sha(_canonical_bytes(manifest)) != live_root:
                raise SyncError("frontier bytes do not equal the confirmed pointer")
            document = {"format": CURRENT_STATE_FORMAT, "version": 1,
                "provenance": {"mode": "chain-pointer", "admission_replayed": False},
                "release_root": authority.release_root, "deployment": addresses,
                "chain": {"chain_id": contract["chain_id"], "observation": {
                    "block_hash": head["hash"], "block_number": head["number"],
                    "confirmation_depth": confirmations}}, "epoch": pointer,
                "frontier": {"root": live_root, "manifest": manifest}, "profiles": {}}
            temporary = Path(tempfile.mkdtemp(prefix=".sync-", dir=output))
            try:
                _materialize(temporary, document, fetch, authority, release_dir)
                finish = rpc.head(confirmations)
                if finish["number"] < head["number"] \
                        or rpc.block(head["number"])["hash"] != head["hash"] \
                        or _pointer(rpc, addresses, finish["number"]) != pointer \
                        or rpc.block(finish["number"])["hash"] != finish["hash"]:
                    progress("confirmed state changed during sync; retrying from a fresh block")
                    continue
                generation = output / (str(head["number"]) + "-" + head["hash"][2:])
                if generation.is_symlink():
                    raise SyncError("linked sync generation refused")
                if generation.exists():
                    # Never replace module paths which an already-open store may be using.
                    existing = CurrentState.load(generation / "current-state.json")
                    if existing.document != document:
                        raise SyncError("existing immutable sync generation differs")
                    for profile in PROFILE_IDS:
                        if document["profiles"][profile]["exec"] == "candidate_module":
                            existing.candidate_bundle(profile)
                else:
                    os.rename(temporary, generation)
                _atomic_write(previous, _json_bytes({"block_number": head["number"],
                    "block_hash": head["hash"], "frontier_root": live_root}))
                progress("current modules verified; admission history was not replayed")
                return generation / "current-state.json"
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        raise SyncError("chain kept changing during sync; retry; previous modules remain intact")
