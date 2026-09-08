# SPDX-License-Identifier: Apache-2.0
"""Closed consumer state format, distinct from the sealed validator's audit snapshot.

The sealed adapter's bounded module/provenance reader is reused without inventing
empty audit evidence or changing its original snapshot parser.
"""
from __future__ import annotations

from pathlib import Path

from coretex_memory_agent.authority import (
    CurrentReleaseAuthority, CandidateBinding, AuthorityError, PROFILE_IDS,
    _sha256, _read,
)
from coretex_memory_agent.snapshot import (
    ResolverSnapshot, SnapshotError, ADDRESS_RE, _closed, _root, _integer,
    _block_hash, _safe_bundle_path,
)

CURRENT_STATE_FORMAT = "coretex.current-state/v1"


class CurrentState(ResolverSnapshot):
    @property
    def is_chain_pointer(self):
        return True

    @classmethod
    def parse(cls, value, *, base_dir=None):
        document = _closed(value, ("chain", "deployment", "epoch", "format", "frontier",
                                  "profiles", "provenance", "release_root", "version"),
                           "consumer current state")
        if document["format"] != CURRENT_STATE_FORMAT or type(document["version"]) is not int \
                or document["version"] != 1:
            raise SnapshotError("unsupported consumer current-state format")
        provenance = _closed(document["provenance"], ("mode", "admission_replayed"), "provenance")
        if provenance["mode"] != "chain-pointer" or provenance["admission_replayed"] is not False:
            raise SnapshotError("current state is chain-pointer authority, not replay evidence")
        _root(document["release_root"], "release root")
        chain = _closed(document["chain"], ("chain_id", "observation"), "chain")
        _integer(chain["chain_id"], "chain id", minimum=1)
        observed = _closed(chain["observation"],
                          ("block_hash", "block_number", "confirmation_depth"), "observation")
        _block_hash(observed["block_hash"], "observation block hash")
        _integer(observed["block_number"], "observation block", minimum=1)
        _integer(observed["confirmation_depth"], "confirmation depth", minimum=1)
        deployment = _closed(document["deployment"], ("mining", "registry", "verifier"), "deployment")
        for address in deployment.values():
            if not isinstance(address, str) or ADDRESS_RE.fullmatch(address) is None:
                raise SnapshotError("deployment address is malformed")
        epoch = _closed(document["epoch"], ("id", "context", "live_state_root"), "epoch")
        _integer(epoch["id"], "epoch id", minimum=1)
        _root(epoch["live_state_root"], "live state root")
        context = _closed(epoch["context"],
                         ("core_version_hash", "epoch_context_root", "parent_state_root"), "context")
        for key, root in context.items():
            _root(root, key)
        frontier = _closed(document["frontier"], ("manifest", "root"), "frontier")
        _root(frontier["root"], "frontier root")
        manifest = _closed(frontier["manifest"], ("benchmark_law_root", "default_composition_root",
            "epoch", "format", "parent_frontier_root", "profiles", "runtime_abi_root"), "frontier manifest")
        if manifest["format"] != "coretex.memory-frontier.v1":
            raise SnapshotError("unsupported frontier format")
        _integer(manifest["epoch"], "frontier epoch")
        if manifest["epoch"] > epoch["id"]:
            raise SnapshotError("frontier is from a later epoch")
        for field in ("benchmark_law_root", "default_composition_root", "parent_frontier_root", "runtime_abi_root"):
            _root(manifest[field], field)
        _closed(manifest["profiles"], PROFILE_IDS, "frontier profiles")
        if _sha256(manifest) != frontier["root"] or frontier["root"] != epoch["live_state_root"]:
            raise SnapshotError("frontier bytes/root differ from chain pointer")
        _closed(document["profiles"], PROFILE_IDS, "profiles")
        for profile in PROFILE_IDS:
            row = document["profiles"][profile]
            if not isinstance(row, dict):
                raise SnapshotError("profile must be an object")
            _root(manifest["profiles"][profile], "profile root")
            if row.get("release_root") != manifest["profiles"][profile]:
                raise SnapshotError("profile release differs from frontier")
            if row.get("exec") == "reference":
                _closed(row, ("exec", "release_root"), "reference profile")
                continue
            _closed(row, ("exec", "release_root", "candidate_hash", "bundle", "provenance"), "module profile")
            if row["exec"] != "candidate_module":
                raise SnapshotError("unsupported profile execution")
            _root(row["candidate_hash"], "candidate hash")
            bundle = _closed(row["bundle"], ("directory", "manifest", "manifest_sha256", "manifest_size",
                                            "module", "module_sha256", "module_size"), "bundle")
            _safe_bundle_path(bundle["directory"], f"bundles/{profile}", "bundle directory")
            for key, filename in (("manifest", "manifest.json"), ("module", "module.py")):
                _safe_bundle_path(bundle[key], filename, key)
                _root(bundle[key + "_sha256"], key + " hash")
                _integer(bundle[key + "_size"], key + " size", minimum=1)
            provenance = _closed(row["provenance"], ("composition", "composition_root",
                "composition_sha256", "composition_size"), "module provenance")
            _safe_bundle_path(provenance["composition"], f"provenance/{profile}.composition.json", "composition")
            _root(provenance["composition_root"], "composition root")
            _root(provenance["composition_sha256"], "composition hash")
            _integer(provenance["composition_size"], "composition size", minimum=1)
            if provenance["composition_root"] != manifest["default_composition_root"]:
                raise SnapshotError("profile provenance differs from frontier composition")
        return cls(dict(document), None if base_dir is None else Path(base_dir).resolve())


def authority_from_current(release_dir, snapshot):
    """Rehash a saved current-state closure, without claiming fresh RPC or admission replay."""
    parsed = snapshot if isinstance(snapshot, CurrentState) else CurrentState.parse(snapshot)
    base = CurrentReleaseAuthority.load(release_dir, expected_release_root=parsed.release_root)
    contract = _read(Path(release_dir) / base.release["objects"]["rig_contract_authority_root"]["path"],
                     "contract authority")
    if parsed.document["chain"]["chain_id"] != contract["chain_id"]:
        raise AuthorityError("consumer state has another chain id")
    for key, name in (("mining", "mining"), ("registry", "coretex_registry"), ("verifier", "coretex_verifier")):
        if parsed.document["deployment"][key].lower() != contract["contracts"][name].lower():
            raise AuthorityError("consumer state has another contract deployment")
    front = parsed.document["frontier"]["manifest"]
    if front["benchmark_law_root"] != base.release["law"]["benchmark_law_root"] \
            or front["runtime_abi_root"] != base.release["objects"]["miner_module_abi_root"]["root"] \
            or parsed.document["epoch"]["context"]["core_version_hash"] != base.compatibility_lock_root:
        raise AuthorityError("consumer state has another law, runtime ABI or compatibility lock")
    bindings = {}
    for profile in PROFILE_IDS:
        row = parsed.document["profiles"][profile]
        if row["exec"] == "reference":
            genesis = base.composition.binding(profile)
            if genesis.exec != "reference" or genesis.release_root != row["release_root"]:
                raise AuthorityError("consumer reference slot is not the release's reference")
            bindings[profile] = genesis
        else:
            bundle = parsed.candidate_bundle(profile)
            bindings[profile] = CandidateBinding(profile, row["release_root"], bundle.candidate_hash,
                bundle.directory, bundle.manifest, bundle.module_sha256)
    return CurrentReleaseAuthority(release_root=base.release_root,
        compatibility_lock_root=base.compatibility_lock_root, release=base.release,
        compatibility_lock=base.compatibility_lock, composition=base.composition,
        bindings=bindings, frontier_root=parsed.frontier_root, retrieval=base._retrieval)
