# SPDX-License-Identifier: Apache-2.0
"""One-command public setup: verify the live deployment, cache kit packages, INSTALL THE LAW.

The retired npm client (``coretex-client-setup``) hydrated V4 launch artifacts from the v16 S3
prefix. This is the V5 rig validator. Packages come from the coordinator kit
(``GET /coretex/v5/kit/file/<sha256>``), the public content-addressed store (S3-backed). Chain
state is read from Base, not from that store.

This command does not install the kit's validator wheel over the package already on PATH.

THE ADMISSION LAW, AND WHY IT IS DISCOVERED RATHER THAN PASTED
==============================================================
Setup used to end with ``law.synced: false`` and a paragraph asking the operator to obtain a
publication root by some unspecified means and run ``sync-law`` with it. The root decides WHICH
law gets installed, so leaving it to a paste is exactly where a rehearsal publication ends up
pinned on a live host — which is what the removed ``DEFAULT_PUBLICATION_ROOT`` did.

The root is a property of the deployment, so the coordinator publishes it: the kit carries a
``law_publication`` component whose explicit ``publicationRoot`` names the publication and whose files are the
publication manifest (``LAW-PUBLICATION.json``) plus one tar per code root. Setup downloads them
under their kit-declared sha256s, arranges them as a local ``flat-cas`` mirror — the manifest
under the PUBLICATION ROOT's name, each object under its own, which is the layout
:func:`law.sync_law` addresses — and then runs the ordinary sync against that directory.

THIS ADDS NO VERIFICATION PATH AND WEAKENS NONE. ``sync_law`` re-derives every address from the
bytes that arrived: the manifest must hash to the root, each container to the digest the manifest
binds, and each extracted tree to the tree-hash root its own name is. The kit's sha256s are a
transport check on top of that, never a substitute for it, and a coordinator's word about which
root is live is a POINTER — the trees still have to reproduce it.

A normal setup has one outcome: the current miner-kit and current law are both verified and one
closed tuple is activated atomically.  ``--skip-packages`` and ``--skip-law`` remain explicit
diagnostic escape hatches, but an incomplete public kit is not a successful current install.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import PurePosixPath
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional

from . import law as law_mod
from . import frontier as fr
from .rpc import DEFAULT_USER_AGENT

DEFAULT_RPC = "https://mainnet.base.org"
DEFAULT_COORDINATOR = "https://coordinator.agentmoney.net"
DEFAULT_PACKAGES_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
    "coretex", "packages")
KIT_MANIFEST_FORMAT = "coretex.memory-frontier.v1/kit-manifest"
CURRENT_MINER_KIT_COMPONENT_ID = "current_miner_kit"
KIT_TAR_PREFIX = "coretex-validator-miner-kit-"
KIT_EXTRACTION_FORMAT = "coretex-validator.kit-extraction/v1"
KIT_EXTRACTION_MARKER = ".extracted"
MAX_KIT_MEMBERS = 20_000
MAX_KIT_EXTRACTED_BYTES = 512 * 1024 * 1024
REQUIRED_CURRENT_KIT_FILES = (
    "benchmark-v2/kit/self_check.py",
    "benchmark-v2/kit/dev_instances.py",
    "benchmark-v2/integration/portability_matrix.py",
)


def default_packages_dir() -> str:
    return DEFAULT_PACKAGES_DIR


def kit_components(manifest: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """The kit's component list, from either a wrapped or a bare manifest. Never raises."""
    kit = manifest.get("kit", manifest) if isinstance(manifest, Mapping) else None
    components = kit.get("components") if isinstance(kit, Mapping) else None
    if not isinstance(components, list):
        return []
    return [c for c in components if isinstance(c, Mapping)]


def _canonical_kit_manifest_body(kit: Mapping[str, Any]) -> Dict[str, Any]:
    """The exact subset hashed by ``coretex-memory-v5-kit.ts``.

    Download URLs, notes, timestamps and host paths are deliberately absent: the coordinator's
    manifest hash commits to the component/file inventory, and this mirrors that inventory byte for
    byte instead of trusting the hash string it arrived beside.
    """
    if kit.get("format") != KIT_MANIFEST_FORMAT:
        raise RuntimeError(
            f"kit.format must be the current {KIT_MANIFEST_FORMAT!r}, got {kit.get('format')!r}")
    raw_components = kit.get("components")
    if not isinstance(raw_components, list) or not raw_components:
        raise RuntimeError("kit.components must be a non-empty array")
    components: List[Dict[str, Any]] = []
    ids = set()
    for index, component in enumerate(raw_components):
        if not isinstance(component, Mapping):
            raise RuntimeError(f"kit.components[{index}] must be an object")
        component_id = component.get("id")
        if not isinstance(component_id, str) or not component_id or component_id in ids:
            raise RuntimeError(f"kit.components[{index}].id is absent or duplicated")
        ids.add(component_id)
        present = component.get("present")
        files = component.get("files")
        missing = component.get("missing")
        if not isinstance(present, bool) or not isinstance(files, list) \
                or not isinstance(missing, list) or not all(isinstance(v, str) for v in missing):
            raise RuntimeError(
                f"kit component {component_id!r} needs boolean present and array files/missing")
        canonical_files: List[Dict[str, Any]] = []
        for file_index, item in enumerate(files):
            if not isinstance(item, Mapping):
                raise RuntimeError(f"kit component {component_id!r} file {file_index} is not an object")
            path, sha, size = item.get("path"), item.get("sha256"), item.get("bytes")
            if not isinstance(path, str) or not path or path.startswith(("/", "\\")):
                raise RuntimeError(f"kit component {component_id!r} has an invalid file path")
            if sha is not None and (not isinstance(sha, str) or not law_mod.is_root(sha)):
                raise RuntimeError(f"kit file {path!r} has an invalid sha256")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise RuntimeError(f"kit file {path!r} has an invalid byte length")
            canonical_files.append({"path": path, "sha256": sha or "", "bytes": size})
        components.append({"id": component_id, "present": present,
                           "files": canonical_files, "missing": list(missing)})
    return {"format": KIT_MANIFEST_FORMAT, "components": components}


def _miner_kit_candidates(manifest: Mapping[str, Any]) -> List[Dict[str, str]]:
    components = [component for component in kit_components(manifest)
                  if component.get("id") == CURRENT_MINER_KIT_COMPONENT_ID]
    if len(components) != 1 or components[0].get("present") is not True:
        raise RuntimeError(
            f"the current kit must publish exactly one present {CURRENT_MINER_KIT_COMPONENT_ID} "
            f"component, found {len(components)}")
    raw_files = components[0].get("files")
    candidates = component_files(components[0])
    if not isinstance(raw_files, list) or len(raw_files) != 1 or len(candidates) != 1:
        raise RuntimeError(
            f"{CURRENT_MINER_KIT_COMPONENT_ID} must contain exactly one addressed tar, found "
            f"{len(candidates)} files")
    item = candidates[0]
    name = item["name"]
    expected_name = f"{KIT_TAR_PREFIX}{item['sha256']}.tar"
    if name != expected_name:
        raise RuntimeError(
            f"current miner-kit filename {name!r} must embed its full sha256 as {expected_name!r}")
    return candidates


def current_miner_kit_file(manifest: Mapping[str, Any]) -> Dict[str, str]:
    """The ONE current miner-kit tar. There is no ordered fallback among prior tarballs."""
    candidates = _miner_kit_candidates(manifest)
    if len(candidates) != 1:
        raise RuntimeError(
            f"the current kit must publish exactly one miner-kit tar, found {len(candidates)}")
    return candidates[0]


def validate_kit_manifest_envelope(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate the current public envelope and independently recompute ``manifestHash``."""
    if not isinstance(manifest, Mapping) or manifest.get("ok") is not True:
        raise RuntimeError("kit manifest response must be an ok:true object")
    kit = manifest.get("kit")
    if not isinstance(kit, Mapping):
        raise RuntimeError("kit manifest response has no kit object")
    body = _canonical_kit_manifest_body(kit)
    observed = hashlib.sha256(fr.canonical_bytes(body)).hexdigest()
    claimed = kit.get("manifestHash")
    if claimed != observed:
        raise RuntimeError(f"kit.manifestHash is {claimed!r}, recomputed {observed}")
    production = manifest.get("productionRelease")
    if not isinstance(production, Mapping):
        raise RuntimeError("the current kit envelope has no productionRelease object")
    if production.get("kitManifestHash") != observed:
        raise RuntimeError("productionRelease.kitManifestHash does not bind this kit manifest")
    # These are the two pieces a canonical install needs. Merely parsing the rest of the inventory
    # must never turn an old/partial coordinator into a successful current install.
    current_miner_kit_file(manifest)
    law_components = [c for c in kit_components(manifest)
                      if c.get("id") == LAW_PUBLICATION_COMPONENT_ID]
    if len(law_components) != 1 or law_components[0].get("present") is not True:
        raise RuntimeError("the current kit must publish exactly one present law_publication component")
    law_publication_root(law_components[0])
    return kit


def component_files(component: Mapping[str, Any]) -> List[Dict[str, str]]:
    """The downloadable files of one component, normalized. Entries with no sha are dropped."""
    out: List[Dict[str, str]] = []
    for item in component.get("files") or []:
        if not isinstance(item, Mapping):
            continue
        sha = str(item.get("sha256") or "")
        if not sha:
            continue
        path = str(item.get("path") or "")
        out.append({
            "path": path, "name": os.path.basename(path.replace("\\", "/")), "sha256": sha,
            "download": str(item.get("download") or ""),
            "encoding": str(item.get("downloadEncoding") or "raw-bytes"),
        })
    return out


def kit_package_files(manifest: Mapping[str, Any]) -> List[Dict[str, str]]:
    """The miner-kit tar and frozen-runtime-packet identity from a kit manifest.

    The kit also carries a ``coretex_validator`` wheel. Setup does not download it: the operator
    already installed this package. The law
    publication's own files are addressed by root and handled by :func:`law_publication_files`.
    """
    current = current_miner_kit_file(manifest)
    out: List[Dict[str, str]] = [current]
    seen = {current["sha256"]}
    for component in kit_components(manifest):
        for item in component_files(component):
            if item["sha256"] in seen:
                continue
            interesting = item["name"] == "FROZEN-RUNTIME-PACKET.json"
            if not interesting:
                continue
            seen.add(item["sha256"])
            out.append(item)
    return out


def _urljoin(coordinator: str, download: str) -> str:
    if download.startswith("http://") or download.startswith("https://"):
        return download
    return urllib.parse.urljoin(coordinator.rstrip("/") + "/", download.lstrip("/"))


def _fetch(url: str, *, timeout: float, limit: int) -> bytes:
    req = urllib.request.Request(url, headers={"user-agent": DEFAULT_USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"{url} exceeded {limit} bytes")
    return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unwrap_kit_bytes(raw: bytes, encoding: str) -> bytes:
    if encoding != "json-envelope-base64":
        return raw
    document = json.loads(raw.decode("utf-8"))
    payload = document.get("data") if isinstance(document, Mapping) else None
    if not isinstance(payload, str):
        raise RuntimeError("kit json envelope has no data field")
    return base64.b64decode(payload)


def fetch_kit_manifest(coordinator: str, *, timeout: float = 60.0) -> Dict[str, Any]:
    """``GET /coretex/v5/kit/manifest``, parsed. The one document setup discovers everything from."""
    url = _urljoin(coordinator, "/coretex/v5/kit/manifest")
    document = json.loads(_fetch(url, timeout=timeout, limit=2 * 1024 * 1024))
    validate_kit_manifest_envelope(document)
    return document


def download_kit_file(coordinator: str, item: Mapping[str, Any], target: str, *,
                      timeout: float = 60.0,
                      max_file_bytes: int = 64 * 1024 * 1024) -> Dict[str, Any]:
    """One kit file, to ``target``, CHECKED against the sha256 the kit named and written atomically.

    A file already on disk under the named hash is reused rather than refetched — and the hash is
    what decides that, never the file name, so a stale file with the right name is replaced.
    """
    if os.path.isfile(target):
        with open(target, "rb") as fh:
            if _sha256(fh.read()) == item["sha256"]:
                return {**item, "status": "cached", "local_path": target}
    url = _urljoin(coordinator, item["download"])
    raw = _fetch(url, timeout=timeout, limit=max_file_bytes)
    payload = _unwrap_kit_bytes(raw, item.get("encoding") or "raw-bytes")
    digest = _sha256(payload)
    if digest != item["sha256"]:
        raise RuntimeError(f"{item['name']} hashed to {digest}, kit named {item['sha256']}")
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    tmp = target + ".part"
    with open(tmp, "wb") as fh:
        fh.write(payload)
    os.replace(tmp, target)
    return {**item, "status": "downloaded", "local_path": target, "bytes": len(payload)}


def fetch_kit_packages(
    coordinator: str,
    *,
    dest_dir: str,
    timeout: float = 60.0,
    max_file_bytes: int = 64 * 1024 * 1024,
    manifest: Optional[Mapping[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Download miner-kit / runtime-packet files into dest_dir. Matching hashes are skipped."""
    os.makedirs(dest_dir, exist_ok=True)
    if manifest is None:
        manifest = fetch_kit_manifest(coordinator, timeout=timeout)
    return [download_kit_file(coordinator, item, os.path.join(dest_dir, item["name"]),
                              timeout=timeout, max_file_bytes=max_file_bytes)
            for item in kit_package_files(manifest)]


def extraction_tree_sha256(root: str) -> str:
    """Hash every regular extracted file, refusing links/devices and excluding only the marker."""
    lines: List[bytes] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        for dirname in dirnames:
            path = os.path.join(dirpath, dirname)
            if os.path.islink(path):
                raise RuntimeError(f"extracted kit contains symlink directory {path}")
        for filename in filenames:
            if filename == KIT_EXTRACTION_MARKER and os.path.abspath(dirpath) == os.path.abspath(root):
                continue
            path = os.path.join(dirpath, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                raise RuntimeError(f"extracted kit contains a non-regular file {path}")
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            lines.append(rel.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
    return hashlib.sha256(b"".join(sorted(lines))).hexdigest()


def validate_current_miner_kit_tree(root: str) -> None:
    """The explicit current kit is runnable support, not merely a correctly hashed tar."""
    missing = [relpath for relpath in REQUIRED_CURRENT_KIT_FILES
               if not os.path.isfile(os.path.join(root, *relpath.split("/")))]
    if missing:
        raise RuntimeError(
            "the current miner-kit is missing required support files: " + ", ".join(missing))


def _extract_tar(archive: str, dest: str) -> None:
    """Extract only ordinary files/directories, including on Python versions without filters."""
    os.makedirs(dest, exist_ok=True)
    seen = set()
    total = 0
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        if len(members) > MAX_KIT_MEMBERS:
            raise RuntimeError(f"miner-kit tar has {len(members)} members, limit {MAX_KIT_MEMBERS}")
        for member in members:
            raw = member.name
            parts = PurePosixPath(raw).parts
            if (not raw or raw.startswith(("/", "\\")) or "\\" in raw
                    or any(part in ("", ".", "..") for part in parts)
                    or raw in seen or not (member.isdir() or member.isreg())):
                raise RuntimeError(f"unsafe tar member {raw!r}: only unique relative files/dirs are allowed")
            seen.add(raw)
            total += int(member.size or 0)
            if total > MAX_KIT_EXTRACTED_BYTES:
                raise RuntimeError(
                    f"miner-kit tar expands beyond {MAX_KIT_EXTRACTED_BYTES} bytes")
            target = os.path.join(dest, *parts)
            if member.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            source = tar.extractfile(member)
            if source is None:  # pragma: no cover - tarfile invariant for regular files
                raise RuntimeError(f"unsafe tar member {raw!r}: regular file has no payload")
            with source, open(target, "wb") as output:
                shutil.copyfileobj(source, output)
            os.chmod(target, member.mode & 0o755 or 0o600)


def maybe_extract_tars(files: List[Mapping[str, Any]], dest_dir: str) -> List[str]:
    extracted = []
    for item in files:
        path = str(item.get("local_path") or "")
        if not path.endswith(".tar"):
            continue
        expected = str(item.get("sha256") or "")
        if not law_mod.is_root(expected):
            raise RuntimeError(f"tar {path} has no valid expected sha256")
        with open(path, "rb") as handle:
            actual = hashlib.sha256(handle.read()).hexdigest()
        if actual != expected:
            raise RuntimeError(f"tar {path} hashes to {actual}, kit named {expected}")
        out = os.path.join(dest_dir, os.path.splitext(os.path.basename(path))[0])
        marker = os.path.join(out, ".extracted")
        if os.path.isfile(marker):
            try:
                with open(marker, "r", encoding="utf-8") as fh:
                    recorded = json.load(fh)
                tree = extraction_tree_sha256(out)
                if (recorded.get("format") == KIT_EXTRACTION_FORMAT
                        and recorded.get("archive_sha256") == expected
                        and recorded.get("tree_sha256") == tree):
                    extracted.append(out)
                    continue
            except (OSError, ValueError, RuntimeError, AttributeError):
                pass
        os.makedirs(dest_dir, exist_ok=True)
        staging = tempfile.mkdtemp(prefix=".kit-incomplete-", dir=dest_dir)
        retired = None
        try:
            _extract_tar(path, staging)
            tree = extraction_tree_sha256(staging)
            with open(os.path.join(staging, KIT_EXTRACTION_MARKER), "w", encoding="utf-8") as fh:
                json.dump({"format": KIT_EXTRACTION_FORMAT, "archive_sha256": expected,
                           "tree_sha256": tree}, fh, sort_keys=True, separators=(",", ":"))
                fh.write("\n")
            if os.path.exists(out):
                retired = out + f".retired-{os.getpid()}"
                if os.path.exists(retired):
                    shutil.rmtree(retired)
                os.replace(out, retired)
            os.replace(staging, out)
            staging = ""
            if retired:
                shutil.rmtree(retired)
        except Exception:
            if retired and not os.path.exists(out) and os.path.exists(retired):
                os.replace(retired, out)
            raise
        finally:
            if staging:
                shutil.rmtree(staging, ignore_errors=True)
        extracted.append(out)
    return extracted


# --------------------------------------------------------------------------- #
# the admission law, discovered from the kit
# --------------------------------------------------------------------------- #
#: The kit component that publishes the admission law, and the manifest file inside it.
LAW_PUBLICATION_COMPONENT_ID = "law_publication"
LAW_PUBLICATION_MANIFEST_NAME = "LAW-PUBLICATION.json"

_LAW_REMEDY = ("Run `coretex-validator setup` without --skip-law to verify and activate the one "
               "current kit/law tuple. Deterministic admission BACKLOGs without an active tuple")


def law_publication_component(manifest: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """The kit's ``law_publication`` component, or ``None`` if this coordinator publishes none."""
    for component in kit_components(manifest):
        if str(component.get("id") or "") == LAW_PUBLICATION_COMPONENT_ID:
            return component
    return None


def law_publication_root(component: Mapping[str, Any]) -> str:
    """The explicit current publication root. Free-text notes are never an authority."""
    explicit = component.get("publicationRoot")
    if not law_mod.is_root(explicit):
        raise RuntimeError(
            f"the current {LAW_PUBLICATION_COMPONENT_ID} component must carry an explicit "
            f"valid publicationRoot, got {explicit!r}")
    return str(explicit)


def mirror_law_publication(coordinator: str, component: Mapping[str, Any],
                           publication_root: str, *, dest_dir: str, timeout: float = 60.0,
                           max_file_bytes: int = 64 * 1024 * 1024) -> Dict[str, Any]:
    """Download the component's files into a local ``flat-cas`` mirror and return where it is.

    THE NAMING IS THE LAYOUT (``law.LAYOUTS`` → ``flat-cas``: ``manifest: "{root}"``,
    ``object: "{root}"``). So ``LAW-PUBLICATION.json`` is written under the PUBLICATION ROOT's
    name — that is the address ``law._locate_manifest`` asks for — and every root-named file under
    its own name. Anything else the component ships (a README, an index) is NOT mirrored: it has
    no address, so nothing could check it, and unaddressed files in a law mirror are precisely
    what the tree-hash rule refuses to let into a cache.
    """
    law_mod.check_root(publication_root, "publication root")
    dest = os.path.abspath(os.path.expanduser(dest_dir))
    os.makedirs(dest, exist_ok=True)
    mirrored: List[Dict[str, Any]] = []
    skipped: List[str] = []
    manifest_seen = False
    for item in component_files(component):
        name = item["name"]
        if name == LAW_PUBLICATION_MANIFEST_NAME:
            local, manifest_seen = publication_root, True
        elif law_mod.is_root(name):
            local = name
        else:
            skipped.append(name)
            continue
        mirrored.append(download_kit_file(coordinator, item, os.path.join(dest, local),
                                          timeout=timeout, max_file_bytes=max_file_bytes))
    if not manifest_seen:
        raise RuntimeError(
            f"the kit's {LAW_PUBLICATION_COMPONENT_ID} component ships no "
            f"{LAW_PUBLICATION_MANIFEST_NAME}, so there is nothing to check publication "
            f"{publication_root} against. Refused rather than treated as 'no law published': the "
            "component IS there, and a publication set without its manifest is broken, not absent")
    return {"dir": dest, "files": mirrored, "not_mirrored": sorted(skipped)}


def sync_law_from_kit(coordinator: str, manifest: Mapping[str, Any], *, packages_dir: str,
                      cache_dir: Optional[str] = None, timeout: float = 60.0,
                      max_file_bytes: int = 64 * 1024 * 1024, skip_law: bool = False,
                      force: bool = False) -> Dict[str, Any]:
    """Discover, mirror and VERIFY the published admission law. The ``law`` block of the report.

    Verification is entirely :func:`law.sync_law`'s and is not repeated, weakened or wrapped here:
    it re-derives the manifest's address, every container digest and every TREE hash from the
    bytes that arrived, refuses a set missing any required tree, and installs atomically or not at
    all. Its refusals PROPAGATE — a law that does not reproduce its address must fail the command.
    """
    if skip_law:
        return {"synced": False,
                "reason": "--skip-law: the admission law was not fetched. " + _LAW_REMEDY}
    component = law_publication_component(manifest)
    if component is None:
        raise RuntimeError(
            f"the current kit carries no {LAW_PUBLICATION_COMPONENT_ID} component; a canonical "
            "install requires both the current miner-kit and its law publication")
    publication_root = law_publication_root(component)

    mirror = mirror_law_publication(
        coordinator, component, publication_root,
        dest_dir=os.path.join(os.path.expanduser(packages_dir), "law-publication",
                              publication_root),
        timeout=timeout, max_file_bytes=max_file_bytes)
    cache = law_mod.sync_law(publication_root, mirror=mirror["dir"], cache_dir=cache_dir,
                             force=force, max_object_bytes=max_file_bytes)
    return {
        "synced": True,
        "publicationRoot": publication_root,
        "trees": dict(cache.receipt["trees"]),
        # The seventh sealed root is a FILE, not a tree (D-3): `receipt.py::code_roots` hashes
        # `v5/production/CANDIDATE-ISOLATION.production.json` directly, so it is installed and
        # reported beside the six trees rather than folded into them.
        "files": dict(cache.files),
        "cache_dir": cache.root_dir,
        "mirror_dir": mirror["dir"],
        "env": cache.env(),
        "source": (f"the coordinator kit's {LAW_PUBLICATION_COMPONENT_ID} component; every "
                   "address was re-derived from the bytes that arrived"),
    }


def _fmt_root(raw: str) -> str:
    text = raw.strip()
    if text.startswith("0x") or text.startswith("0X"):
        return "0x" + text[2:].lower()
    return "0x" + text.lower()


def run(
    *,
    rpc_url: str = DEFAULT_RPC,
    coordinator: str = DEFAULT_COORDINATOR,
    release: Optional[str] = None,
    confirmation_depth: int = 15,
    packages_dir: Optional[str] = None,
    skip_packages: bool = False,
    skip_law: bool = False,
    law_cache: Optional[str] = None,
) -> Dict[str, Any]:
    from . import release as rel
    from .rpc import JsonRpc, RigViews

    packages_dir = os.path.expanduser(packages_dir or default_packages_dir())
    parsed = rel.discover(release)
    rpc = JsonRpc(rpc_url)
    rpc.assert_chain(parsed.chain_id)
    block = int(parsed.observation_block or rpc.confirmed_head(confirmation_depth))
    verification = rel.verify_deployment(parsed, rpc, block=block)
    views = RigViews(rpc, parsed.deployment, block=block)
    epoch = views.current_epoch()
    has_context = views.epoch_has_context(epoch)
    live_root = _fmt_root(views.live_state_root(epoch)) if has_context else None
    transition_count = views.transition_count(epoch)

    packages: List[Dict[str, Any]] = []
    extracted: List[str] = []
    kit_manifest: Optional[Dict[str, Any]] = None
    if not (skip_packages and skip_law):
        kit_manifest = fetch_kit_manifest(coordinator)
    if not skip_packages:
        packages = fetch_kit_packages(coordinator, dest_dir=packages_dir, manifest=kit_manifest)
        extracted = maybe_extract_tars(packages, packages_dir)
    law_block = sync_law_from_kit(coordinator, kit_manifest or {}, packages_dir=packages_dir,
                                  cache_dir=law_cache, skip_law=skip_law)

    active_install = None
    if not skip_packages and not skip_law:
        assert kit_manifest is not None                 # fetched and envelope-validated above
        miner = current_miner_kit_file(kit_manifest)
        matching = [item for item in packages
                    if item.get("sha256") == miner["sha256"]
                    and item.get("name") == miner["name"]]
        if len(matching) != 1:
            raise RuntimeError("the verified current miner-kit was not downloaded exactly once")
        archive_path = str(matching[0].get("local_path") or "")
        if not archive_path or not os.path.isfile(archive_path):
            raise RuntimeError("the verified current miner-kit archive is absent after download")
        extraction = os.path.join(
            packages_dir, os.path.splitext(os.path.basename(archive_path))[0])
        if extraction not in extracted:
            raise RuntimeError("the verified current miner-kit was not extracted")
        marker_path = os.path.join(extraction, KIT_EXTRACTION_MARKER)
        try:
            with open(marker_path, "r", encoding="utf-8") as handle:
                marker = json.load(handle)
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"the current miner-kit extraction receipt is unreadable: {exc}") \
                from exc
        tree_sha = extraction_tree_sha256(extraction)
        validate_current_miner_kit_tree(extraction)
        if (not isinstance(marker, Mapping)
                or marker.get("format") != KIT_EXTRACTION_FORMAT
                or marker.get("archive_sha256") != miner["sha256"]
                or marker.get("tree_sha256") != tree_sha):
            raise RuntimeError("the current miner-kit extraction does not match its receipt")
        active_install = law_mod.write_active_install(
            cache_dir=law_cache, publication_root=law_block["publicationRoot"],
            kit_manifest_hash=str(kit_manifest["kit"]["manifestHash"]),
            miner_kit_sha256=miner["sha256"], miner_kit_filename=miner["name"],
            miner_kit_tree_sha256=tree_sha)

    return {
        "ok": bool(verification.ok),
        "rpc": rpc_url,
        "coordinator": coordinator.rstrip("/"),
        "packages_dir": packages_dir,
        "release": {
            "classification": parsed.classification,
            "chain_id": parsed.chain_id,
            "addresses": parsed.addresses,
        },
        "deployment": verification.as_dict(),
        "chain": {
            "block": block,
            "epoch": epoch,
            "epoch_has_context": has_context,
            "live_state_root": live_root,
            "transition_count": transition_count,
        },
        "packages": [{k: v for k, v in item.items() if k != "download"} for item in packages],
        "extracted": extracted,
        "law": law_block,
        "active_install": active_install,
        "next": "coretex-validator verify-release --rpc " + rpc_url,
    }
