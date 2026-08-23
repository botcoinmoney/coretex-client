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
``law_publication`` component whose note names the publication root and whose files are the
publication manifest (``LAW-PUBLICATION.json``) plus one tar per code root. Setup downloads them
under their kit-declared sha256s, arranges them as a local ``flat-cas`` mirror — the manifest
under the PUBLICATION ROOT's name, each object under its own, which is the layout
:func:`law.sync_law` addresses — and then runs the ordinary sync against that directory.

THIS ADDS NO VERIFICATION PATH AND WEAKENS NONE. ``sync_law`` re-derives every address from the
bytes that arrived: the manifest must hash to the root, each container to the digest the manifest
binds, and each extracted tree to the tree-hash root its own name is. The kit's sha256s are a
transport check on top of that, never a substitute for it, and a coordinator's word about which
root is live is a POINTER — the trees still have to reproduce it.

Three outcomes, deliberately not two: installed; NOT OFFERED (an older coordinator has no such
component) which reports a remedy and still succeeds; and OFFERED-AND-WRONG, which fails loudly.
Bytes that disagree with their address are never a soft "law unavailable".
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tarfile
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional

from . import law as law_mod
from .rpc import DEFAULT_USER_AGENT

DEFAULT_RPC = "https://mainnet.base.org"
DEFAULT_COORDINATOR = "https://coordinator.agentmoney.net"
DEFAULT_PACKAGES_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
    "coretex", "packages")


def default_packages_dir() -> str:
    return DEFAULT_PACKAGES_DIR


def kit_components(manifest: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """The kit's component list, from either a wrapped or a bare manifest. Never raises."""
    kit = manifest.get("kit", manifest) if isinstance(manifest, Mapping) else None
    components = kit.get("components") if isinstance(kit, Mapping) else None
    if not isinstance(components, list):
        return []
    return [c for c in components if isinstance(c, Mapping)]


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
    already installed this package, and the live kit wheel is an older 0.4.0 pin. The law
    publication's own files are addressed by root and handled by :func:`law_publication_files`.
    """
    out: List[Dict[str, str]] = []
    seen = set()
    for component in kit_components(manifest):
        for item in component_files(component):
            if item["sha256"] in seen:
                continue
            interesting = (
                (item["name"].startswith("coretex-validator-miner-kit-")
                 and item["name"].endswith(".tar"))
                or item["name"] == "FROZEN-RUNTIME-PACKET.json"
            )
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
    return json.loads(_fetch(url, timeout=timeout, limit=2 * 1024 * 1024))


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


def _extract_tar(archive: str, dest: str) -> None:
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        kwargs: Dict[str, Any] = {}
        if hasattr(tarfile, "data_filter"):
            kwargs["filter"] = "data"
        tar.extractall(dest, **kwargs)


def maybe_extract_tars(files: List[Mapping[str, Any]], dest_dir: str) -> List[str]:
    extracted = []
    for item in files:
        path = str(item.get("local_path") or "")
        if not path.endswith(".tar"):
            continue
        out = os.path.join(dest_dir, os.path.splitext(os.path.basename(path))[0])
        marker = os.path.join(out, ".extracted")
        if os.path.isfile(marker):
            extracted.append(out)
            continue
        _extract_tar(path, out)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(item.get("sha256") or "")
        extracted.append(out)
    return extracted


# --------------------------------------------------------------------------- #
# the admission law, discovered from the kit
# --------------------------------------------------------------------------- #
#: The kit component that publishes the admission law, and the manifest file inside it.
LAW_PUBLICATION_COMPONENT_ID = "law_publication"
LAW_PUBLICATION_MANIFEST_NAME = "LAW-PUBLICATION.json"

#: A bare lowercase sha256, not touching another hex digit on either side. Used to read the
#: publication root out of a free-text note without depending on how the note is worded.
_ROOT_IN_TEXT = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{64}(?![0-9a-fA-F])")

_LAW_REMEDY = ("Install it explicitly instead: `coretex-validator sync-law --mirror URL --root "
               "ROOT`. Deterministic admission BACKLOGs until then, which is the honest outcome "
               "and not a broken install")


class LawNotPublished(Exception):
    """This kit does not offer a law publication this client can ADDRESS.

    Deliberately not a verification failure. An older coordinator carries no ``law_publication``
    component at all, and a component whose note names no address — or two — cannot be resolved to
    one publication without guessing. Both are facts about the coordinator, so setup reports them
    and succeeds. Bytes that disagree with an address are a different matter entirely and are
    raised by :func:`law.sync_law`, which nothing here catches.
    """


def law_publication_component(manifest: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """The kit's ``law_publication`` component, or ``None`` if this coordinator publishes none."""
    for component in kit_components(manifest):
        if str(component.get("id") or "") == LAW_PUBLICATION_COMPONENT_ID:
            return component
    return None


def law_publication_root(component: Mapping[str, Any]) -> str:
    """The publication root the component names. Parsed defensively; never guessed.

    An explicit ``publicationRoot`` / ``publication_root`` field wins when a coordinator sends
    one. Otherwise the free-text ``note`` is scanned for bare sha256 addresses and must yield
    EXACTLY ONE: a note naming none has not told us what to install, and a note naming several has
    not told us which — and picking one would make the installed law a function of word order.
    """
    for field in ("publicationRoot", "publication_root"):
        explicit = component.get(field)
        if explicit is None:
            continue
        if not law_mod.is_root(explicit):
            raise LawNotPublished(
                f"the kit's {LAW_PUBLICATION_COMPONENT_ID} component names {field}="
                f"{explicit!r}, which is not a bare sha256")
        return str(explicit)
    note = str(component.get("note") or "")
    found = sorted(set(_ROOT_IN_TEXT.findall(note)))
    if not found:
        raise LawNotPublished(
            f"the kit's {LAW_PUBLICATION_COMPONENT_ID} component names no publication root: its "
            f"note is {note!r} and it carries no publicationRoot field")
    if len(found) > 1:
        raise LawNotPublished(
            f"the kit's {LAW_PUBLICATION_COMPONENT_ID} note names {len(found)} addresses "
            f"({found}); which one is the publication root is not something this client will "
            "guess at")
    return found[0]


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
        return {"synced": False,
                "reason": (f"this coordinator's kit carries no {LAW_PUBLICATION_COMPONENT_ID} "
                           "component, so it does not publish which admission law its chain head "
                           "binds. " + _LAW_REMEDY)}
    try:
        publication_root = law_publication_root(component)
    except LawNotPublished as exc:
        return {"synced": False, "reason": f"{exc}. " + _LAW_REMEDY}

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
        "next": "coretex-validator verify-release --rpc " + rpc_url,
    }
