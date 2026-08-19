# SPDX-License-Identifier: Apache-2.0
"""One-command public setup: verify the live deployment, cache kit packages, read chain head.

The retired npm client (``coretex-client-setup``) hydrated V4 launch artifacts from the v16 S3
prefix. This is the V5 rig validator. Packages come from the coordinator kit
(``GET /coretex/v5/kit/file/<sha256>``), the public content-addressed store (S3-backed). Chain
state is read from Base, not from that store.

This command does not install the kit's validator wheel over the package already on PATH, and it
does not fetch the rehearsal publication root. Admission-law trees are ``sync-law`` with an
explicit live ``--root``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tarfile
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional

from .rpc import DEFAULT_USER_AGENT

DEFAULT_RPC = "https://mainnet.base.org"
DEFAULT_COORDINATOR = "https://coordinator.agentmoney.net"
DEFAULT_PACKAGES_DIR = os.path.join(
    os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
    "coretex", "packages")


def default_packages_dir() -> str:
    return DEFAULT_PACKAGES_DIR


def kit_package_files(manifest: Mapping[str, Any]) -> List[Dict[str, str]]:
    """The miner-kit tar and frozen-runtime-packet identity from a kit manifest.

    The kit also carries a ``coretex_validator`` wheel. Setup does not download it: the operator
    already installed this package, and the live kit wheel is an older 0.4.0 pin.
    """
    kit = manifest.get("kit", manifest)
    components = kit.get("components") if isinstance(kit, Mapping) else None
    if not isinstance(components, list):
        return []
    out: List[Dict[str, str]] = []
    seen = set()
    for component in components:
        if not isinstance(component, Mapping):
            continue
        for item in component.get("files") or []:
            if not isinstance(item, Mapping):
                continue
            path = str(item.get("path") or "")
            sha = str(item.get("sha256") or "")
            download = str(item.get("download") or "")
            encoding = str(item.get("downloadEncoding") or "raw-bytes")
            name = os.path.basename(path.replace("\\", "/"))
            if not sha or sha in seen:
                continue
            interesting = (
                (name.startswith("coretex-validator-miner-kit-") and name.endswith(".tar"))
                or name == "FROZEN-RUNTIME-PACKET.json"
            )
            if not interesting:
                continue
            seen.add(sha)
            out.append({
                "path": path, "name": name, "sha256": sha,
                "download": download, "encoding": encoding,
            })
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


def fetch_kit_packages(
    coordinator: str,
    *,
    dest_dir: str,
    timeout: float = 60.0,
    max_file_bytes: int = 64 * 1024 * 1024,
) -> List[Dict[str, Any]]:
    """Download miner-kit / runtime-packet files into dest_dir. Matching hashes are skipped."""
    os.makedirs(dest_dir, exist_ok=True)
    manifest_url = _urljoin(coordinator, "/coretex/v5/kit/manifest")
    manifest = json.loads(_fetch(manifest_url, timeout=timeout, limit=2 * 1024 * 1024))
    results = []
    for item in kit_package_files(manifest):
        target = os.path.join(dest_dir, item["name"])
        if os.path.isfile(target):
            with open(target, "rb") as fh:
                existing = _sha256(fh.read())
            if existing == item["sha256"]:
                results.append({**item, "status": "cached", "local_path": target})
                continue
        url = _urljoin(coordinator, item["download"])
        raw = _fetch(url, timeout=timeout, limit=max_file_bytes)
        payload = _unwrap_kit_bytes(raw, item["encoding"])
        digest = _sha256(payload)
        if digest != item["sha256"]:
            raise RuntimeError(
                f"{item['name']} hashed to {digest}, kit named {item['sha256']}")
        tmp = target + ".part"
        with open(tmp, "wb") as fh:
            fh.write(payload)
        os.replace(tmp, target)
        results.append({**item, "status": "downloaded", "local_path": target,
                        "bytes": len(payload)})
    return results


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
    if not skip_packages:
        packages = fetch_kit_packages(coordinator, dest_dir=packages_dir)
        extracted = maybe_extract_tars(packages, packages_dir)

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
        "law": {
            "synced": False,
            "reason": ("setup does not fetch admission-law trees. Pass an explicit live "
                       "publication root to `coretex-validator sync-law --mirror "
                       f"{coordinator.rstrip('/')} --root ROOT` — the baked-in default root is "
                       "a 2026-08-04 rehearsal, not this chain head"),
        },
        "next": "coretex-validator verify-release --rpc " + rpc_url,
    }
