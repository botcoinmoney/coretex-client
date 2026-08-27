# SPDX-License-Identifier: Apache-2.0
"""Current rig wire constants, loaded from the release-derived language-neutral sidecar."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RIG-WIRE-BINDING.v1.json")
_AUTHORITY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "RIG-CONTRACT-AUTHORITY.base-mainnet.json")


def _reject_duplicates(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            raise RuntimeError(f"duplicate JSON key {key!r}")
        value[key] = member
    return value


def _json(raw: bytes, where: str) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                RuntimeError(f"non-finite JSON value {token!r}")))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"{where} is not duplicate-free UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{where} must contain one JSON object")
    return value


def _load() -> dict:
    with open(_PATH, "rb") as handle:
        raw = handle.read()
    value = _json(raw, "RIG-WIRE-BINDING.v1.json")
    if not isinstance(value, dict) or set(value) != {
            "authority", "authoritySha256", "descriptor", "format", "limits", "mining",
            "receipt", "registry", "verifier"}:
        raise RuntimeError("RIG-WIRE-BINDING.v1.json has another or open schema")
    if value["format"] != "coretex.rig-wire-binding/v1":
        raise RuntimeError("RIG-WIRE-BINDING.v1.json has another format")
    with open(_AUTHORITY_PATH, "rb") as handle:
        authority_raw = handle.read()
    if hashlib.sha256(authority_raw).hexdigest() != value["authoritySha256"]:
        raise RuntimeError("rig wire sidecar does not reproduce authoritySha256")
    authority = _json(authority_raw, "RIG-CONTRACT-AUTHORITY.base-mainnet.json")
    projection = value["authority"]
    if projection.get("chainId") != authority.get("chain_id") \
            or projection.get("deploymentBlock") != authority.get("deployment_block") \
            or projection.get("contracts") != authority.get("contracts") \
            or projection.get("codeHashes") != authority.get("code_hashes"):
        raise RuntimeError("rig wire sidecar disagrees with the embedded contract authority")
    return value


_BINDING = _load()
RIG_BINDING_AUTHORITY_SHA256 = _BINDING["authoritySha256"]
RIG_CONTRACT_AUTHORITY = _BINDING["authority"]

_RECEIPT = _BINDING["receipt"]
CORETEX_RECEIPT_TUPLE_COMPONENTS: List[Dict[str, str]] = list(_RECEIPT["tupleComponents"])
CORETEX_RECEIPT_TUPLE_TYPES: List[str] = list(_RECEIPT["tupleTypes"])
CORETEX_RECEIPT_PRIMARY_TYPE = _RECEIPT["primaryType"]
CORETEX_RECEIPT_TYPES: Dict[str, List[Dict[str, str]]] = {
    CORETEX_RECEIPT_PRIMARY_TYPE: list(_RECEIPT["signedFields"]),
}
CORETEX_RECEIPT_TYPEHASH = _RECEIPT["typehash"]
SUBMIT_CORETEX_RECEIPT_SELECTOR = _RECEIPT["submitSelector"]
SUBMIT_CORETEX_RECEIPT_FRAGMENT = _RECEIPT["submitFragment"]
EIP712_DOMAIN_NAME = _RECEIPT["eip712"]["name"]
EIP712_DOMAIN_VERSION = _RECEIPT["eip712"]["version"]

TRANSITION_DESCRIPTOR_BYTES = int(_BINDING["descriptor"]["bytes"])
TRANSITION_DESCRIPTOR_VERSION = int(_BINDING["descriptor"]["version"])

if [field["type"] for field in CORETEX_RECEIPT_TUPLE_COMPONENTS] \
        != CORETEX_RECEIPT_TUPLE_TYPES:
    raise RuntimeError("rig wire tuple components and tuple types disagree")
if CORETEX_RECEIPT_TUPLE_COMPONENTS[-2:] != [
        {"name": "compactPatchBytes", "type": "bytes"},
        {"name": "signature", "type": "bytes"}]:
    raise RuntimeError("rig receipt does not end in its two unsigned byte tails")

__all__ = [
    "CORETEX_RECEIPT_PRIMARY_TYPE", "CORETEX_RECEIPT_TUPLE_COMPONENTS",
    "CORETEX_RECEIPT_TUPLE_TYPES", "CORETEX_RECEIPT_TYPEHASH", "CORETEX_RECEIPT_TYPES",
    "EIP712_DOMAIN_NAME", "EIP712_DOMAIN_VERSION", "RIG_BINDING_AUTHORITY_SHA256",
    "RIG_CONTRACT_AUTHORITY", "SUBMIT_CORETEX_RECEIPT_FRAGMENT",
    "SUBMIT_CORETEX_RECEIPT_SELECTOR", "TRANSITION_DESCRIPTOR_BYTES",
    "TRANSITION_DESCRIPTOR_VERSION",
]
