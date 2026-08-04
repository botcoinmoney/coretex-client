# SPDX-License-Identifier: UNLICENSED
"""The minimum Solidity ABI encoding V5-G needs, over this lane's own stdlib Keccak.

DELIBERATELY NOT A LIBRARY. Cut V5-G must produce (a) the EIP-712 digest the deployed
``CoreTexMemoryMining`` will recompute in Solidity and (b) the calldata for four function calls.
Pulling in ``eth-abi``/``web3`` for that would put a third-party encoder between the proof and the
contract; if the encoder and the contract disagreed, the test would fail for the wrong reason.
Everything here is 4 word-sized primitives plus one dynamic ``bytes`` tail, checked against the
CHAIN itself: :func:`e2e.receipt.domain_separator` reads the domain separator back out of the
deployed contract rather than deriving it, and the contract re-derives the struct hash, so a bug
in this file shows up as ``InvalidSignature`` and never as a false pass.

``keccak256`` is ``v5/keccak256.py`` — the same stdlib implementation the eval-artifact bindings
already use (NOT ``hashlib.sha3_256``; see that module for why they differ).
"""
from __future__ import annotations

import os
import sys
from typing import Any, Iterable


from .keccak256 import keccak256

WORD = 32


class AbiError(ValueError):
    """A value does not fit the Solidity type it is being encoded as."""


def as_bytes32(value: Any, field: str = "bytes32") -> bytes:
    """Accept bare hex, ``0x``-hex or 32 raw bytes; refuse everything else."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        text = value[2:] if value[:2] in ("0x", "0X") else value
        if len(text) != 64:
            raise AbiError(f"{field}: expected 64 hex chars, got {len(text)}")
        try:
            raw = bytes.fromhex(text)
        except ValueError as exc:
            raise AbiError(f"{field}: not hex ({exc})") from exc
    else:
        raise AbiError(f"{field}: must be hex or bytes, got {type(value).__name__}")
    if len(raw) != WORD:
        raise AbiError(f"{field}: must be exactly 32 bytes, got {len(raw)}")
    return raw


def as_address(value: str, field: str = "address") -> bytes:
    text = value[2:] if value[:2] in ("0x", "0X") else value
    if len(text) != 40:
        raise AbiError(f"{field}: expected a 20-byte address, got {value!r}")
    return bytes(12) + bytes.fromhex(text.lower())


def as_uint(value: int, *, bits: int = 256, field: str = "uint") -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AbiError(f"{field}: must be an int, got {type(value).__name__}")
    if value < 0 or value >= (1 << bits):
        raise AbiError(f"{field}={value} does not fit uint{bits}")
    return value.to_bytes(WORD, "big")


def as_bool(value: bool, field: str = "bool") -> bytes:
    if not isinstance(value, bool):
        raise AbiError(f"{field}: must be a bool")
    return (1 if value else 0).to_bytes(WORD, "big")


def pad_bytes(payload: bytes) -> bytes:
    """The canonical dynamic ``bytes`` tail: length word, payload, zero padding to a word."""
    padded = (len(payload) + WORD - 1) // WORD * WORD
    return len(payload).to_bytes(WORD, "big") + payload + bytes(padded - len(payload))


def selector(signature: str) -> bytes:
    return keccak256(signature.encode("utf-8"))[:4]


def type_hash(signature: str) -> bytes:
    return keccak256(signature.encode("utf-8"))


def encode_static(words: Iterable[bytes]) -> bytes:
    out = b""
    for word in words:
        if len(word) != WORD:
            raise AbiError(f"static word must be 32 bytes, got {len(word)}")
        out += word
    return out


def eip712_digest(domain_separator: bytes, struct_hash: bytes) -> bytes:
    """``keccak256(0x19 0x01 ++ domainSeparator ++ structHash)`` — EIP-712 §"encode"."""
    return keccak256(b"\x19\x01" + as_bytes32(domain_separator, "domainSeparator")
                     + as_bytes32(struct_hash, "structHash"))


def hex0x(raw: bytes) -> str:
    return "0x" + raw.hex()


def addresses_equal(a: str, b: str) -> bool:
    """Case-insensitive address comparison. NEVER use ``==`` on addresses directly.

    It lives in this module — pure encoding, no curve arithmetic — rather than beside
    ``ecrecover``, on purpose. Comparing two addresses is not a cryptographic operation, and
    putting it in :mod:`.secp256k1` would drag the curve code onto every path that merely needed
    to check whether two strings name the same account. The snapshot REPRODUCTION path is exactly
    such a path and must stay key-free and curve-free (see :mod:`.snapshot`).
    """
    return str(a or "").lower() == str(b or "").lower()
