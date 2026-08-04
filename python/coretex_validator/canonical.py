# SPDX-License-Identifier: Apache-2.0
"""How a CHAIN value is spelled before it enters a canonical document.

THE CANONICALIZATION RULE IS NOT DEFINED HERE. It is :func:`frontier.canonical_bytes`, re-exported
below. This module adds no dialect — it only decides the SPELLING of a value that came off the
chain, which is a separate decision from how the resulting object is serialised, and conflating
the two is how two conforming implementations end up with different bytes for the same state.

TWO RENDERINGS, AND THE SPLIT IS LOAD-BEARING
---------------------------------------------
* **Solidity-boundary words** — ``bytes32``, ``address``, tx/block hashes, ABI ``bytes`` — render
  ``0x``-prefixed lowercase. That is what the chain itself uses and what every block explorer,
  ``cast`` invocation and ABI decoder hands a validator. Re-spelling them would make byte-for-byte
  reproduction depend on knowing a house convention, which is precisely the thing a public
  validator must not need.
* **Content-addressed roots** — sha256 over canonical bytes — render BARE lowercase 64-hex,
  because that is the one root rendering the frontier law uses (``frontier.check_root``).

A value that is BOTH — the rig lane puts a bare sha256 root into a ``bytes32``, so ``artifactHash``
IS a candidate release root and ``newStateRoot`` IS a frontier root — therefore appears in both
spellings, and :func:`root_from_word` is the ONLY sanctioned conversion. Crossing the boundary in
one named place lets a test pin the direction; crossing it inline means every call site invents its
own strip-and-hope.

This package previously rendered everything bare. That was not a decision, it was an artefact of
reusing ``dispatch._word``, which returns bare hex because the V5 memory lane's ``frontier`` roots
are bare. Corrected here.

WIDE INTEGERS MUST NOT NARROW
-----------------------------
``uint256`` and ``uint128`` values render as DECIMAL STRINGS. This is a CORRECTNESS FIX, not a
style preference. Python would serialise them exactly, but these bytes are consumed by a
TypeScript mirror and by anything else with IEEE-754 numbers, where ``2**53`` and ``2**53 + 1`` are
*the same double*. A snapshot whose bytes mean different things to two conforming readers is not
canonical.

The affected fields are real ones, not hypothetical: ``rigId``, ``improvementCredits``,
``workUnitsBps``, ``creditsEarned``, ``difficultyCountSnapshot`` (all ``uint256``) and
``worldSeed`` (``uint128``). :func:`wide` is the only way such a value enters a payload, and
:func:`narrow` REFUSES an integer that would need to be wide but was declared narrow — so the
failure mode is a refusal, never a silent rounding.
"""
from __future__ import annotations

import re
from typing import Any

from . import frontier as fr

#: THE rule. Re-exported, never re-implemented.
canonical_bytes = fr.canonical_bytes
sha256_hex = fr.sha256_hex

#: Quoted into a snapshot so a validator does not have to guess which rule produced the bytes.
CANONICAL_RULE_ID = "coretex_memory.release.canonical_manifest_bytes"

#: Above this an IEEE-754 double can no longer represent every integer exactly.
MAX_SAFE_INTEGER = 2 ** 53 - 1

_WORD_RE = re.compile(r"\A0x[0-9a-f]{64}\Z")
_ADDRESS_RE = re.compile(r"\A0x[0-9a-f]{40}\Z")
_HEXDATA_RE = re.compile(r"\A0x([0-9a-f]{2})*\Z")

ZERO_WORD = "0x" + "0" * 64
ZERO_ADDRESS = "0x" + "0" * 40


class CanonicalizationError(ValueError):
    """A value that cannot be spelled canonically. Always a refusal, never a coercion."""


def _refuse(message: str) -> CanonicalizationError:
    return CanonicalizationError(message)


def word(value: Any, field: str = "bytes32") -> str:
    """A 32-byte chain word as ``0x`` + 64 lowercase hex.

    Accepts 32 raw bytes or a hex string with or without the prefix. Refuses everything else —
    including a SHORT hex string that "obviously" means a left-padded value, because guessing the
    padding side is exactly how a root and a left-aligned label get confused.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != 32:
            raise _refuse(f"{field}: {len(raw)} bytes is not a 32-byte word")
        return "0x" + raw.hex()
    if not isinstance(value, str):
        raise _refuse(f"{field}: {type(value).__name__} is not a chain word")
    text = value.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    if not _WORD_RE.match(text):
        raise _refuse(f"{field}: {value!r} is not 32 bytes of hex")
    return text


def address(value: Any, field: str = "address") -> str:
    """A 20-byte address as ``0x`` + 40 lowercase hex.

    EIP-55 checksummed input is accepted and LOWERCASED: the casing is a checksum over the same 20
    bytes, so two spellings of one address must never produce two snapshots.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) == 32:                                  # a left-padded address word
            if raw[:12] != b"\x00" * 12:
                raise _refuse(f"{field}: 32-byte value has a dirty address padding")
            raw = raw[12:]
        if len(raw) != 20:
            raise _refuse(f"{field}: {len(raw)} bytes is not an address")
        return "0x" + raw.hex()
    if not isinstance(value, str):
        raise _refuse(f"{field}: {type(value).__name__} is not an address")
    text = value.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    if _WORD_RE.match(text):
        if text[2:26] != "0" * 24:
            raise _refuse(f"{field}: {value!r} is a 32-byte word with a dirty address padding")
        text = "0x" + text[26:]
    if not _ADDRESS_RE.match(text):
        raise _refuse(f"{field}: {value!r} is not 20 bytes of hex")
    return text


def hexdata(value: Any, field: str = "bytes") -> str:
    """Variable-length ABI ``bytes`` as ``0x`` + even-length lowercase hex (``0x`` when empty)."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "0x" + bytes(value).hex()
    if not isinstance(value, str):
        raise _refuse(f"{field}: {type(value).__name__} is not byte data")
    text = value.lower()
    if not text.startswith("0x"):
        text = "0x" + text
    if not _HEXDATA_RE.match(text):
        raise _refuse(f"{field}: {value!r} is not an even-length hex string")
    return text


def bare_root(value: Any, field: str = "root") -> str:
    """A content-addressed root: bare lowercase 64-hex, delegated to the frontier law.

    Deliberately NOT tolerant of a ``0x`` prefix. ``frontier.check_root`` refuses it, and this
    module must not be where the two spellings quietly become interchangeable.
    """
    try:
        return fr.check_root(value, field)
    except fr.FrontierError as exc:
        raise _refuse(str(exc)) from exc


def root_from_word(value: Any, field: str = "root") -> str:
    """The bare-root spelling of a chain word. The ONE sanctioned ``0x`` -> bare conversion."""
    return bare_root(word(value, field)[2:], field)


def word_from_root(value: Any, field: str = "root") -> str:
    """The chain-word spelling of a bare root. The inverse of :func:`root_from_word`."""
    return word(bare_root(value, field), field)


def wide(value: Any, field: str = "uint256") -> str:
    """A wide unsigned integer as an EXACT decimal string.

    Every ``uint256``/``uint128`` goes through here. Rendering one as a JSON number is correct in
    Python and lossy in any IEEE-754 reader, and a canonical document may not mean two things.
    """
    if isinstance(value, bool):
        raise _refuse(f"{field}: bool is not an unsigned integer")
    if isinstance(value, str):
        if not value.isdigit():
            raise _refuse(f"{field}: {value!r} is not a decimal integer string")
        value = int(value)
    if not isinstance(value, int):
        raise _refuse(f"{field}: {type(value).__name__} is not an integer")
    if value < 0:
        raise _refuse(f"{field}: {value} is negative")
    if value >= 2 ** 256:
        raise _refuse(f"{field}: {value} does not fit a uint256")
    return str(value)


def narrow(value: Any, field: str = "uint64", *, bits: int = 64) -> int:
    """A narrow unsigned integer as a JSON integer — REFUSED if it could not survive a double.

    ``uint64`` is the widest type the rig lane uses for epochs and indices, and in practice those
    values are tiny. "In practice" is not a guarantee, so the bound is checked: a ``uint64`` above
    ``2**53 - 1`` is refused rather than silently rendered as a number a JavaScript validator would
    read back as a different integer. The caller's fix is :func:`wide`.
    """
    if isinstance(value, bool):
        raise _refuse(f"{field}: bool is not an unsigned integer")
    if not isinstance(value, int):
        raise _refuse(f"{field}: {type(value).__name__} is not an integer")
    if value < 0:
        raise _refuse(f"{field}: {value} is negative")
    if value >= 2 ** bits:
        raise _refuse(f"{field}: {value} does not fit a uint{bits}")
    if value > MAX_SAFE_INTEGER:
        raise _refuse(
            f"{field}: {value} exceeds 2**53-1 and cannot be rendered as a JSON number without "
            "risking a narrowing in an IEEE-754 reader; render it with wide() instead")
    return value


def canonical_rule_record() -> dict:
    """What a snapshot states about its own serialisation, so a validator need not guess."""
    return {
        "rule_id": CANONICAL_RULE_ID,
        "json": "UTF-8, keys sorted by code point, no insignificant whitespace",
        "floats": "refused",
        "null": "refused — a field is present with a well-typed value or absent",
        "chain_words": "0x-prefixed lowercase hex (bytes32, address, tx/block hashes, ABI bytes)",
        "content_roots": "bare lowercase 64-hex sha256",
        "wide_integers": "uint256/uint128 as exact decimal STRINGS (IEEE-754 safety)",
        "narrow_integers": "uint64 and below as JSON numbers, refused above 2**53-1",
    }
