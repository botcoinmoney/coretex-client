# SPDX-License-Identifier: UNLICENSED
"""Keccak-256 (the ETHEREUM hash), pure stdlib, for the V5 eval-artifact bindings.

WHY THIS EXISTS. V5-C must check two values that are computed ON-CHAIN with ``keccak256``:

  * ``CoreTexMemoryMining.transitionHash`` — the 22nd signed receipt field,
    ``keccak256(abi.encodePacked(TRANSITION_HASH_DOMAIN_LABEL, transitionBytes))``, which binds
    the broadcast manifest-edit bytes to the coordinator's EIP-712 signature;
  * ``CoreTexMemoryMining.epochCommit[epoch]`` — ``keccak256(abi.encodePacked(bytes32 secret))``,
    the commitment the revealed epoch entropy secret must open.

The V5-A law's cardinal property is that **a validator needs nothing but the stdlib** to
reproduce a mine. Depending on ``pycryptodome``/``eth-hash`` for those two checks would break
that, so the ~60 lines of Keccak-f[1600] live here instead.

**This is NOT SHA3-256.** ``hashlib.sha3_256`` uses the NIST FIPS-202 domain-padding byte
``0x06``; the pre-standard Keccak that Ethereum froze uses ``0x01``. They differ for every input,
including the empty string. Known-answer vectors are asserted in
``tests/test_keccak256.py``; :func:`self_test` runs them on demand.
"""
from __future__ import annotations

_MASK = (1 << 64) - 1

#: Keccak-f[1600] iota round constants (24 rounds).
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

#: rho rotation offsets, indexed ``[x][y]``.
_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

#: keccak256 => 1600-bit state, 256-bit capacity*2 => rate 1088 bits = 136 bytes.
RATE_BYTES = 136
DIGEST_BYTES = 32
#: The ORIGINAL Keccak padding byte. FIPS-202 SHA3 uses 0x06 — see the module docstring.
PAD_BYTE = 0x01


def _rol(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _keccak_f1600(a: list) -> list:
    for rnd in range(24):
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROTATION[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _MASK) & b[(x + 2) % 5][y])
        # iota
        a[0][0] ^= _ROUND_CONSTANTS[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    """Keccak-256 digest of ``data`` (32 bytes). Ethereum's ``keccak256``."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"keccak256 takes bytes, got {type(data).__name__}")
    data = bytes(data)

    # pad10*1 with the ORIGINAL Keccak domain byte
    padded = bytearray(data)
    padded.append(PAD_BYTE)
    while len(padded) % RATE_BYTES != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), RATE_BYTES):
        block = padded[offset:offset + RATE_BYTES]
        for i in range(RATE_BYTES // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    while len(out) < DIGEST_BYTES:                     # one squeeze suffices at rate 136
        for i in range(RATE_BYTES // 8):
            out += state[i % 5][i // 5].to_bytes(8, "little")
            if len(out) >= DIGEST_BYTES:
                break
        if len(out) < DIGEST_BYTES:                    # pragma: no cover - unreachable at 136/32
            _keccak_f1600(state)
    return bytes(out[:DIGEST_BYTES])


def keccak256_hex(data: bytes) -> str:
    """Bare lowercase 64-char hex Keccak-256 — the rendering every V5 root uses."""
    return keccak256(data).hex()


#: (input, expected hex) PUBLISHED Ethereum known-answer vectors — independent of this code.
#: Together they exercise the full permutation, the 0x01 domain padding and the squeeze.
KNOWN_ANSWERS = (
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"hello", "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"),
)

#: REGRESSION vectors (multi-block: an exactly-rate-sized and an over-rate input, both of which
#: absorb two blocks). These were produced BY this implementation after the published vectors
#: above validated it, so they lock behaviour across the rate boundary — they are not an
#: independent attestation, and are labelled separately for that reason.
REGRESSION_ANSWERS = (
    (b"a" * RATE_BYTES, "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"),
    (b"x" * 200, "3c3800defb6a25a70a2737e0716eeb5d270559ad3cad8f6abddac58802d7158e"),
)


def self_test() -> bool:
    """Run every vector. Raises ``AssertionError`` on any mismatch."""
    for data, expected in KNOWN_ANSWERS + REGRESSION_ANSWERS:
        got = keccak256_hex(data)
        assert got == expected, f"keccak256({data!r}) = {got}, expected {expected}"
    return True
