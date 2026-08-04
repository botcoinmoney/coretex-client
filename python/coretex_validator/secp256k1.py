# SPDX-License-Identifier: Apache-2.0
"""``ecrecover``, on the standard library.

WHY THIS EXISTS, AND WHY IT IS SMALL ON PURPOSE. Two checks in this package recover an Ethereum
address from a signature: the join's step 7 (``ecrecover(digest, signature) ==
mining.coordinatorSigner()``, RIG-CORETEX-REGISTRY-DESIGN.md §7.2) and the resolver-snapshot
transport check. Depending on ``eth-keys``/``coincurve`` for those would give the validator a
supply-chain root it does not otherwise have — see the package docstring. secp256k1 point
arithmetic over a 256-bit prime field is about 80 lines of integer arithmetic, so it lives here.

WHAT THIS IS NOT. It does not sign, it does not generate keys, and it is not constant-time. All
three are correct omissions: a validator only ever verifies, it never holds a secret, and there is
no secret here to leak through timing. If you are tempted to add signing, add it somewhere else.

MALLEABILITY IS REJECTED, NOT NORMALISED. ``s > n/2`` is refused rather than flipped. Both
readings recover a valid address, so silently accepting the high-``s`` form would let two distinct
signature encodings authenticate the same payload — the exact ambiguity EIP-2 removed. ``v`` is
accepted as 27/28 (and 0/1, which some signers emit) and nothing else.
"""
from __future__ import annotations

from typing import Tuple

from .keccak256 import keccak256

#: The secp256k1 field prime, curve order, and generator.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
#: EIP-2: any ``s`` above this is the malleable twin of a canonical signature.
HALF_N = N // 2


class SignatureError(ValueError):
    """A signature that cannot be recovered from. Always a refusal, never a fallback."""


def _inv(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _double(point):
    if point is None:
        return None
    x, y = point
    if y == 0:
        return None
    lam = (3 * x * x % P) * _inv(2 * y % P, P) % P
    nx = (lam * lam - 2 * x) % P
    return nx, (lam * (x - nx) - y) % P


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx:
        return _double(a) if (ay + by) % P == 0 else None if ay != by else _double(a)
    lam = (by - ay) * _inv((bx - ax) % P, P) % P
    nx = (lam * lam - ax - bx) % P
    return nx, (lam * (ax - nx) - ay) % P


def _mul(point, scalar: int):
    scalar %= N
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _double(addend)
        scalar >>= 1
    return result


def _decompress(x: int, odd: bool):
    """The curve point at ``x`` with the requested parity, or ``None`` if ``x`` is off-curve."""
    if not 0 < x < P:
        return None
    alpha = (pow(x, 3, P) + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)
    if pow(beta, 2, P) != alpha:                      # x is not on the curve at all
        return None
    y = beta if (beta & 1) == odd else P - beta
    return x, y


def split_signature(signature: bytes) -> Tuple[int, int, int]:
    """A 65-byte ``r ‖ s ‖ v`` signature, range-checked. Returns ``(r, s, recovery_id)``."""
    raw = bytes(signature)
    if len(raw) != 65:
        raise SignatureError(f"a signature is 65 bytes (r‖s‖v); this one is {len(raw)}")
    r = int.from_bytes(raw[0:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    if not 0 < r < N:
        raise SignatureError("r is not in [1, n)")
    if not 0 < s < N:
        raise SignatureError("s is not in [1, n)")
    if s > HALF_N:
        raise SignatureError(
            "s is above n/2: this is the EIP-2 malleable twin of a canonical signature. It is "
            "REFUSED rather than normalised, because accepting both encodings would let two "
            "distinct signatures authenticate one payload")
    if v in (27, 28):
        recovery = v - 27
    elif v in (0, 1):
        recovery = v
    else:
        raise SignatureError(f"v must be 27/28 (or 0/1); it is {v}")
    return r, s, recovery


def ecrecover(digest: bytes, signature: bytes) -> str:
    """The address that signed ``digest``, ``0x``-prefixed lowercase.

    ``digest`` is the 32 bytes actually signed — for EIP-712 that is the
    ``keccak256(0x1901 ‖ domainSeparator ‖ structHash)`` value, NOT the struct hash. Passing the
    wrong one recovers a valid-looking address for the wrong message, which is why the callers in
    this package build the digest through :func:`abi.eip712_digest` and never inline it.
    """
    if len(bytes(digest)) != 32:
        raise SignatureError("the signed digest must be exactly 32 bytes")
    r, s, recovery = split_signature(signature)
    point = _decompress(r, bool(recovery & 1))
    if point is None:
        raise SignatureError("r does not name a point on secp256k1; the signature is malformed")
    e = int.from_bytes(bytes(digest), "big") % N
    # Q = r^-1 (s·R - e·G)
    r_inv = _inv(r, N)
    q = _mul(_add(_mul(point, s), _mul((GX, GY), N - e)), r_inv)
    if q is None:
        raise SignatureError("signature recovery produced the point at infinity")
    uncompressed = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return "0x" + keccak256(uncompressed)[-20:].hex()


def addresses_equal(a: str, b: str) -> bool:
    """Address comparison that ignores EIP-55 casing. Never use ``==`` on addresses directly."""
    return str(a or "").lower() == str(b or "").lower()
