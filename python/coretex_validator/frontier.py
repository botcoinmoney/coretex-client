# SPDX-License-Identifier: Apache-2.0
"""Reference implementation of ``coretex.memory-frontier.v1`` (Cut V5-A, ledger §17.236).

The normative text is ``v5/spec/MEMORY-FRONTIER-V1.md``; this module is the executable form of
it. Scope is deliberately narrow: **state + transition law only**. Nothing here signs, fetches,
touches a chain, reads a socket, or knows what a Wasm bundle is. Every public function is pure
and total: it either returns a value derived solely from its arguments, or raises a typed
:class:`FrontierError`. There is no silent coercion anywhere — no lower-casing, no
``0x``-stripping, no int/float widening, no "absent means null".

Canonicalization is NOT a new dialect. It is *literally* the rule the shipped runtime already
uses for signed release manifests
(``coretex_memory.release.canonical_manifest_bytes``)::

    json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

The one difference is scope, not rule: the runtime excludes the two attestation fields
(``manifest_self_sha256`` / ``operator_signature``) from the body because a document cannot hash
or sign itself. A frontier manifest carries NEITHER field — its attestation is the on-chain root
and the coordinator receipt — so the canonical body is the whole document and the rule applies
unchanged. ``tests/test_canonicalization.py`` asserts byte-identity against the runtime function
itself when the runtime source tree is importable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

# --------------------------------------------------------------------------- #
# Identity constants
# --------------------------------------------------------------------------- #
#: The frontier manifest artifact family. The version lives in the id (house convention:
#: ``benchmark-v2/frontier-state/v1``, ``benchmark-v2/g8-deployment-signed/v1``, ...).
MANIFEST_FORMAT = "coretex.memory-frontier.v1"

#: The transition-edit artifact family — the payload of ``CoreTexMemoryFrontierAdvanced``.
TRANSITION_FORMAT = "coretex.memory-frontier-transition.v1"

#: The epoch-finalization record family (see :func:`finalize_epoch`).
FINALIZATION_FORMAT = "coretex.memory-frontier.v1/epoch-finalization"

#: The composition artifact a ``default_composition_root`` / ``resulting_composition_root``
#: MUST address. This is the EXISTING signed family already in production use
#: (``coretex_memory_agent.routing.DEPLOYMENT_MANIFEST_FORMAT``) — V5 does not mint a new one.
COMPOSITION_ARTIFACT_FORMAT = "benchmark-v2/g8-deployment-signed/v1"

#: Committed-evidence families the genesis derivation reads.
G8_PROMOTION_FORMAT = "benchmark-v2/g8-default-promotion/v1"
FRONTIER_STATE_FORMAT = "benchmark-v2/frontier-state/v1"

#: The CLOSED set of frontier profile ids, in their normative TOTAL ORDER (see the spec §3).
#: The order is the byte order of the UTF-8 id strings; for this all-ASCII set that coincides
#: exactly with what ``json.dumps(..., sort_keys=True)`` emits, so the canonical serializer
#: realizes the normative order with no separate ordering pass.
PROFILE_IDS: Tuple[str, ...] = ("conv.pref.v1", "doc.tool.v1", "event.schema.v1")

#: The frozen legacy profile. It is served by the LAW §7 baseline incumbent and is NOT mineable,
#: so it is NOT a frontier profile: it is covered by the composition artifact addressed by
#: ``default_composition_root``. Named here only so the genesis cross-check can assert it stayed
#: on the baseline.
LEGACY_PROFILE_ID = "legacy.structured.v1"
LEGACY_BASELINE_INCUMBENT = "C4"

#: Required top-level manifest fields. The schema is CLOSED: an unknown field is an error.
MANIFEST_FIELDS: Tuple[str, ...] = (
    "benchmark_law_root", "default_composition_root", "epoch", "format",
    "parent_frontier_root", "profiles", "runtime_abi_root",
)

#: Historical production genesis carries this lock copy, while children produced under an
#: explicitly verified epoch context retire it in favour of the on-chain ``coreVersionHash``.
#: It is optional so both immutable historical roots and the prospective seven-field child shape
#: remain addressable under one decoder; every other unknown field is still refused.
MANIFEST_OPTIONAL_FIELDS: Tuple[str, ...] = ("compatibility_lock_root",)

#: Required transition fields (CLOSED).
TRANSITION_FIELDS: Tuple[str, ...] = (
    "expected_prior_release_root", "format", "new_release_root",
    "resulting_composition_root", "target_profile",
)

#: A root is 64 LOWERCASE hex characters, bare (no ``0x``). See spec §4.
ROOT_RE = re.compile(r"\A[0-9a-f]{64}\Z")
ROOT_HEX_LEN = 64

#: The reserved parent of the genesis manifest — the ONLY manifest permitted to carry it.
ZERO_ROOT = "0" * ROOT_HEX_LEN

#: Hard upper bound on ``transitionBytes``. The exact maximum over the closed profile set is
#: 364 bytes (:func:`max_transition_bytes`); the enforced bound is rounded up to 384 so a future
#: same-shape profile id has room without a law change. V5-B MUST mirror this bound on-chain.
MAX_TRANSITION_BYTES = 384

#: Manifest epochs are unsigned and fit a uint64 (the on-chain mapping key type).
MAX_EPOCH = 2 ** 63 - 1

#: Guard against pathological / cyclic inputs to the canonicalizer.
_MAX_DEPTH = 32


# --------------------------------------------------------------------------- #
# Typed errors — one class per fail-closed reason, never a bare ValueError
# --------------------------------------------------------------------------- #
class FrontierError(Exception):
    """Base class for every frontier-law failure."""


class CanonicalizationError(FrontierError):
    """A value cannot be canonically serialized: ``null``, a float (incl. NaN/Inf), a non-string
    object key, an unsupported type, or a structure deeper than the depth guard."""


class FrontierSchemaError(FrontierError):
    """A document is not a well-formed member of its family: wrong/absent ``format``, a missing
    required field, or an unknown (closed-schema) field."""


class FrontierTypeError(FrontierError):
    """A field is present but has the wrong type (including an explicit ``null``, and including
    ``bool`` where an integer is required — ``bool`` is a Python ``int`` subclass)."""


class FrontierValueError(FrontierError):
    """A field has the right type but an illegal value: a malformed root (bad length, non-hex,
    UPPERCASE, ``0x``-prefixed), an out-of-range epoch, a reserved sentinel used illegally."""


class UnknownProfileError(FrontierError):
    """A profile id outside the CLOSED set for this manifest version (case-sensitive)."""


class DuplicateKeyError(FrontierError):
    """A JSON object carried the same key twice. Python dicts silently keep the last value, so
    this can only be caught while PARSING — see :func:`parse_json`."""


class TransitionSizeError(FrontierError):
    """Canonical transition bytes exceeded :data:`MAX_TRANSITION_BYTES`."""


class StaleParentError(FrontierError):
    """``expected_prior_release_root`` does not match the parent manifest's release root for the
    target profile — the candidate was built against a superseded frontier."""


class NoOpTransitionError(FrontierError):
    """``new_release_root == expected_prior_release_root``: the transition advances nothing."""


class CompositionUnchangedError(FrontierError):
    """``resulting_composition_root`` equals the parent's ``default_composition_root`` while a
    profile's release root changed — the served delegation would not follow the frontier."""


class RootMismatchError(FrontierError):
    """A claimed new frontier root does not equal the recomputed one."""


class EpochRegressionError(FrontierError):
    """A transition named an epoch EARLIER than the parent manifest's own epoch.

    Epochs only ever move forward (spec §8). A child in an earlier epoch than its parent would
    make the manifest chain non-monotonic in the one field the on-chain mapping key agrees with,
    and would let an epoch-N binding be replayed into a closed epoch.
    """


class GenesisEvidenceError(FrontierError):
    """The committed promotion evidence is missing, unpromoted, or self-inconsistent."""


# --------------------------------------------------------------------------- #
# Canonical serialization (spec §2)
# --------------------------------------------------------------------------- #
def _check_value(value: Any, path: str, depth: int) -> None:
    """Fail closed on anything the canonical value grammar does not admit."""
    if depth > _MAX_DEPTH:
        raise CanonicalizationError(f"{path}: structure deeper than {_MAX_DEPTH} levels")
    if value is None:
        raise CanonicalizationError(
            f"{path}: null is not a canonical value — a field is either PRESENT with a "
            "well-typed value or absent-and-invalid; the two are distinct errors, never equal")
    if isinstance(value, bool):
        return                                   # true/false are fine as data
    if isinstance(value, int):
        return                                   # arbitrary-precision int → exact JSON integer
    if isinstance(value, float):
        raise CanonicalizationError(
            f"{path}: floats are not canonical values (NaN/Infinity are not JSON at all and "
            "1 vs 1.0 would serialize differently) — use an integer or a string")
    if isinstance(value, str):
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_value(item, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(
                    f"{path}: object key {key!r} is not a string (JSON has no other key type; "
                    "coercing it would make two distinct documents share one root)")
            _check_value(item, f"{path}.{key}", depth + 1)
        return
    raise CanonicalizationError(f"{path}: value of type {type(value).__name__} is not canonical")


def canonical_bytes(document: Mapping[str, Any]) -> bytes:
    """The canonical bytes of ``document``.

    THE RULE (identical to ``coretex_memory.release.canonical_manifest_bytes``):

      * JSON, UTF-8 encoded;
      * object keys sorted ascending by Unicode code point (``sort_keys=True``); for the ASCII
        identifiers this law uses that is byte order;
      * compact separators ``(",", ":")`` — no insignificant whitespace;
      * ``ensure_ascii=True`` — every non-ASCII character escaped, so the bytes are identical on
        any platform and any locale;
      * ARRAYS KEEP THEIR ORDER (order is data, never normalized);
      * integers serialize in exact integer form; floats are REJECTED, so NaN/Infinity — which
        ``json`` would happily emit as non-JSON tokens — are unreachable;
      * ``null`` is REJECTED outright: the grammar has no null, so "absent" and "explicitly
        null" can never collapse to the same bytes.

    Fails closed with :class:`CanonicalizationError`; never emits partial output.
    """
    if not isinstance(document, dict):
        raise CanonicalizationError(
            f"canonical document must be a JSON object, got {type(document).__name__}")
    _check_value(document, "$", 0)
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Bare lowercase 64-char hex sha256 — the ONE root rendering this law uses."""
    return hashlib.sha256(data).hexdigest()


def _reject_duplicates(pairs):
    seen = set()
    for key, _value in pairs:
        if key in seen:
            raise DuplicateKeyError(
                f"duplicate JSON object key {key!r}: a Python dict would silently keep the last "
                "value, so two different documents would share one root — refused")
        seen.add(key)
    return dict(pairs)


def parse_json(text: str) -> Any:
    """Parse JSON text, REFUSING duplicate object keys (``json`` keeps the last silently).

    Every frontier document that arrives as bytes/text — from a peer, an artifact store, or a
    chain event — must come through here, not through bare ``json.loads``.
    """
    if not isinstance(text, str):
        raise FrontierTypeError(f"parse_json takes str, got {type(text).__name__}")
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicates)
    except DuplicateKeyError:
        raise
    except ValueError as exc:
        raise FrontierSchemaError(f"not valid JSON: {exc}") from exc


# --------------------------------------------------------------------------- #
# Field validators
# --------------------------------------------------------------------------- #
def check_root(value: Any, field: str) -> str:
    """Validate a root/hash field: exactly 64 LOWERCASE hex characters, no ``0x`` prefix.

    Case is REJECTED, never normalized (spec §4): normalizing would let two distinct byte
    strings address one root, and content-addressing then stops being a function of the bytes a
    validator actually fetched.
    """
    if value is None:
        raise FrontierTypeError(f"{field} is null; a root must be present and well-formed")
    if not isinstance(value, str):
        raise FrontierTypeError(f"{field} must be a string, got {type(value).__name__}")
    if value.startswith("0x") or value.startswith("0X"):
        raise FrontierValueError(
            f"{field}={value!r} is 0x-prefixed; roots are BARE hex in every artifact and every "
            "canonical byte string (the 0x form exists only at the Solidity bytes32 boundary)")
    if len(value) != ROOT_HEX_LEN:
        raise FrontierValueError(
            f"{field} must be {ROOT_HEX_LEN} hex characters, got {len(value)}")
    if not ROOT_RE.match(value):
        if ROOT_RE.match(value.lower()):
            raise FrontierValueError(
                f"{field}={value!r} contains UPPERCASE hex; roots are lowercase and case is "
                "REJECTED rather than normalized (see spec §4)")
        raise FrontierValueError(f"{field}={value!r} is not lowercase hex")
    return value


def check_profile_id(value: Any, field: str = "target_profile") -> str:
    """Validate a profile id against the CLOSED set, case-sensitively."""
    if value is None:
        raise FrontierTypeError(f"{field} is null; a profile id must be present")
    if not isinstance(value, str):
        raise FrontierTypeError(f"{field} must be a string, got {type(value).__name__}")
    if value not in PROFILE_IDS:
        lowered = value.lower()
        if lowered in PROFILE_IDS and lowered != value:
            raise UnknownProfileError(
                f"{field}={value!r} differs from {lowered!r} only by case; profile ids are "
                "matched EXACTLY and case is rejected, never folded")
        if value == LEGACY_PROFILE_ID:
            raise UnknownProfileError(
                f"{field}={value!r} is the frozen legacy profile: it is not mineable and is not "
                f"a frontier profile — it is covered by the composition artifact addressed by "
                "default_composition_root")
        raise UnknownProfileError(
            f"{field}={value!r} is not in the CLOSED profile set for {MANIFEST_FORMAT} "
            f"{list(PROFILE_IDS)}; adding a profile is a NEW manifest version, never a runtime "
            "extension")
    return value


def check_epoch(value: Any, field: str = "epoch") -> int:
    if value is None:
        raise FrontierTypeError(f"{field} is null; an epoch must be present")
    if isinstance(value, bool):
        raise FrontierTypeError(
            f"{field} is a bool; bool is an int subclass in Python and would serialize as "
            "true/false — refused")
    if not isinstance(value, int):
        raise FrontierTypeError(
            f"{field} must be an integer, got {type(value).__name__} "
            "(a float would serialize as 0.0 and is not a canonical value)")
    if value < 0 or value > MAX_EPOCH:
        raise FrontierValueError(f"{field}={value} out of range [0, {MAX_EPOCH}]")
    return value


def _check_closed_fields(document: Any, fields: Iterable[str], family: str,
                         optional: Iterable[str] = ()) -> None:
    if not isinstance(document, dict):
        raise FrontierSchemaError(
            f"{family} must be a JSON object, got {type(document).__name__}")
    fields = tuple(fields)
    missing = [f for f in fields if f not in document]
    if missing:
        raise FrontierSchemaError(f"{family} missing required field(s): {missing}")
    unknown = sorted(set(document) - set(fields) - set(optional))
    if unknown:
        raise FrontierSchemaError(
            f"{family} carries unknown field(s) {unknown}; the schema is CLOSED so an unknown "
            "field cannot ride along inside a signed/addressed root")


# --------------------------------------------------------------------------- #
# Manifest (spec §5)
# --------------------------------------------------------------------------- #
def validate_manifest(manifest: Any) -> Dict[str, Any]:
    """Fail-closed structural validation of a ``coretex.memory-frontier.v1`` manifest.

    Returns the manifest unchanged on success (never a copy, never a normalized version).
    """
    _check_closed_fields(manifest, MANIFEST_FIELDS, MANIFEST_FORMAT, MANIFEST_OPTIONAL_FIELDS)
    if manifest["format"] != MANIFEST_FORMAT:
        raise FrontierSchemaError(
            f"format {manifest['format']!r} is not {MANIFEST_FORMAT!r}")
    check_epoch(manifest["epoch"])
    check_root(manifest["benchmark_law_root"], "benchmark_law_root")
    check_root(manifest["runtime_abi_root"], "runtime_abi_root")
    if "compatibility_lock_root" in manifest:
        check_root(manifest["compatibility_lock_root"], "compatibility_lock_root")
    check_root(manifest["default_composition_root"], "default_composition_root")
    check_root(manifest["parent_frontier_root"], "parent_frontier_root")

    profiles = manifest["profiles"]
    if profiles is None:
        raise FrontierTypeError("profiles is null; the profile map must be present")
    if not isinstance(profiles, dict):
        raise FrontierTypeError(
            f"profiles must be an object, got {type(profiles).__name__}")
    for pid in profiles:
        check_profile_id(pid, "profiles key")
    missing = [p for p in PROFILE_IDS if p not in profiles]
    if missing:
        raise FrontierSchemaError(
            f"profiles missing required profile(s): {missing}; every profile in the closed set "
            "carries a release root in EVERY manifest (absence is never 'unchanged')")
    for pid in PROFILE_IDS:
        check_root(profiles[pid], f"profiles[{pid!r}]")
    return manifest


def frontier_root(manifest: Mapping[str, Any]) -> str:
    """``sha256`` over the manifest's canonical bytes, as bare lowercase hex.

    The manifest is validated first: an invalid manifest has NO root (it is not addressable),
    rather than a root nobody can reproduce.
    """
    validate_manifest(manifest)
    return sha256_hex(canonical_bytes(manifest))


def parse_manifest_json(text: str) -> Dict[str, Any]:
    """Parse + validate a manifest from JSON TEXT, refusing duplicate keys."""
    return validate_manifest(parse_json(text))


def new_manifest(*, epoch: int, parent_frontier_root: str, benchmark_law_root: str,
                 runtime_abi_root: str, default_composition_root: str,
                 profiles: Mapping[str, str],
                 compatibility_lock_root: Any = None) -> Dict[str, Any]:
    """Construct + validate a manifest (the only sanctioned way to mint one by hand).

    ``None`` means the optional historical ``compatibility_lock_root`` is absent. Passing a root
    preserves it byte-for-byte; passing any malformed value is refused by :func:`validate_manifest`.
    """
    if not isinstance(profiles, Mapping):
        raise FrontierTypeError(
            f"profiles must be a mapping, got {type(profiles).__name__}")
    manifest = {
        "benchmark_law_root": benchmark_law_root,
        "default_composition_root": default_composition_root,
        "epoch": epoch,
        "format": MANIFEST_FORMAT,
        "parent_frontier_root": parent_frontier_root,
        "profiles": {pid: profiles[pid] for pid in sorted(profiles)},
        "runtime_abi_root": runtime_abi_root,
    }
    if compatibility_lock_root is not None:
        manifest["compatibility_lock_root"] = compatibility_lock_root
    return validate_manifest(manifest)


# --------------------------------------------------------------------------- #
# Transition (spec §6)
# --------------------------------------------------------------------------- #
def make_transition(*, target_profile: str, expected_prior_release_root: str,
                    new_release_root: str, resulting_composition_root: str) -> Dict[str, Any]:
    """Build + validate a transition document (the decoded form of ``transitionBytes``)."""
    transition = {
        "expected_prior_release_root": expected_prior_release_root,
        "format": TRANSITION_FORMAT,
        "new_release_root": new_release_root,
        "resulting_composition_root": resulting_composition_root,
        "target_profile": target_profile,
    }
    return validate_transition(transition)


def validate_transition(transition: Any) -> Dict[str, Any]:
    """Fail-closed structural validation of a transition, INCLUDING the size bound.

    Self-contained checks only. ``new != prior`` (no-op) is a property of the transition alone
    and is checked here; ``prior == the parent's release root`` (staleness) needs the parent and
    is checked by :func:`apply_transition`.
    """
    _check_closed_fields(transition, TRANSITION_FIELDS, TRANSITION_FORMAT)
    if transition["format"] != TRANSITION_FORMAT:
        raise FrontierSchemaError(
            f"format {transition['format']!r} is not {TRANSITION_FORMAT!r}; a transition is "
            "domain-separated from every other artifact so it can never be re-read as one")
    check_profile_id(transition["target_profile"])
    check_root(transition["expected_prior_release_root"], "expected_prior_release_root")
    check_root(transition["new_release_root"], "new_release_root")
    check_root(transition["resulting_composition_root"], "resulting_composition_root")
    if transition["new_release_root"] == transition["expected_prior_release_root"]:
        raise NoOpTransitionError(
            "new_release_root == expected_prior_release_root: a transition that advances "
            "nothing is refused (it would consume a receipt slot, an epoch CAS and a reward for "
            "no state change)")
    size = len(canonical_bytes(transition))
    if size > MAX_TRANSITION_BYTES:
        raise TransitionSizeError(
            f"transition canonicalizes to {size} bytes, over the {MAX_TRANSITION_BYTES}-byte "
            "bound; transitionBytes is a SMALL manifest edit, never a payload")
    return transition


def transition_bytes(*, target_profile: str, expected_prior_release_root: str,
                     new_release_root: str, resulting_composition_root: str) -> bytes:
    """The exact bytes emitted as ``CoreTexMemoryFrontierAdvanced.transitionBytes``.

    A SMALL canonical manifest edit — four values plus a family tag. Never a Wasm bundle, never a
    module, never a diff of anything else. Bounded by :data:`MAX_TRANSITION_BYTES`.
    """
    return canonical_bytes(make_transition(
        target_profile=target_profile,
        expected_prior_release_root=expected_prior_release_root,
        new_release_root=new_release_root,
        resulting_composition_root=resulting_composition_root))


def parse_transition_bytes(data: bytes) -> Dict[str, Any]:
    """Decode + validate ``transitionBytes`` read off a confirmed event.

    Also enforces CANONICITY: the decoded document must re-serialize to exactly the bytes that
    were supplied, so a semantically-equal-but-differently-encoded payload (re-ordered keys,
    added whitespace, an escaped ASCII character) is refused rather than accepted into replay.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise FrontierTypeError(
            f"transitionBytes must be bytes, got {type(data).__name__}")
    if len(data) > MAX_TRANSITION_BYTES:
        raise TransitionSizeError(
            f"transitionBytes is {len(data)} bytes, over the {MAX_TRANSITION_BYTES}-byte bound")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FrontierSchemaError(f"transitionBytes is not UTF-8: {exc}") from exc
    transition = validate_transition(parse_json(text))
    if canonical_bytes(transition) != bytes(data):
        raise FrontierSchemaError(
            "transitionBytes is not in canonical form (it decodes correctly but re-serializes "
            "to different bytes) — non-canonical encodings are refused so the event payload has "
            "exactly one representation")
    return transition


def transition_hash(transition: Mapping[str, Any]) -> str:
    """``sha256`` over the transition's canonical bytes — the value a receipt binds."""
    return sha256_hex(canonical_bytes(validate_transition(transition)))


def max_transition_bytes() -> int:
    """The EXACT maximum canonical transition size over the closed profile set (all roots are
    fixed-width, so only the profile id varies)."""
    worst = max(PROFILE_IDS, key=lambda p: len(p.encode("utf-8")))
    probe = {
        "expected_prior_release_root": "0" * ROOT_HEX_LEN,
        "format": TRANSITION_FORMAT,
        "new_release_root": "1" * ROOT_HEX_LEN,
        "resulting_composition_root": "2" * ROOT_HEX_LEN,
        "target_profile": worst,
    }
    return len(canonical_bytes(probe))


# --------------------------------------------------------------------------- #
# The state transition (spec §7)
# --------------------------------------------------------------------------- #
#: Manifest fields owned by the independently verified epoch context. A child adopts these
#: values; a miner never chooses them.
EPOCH_PINNED_MANIFEST_FIELDS = ("benchmark_law_root", "runtime_abi_root")


def _verified_epoch_pins(epoch_pins: Any) -> Optional[Dict[str, str]]:
    """Validate the complete frontier-pin projection, or select historical carry semantics."""
    if epoch_pins is None:
        return None
    if not isinstance(epoch_pins, Mapping):
        raise FrontierTypeError(
            f"epoch_pins must be a mapping, got {type(epoch_pins).__name__}")
    return {
        field: check_root(epoch_pins.get(field), f"epoch_pins.{field}")
        for field in EPOCH_PINNED_MANIFEST_FIELDS
    }


def apply_transition(manifest: Mapping[str, Any], transition: Mapping[str, Any], *,
                     epoch: Any = None, epoch_pins: Any = None) -> Dict[str, Any]:
    """Apply ``transition`` to ``manifest``, returning a NEW manifest. Pure, total, fail-closed.

    ``manifest`` is never mutated — the returned document is built fresh, so a caller holding the
    parent (a validator mid-replay, the loser of a race) still has byte-identical parent state.

    Invariants enforced, each with its own error class:

      * the parent is a valid manifest and the transition is a valid transition;
      * ``expected_prior_release_root`` equals the parent's release root for the target profile
        (:class:`StaleParentError` — this is the off-chain twin of the contract's parent-root CAS);
      * the transition is not a no-op (checked in :func:`validate_transition`);
      * ``resulting_composition_root`` differs from the parent's ``default_composition_root``
        (:class:`CompositionUnchangedError`);
      * ``epoch`` never regresses (:class:`EpochRegressionError`).

    ``epoch`` — LAZY INHERITANCE (spec §8, ruling §17.237)
    ------------------------------------------------------
    ``None`` (the default) means "same epoch as the parent": the ordinary within-epoch advance,
    identical to the pre-§17.237 behaviour.

    An explicit ``epoch`` greater than the parent's is the FIRST transition of a new epoch. The
    parent manifest is then the INHERITED head — the final head of the latest preceding epoch that
    mined — and this call is the only thing that moves ``epoch``. It is a single fused operation
    on purpose: an intermediate "carried-forward" manifest would mint a root that no confirmed
    event ever names, and the whole point of the ruling is that every root is reachable by
    replaying confirmed events.

    The epoch is NOT read out of the transition (a transition is epoch-neutral, spec §6.3). It
    comes from the confirmed event's own ``epoch`` topic, i.e. from the contract's mapping key —
    which is exactly where §17.237 puts the authority.

    ``epoch_pins`` is optional for historical replay. When present it contains the independently
    verified current epoch context and the child adopts its ``benchmark_law_root`` and
    ``runtime_abi_root``. This is the only constructible first edge after an epoch-boundary law
    change: the inherited parent is immutable historical data and still carries its prior-era
    values. The legacy ``compatibility_lock_root`` copy is omitted from a pinned-era child because
    its authority is the on-chain ``coreVersionHash``. With no pins, every historical field is
    carried exactly as before.
    """
    validate_manifest(manifest)
    validate_transition(transition)
    verified_pins = _verified_epoch_pins(epoch_pins)
    child_epoch = manifest["epoch"] if epoch is None else check_epoch(epoch, "epoch")
    if child_epoch < manifest["epoch"]:
        raise EpochRegressionError(
            f"transition names epoch {child_epoch} but its parent manifest is already at epoch "
            f"{manifest['epoch']}; epochs only move forward, and a closed epoch's head is "
            "immutable once a later epoch has inherited from it")
    inherited = child_epoch > manifest["epoch"]
    if verified_pins is not None:
        for pin in EPOCH_PINNED_MANIFEST_FIELDS:
            if manifest[pin] != verified_pins[pin] and not inherited:
                raise FrontierValueError(
                    f"same-epoch transition cannot change {pin} from {manifest[pin]} to "
                    f"{verified_pins[pin]}; only an inherited parent from an earlier epoch may "
                    "adopt independently verified current-epoch pins")
        if "compatibility_lock_root" in manifest and not inherited:
            raise FrontierValueError(
                "same-epoch transition cannot retire compatibility_lock_root; only the first "
                "edge from an inherited prior-epoch parent retires that historical manifest "
                "copy in favour of the on-chain coreVersionHash")

    target = transition["target_profile"]
    prior = manifest["profiles"][target]
    if transition["expected_prior_release_root"] != prior:
        raise StaleParentError(
            f"transition for {target!r} expects prior release root "
            f"{transition['expected_prior_release_root']} but the parent frontier holds {prior} "
            "— the candidate was built against a superseded frontier and must rebase")
    if transition["resulting_composition_root"] == manifest["default_composition_root"]:
        raise CompositionUnchangedError(
            f"resulting_composition_root {transition['resulting_composition_root']} equals the "
            "parent's default_composition_root, but this transition changes the release serving "
            f"{target!r}: the signed composition binds a release per profile, so it MUST be "
            "re-minted or the runtime would keep serving the superseded bundle")

    profiles = {pid: manifest["profiles"][pid] for pid in PROFILE_IDS}
    profiles[target] = transition["new_release_root"]
    return new_manifest(
        epoch=child_epoch,
        parent_frontier_root=frontier_root(manifest),
        benchmark_law_root=(manifest["benchmark_law_root"] if verified_pins is None
                            else verified_pins["benchmark_law_root"]),
        runtime_abi_root=(manifest["runtime_abi_root"] if verified_pins is None
                          else verified_pins["runtime_abi_root"]),
        default_composition_root=transition["resulting_composition_root"],
        profiles=profiles,
        compatibility_lock_root=(None if verified_pins is not None
                                 else manifest.get("compatibility_lock_root")))


def verify_transition(parent_manifest: Mapping[str, Any], transition: Mapping[str, Any],
                      claimed_new_root: str, *, epoch: Any = None,
                      epoch_pins: Any = None) -> Dict[str, Any]:
    """Public-replay check: reproduce the child manifest and confirm ``claimed_new_root``.

    Raises :class:`RootMismatchError` (or the specific structural error) rather than returning
    False, so an unverified transition can never be mistaken for a passing one. A validator that
    wants a verdict catches :class:`FrontierError` and records a BACKLOG entry.

    ``epoch`` is the epoch the CONFIRMED EVENT names (see :func:`apply_transition`). Supplying it
    is how a replayer reproduces a first-transition-of-an-epoch, which inherits its parent from a
    previous epoch. Omitting it replays a within-epoch advance.

    Returns ``{parent_root, new_root, new_manifest, transition_hash, target_profile, epoch,
    inherited}``, where ``inherited`` is True iff this transition moved the epoch (i.e. it is the
    lazily-initialized first transition of its epoch).
    """
    check_root(claimed_new_root, "claimed_new_root")
    parent_root = frontier_root(parent_manifest)
    child = apply_transition(parent_manifest, transition, epoch=epoch, epoch_pins=epoch_pins)
    computed = frontier_root(child)
    if computed != claimed_new_root:
        raise RootMismatchError(
            f"reproduced frontier root {computed} != claimed {claimed_new_root} (parent "
            f"{parent_root}) — the confirmed event and the fetched artifacts disagree")
    return {"parent_root": parent_root, "new_root": computed, "new_manifest": child,
            "transition_hash": transition_hash(transition),
            "target_profile": transition["target_profile"],
            "epoch": child["epoch"],
            "inherited": child["epoch"] != parent_manifest["epoch"]}


def rollback_transition(manifest: Mapping[str, Any], *, target_profile: str,
                        restore_release_root: str,
                        resulting_composition_root: str) -> Dict[str, Any]:
    """Build the transition that RESTORES ``restore_release_root`` for ``target_profile``.

    A rollback is an ORDINARY transition — same shape, same CAS, same receipt, same event, same
    fail-closed checks — whose ``new_release_root`` happens to be a previously live one. There is
    no separate rollback opcode and no pointer to rewind (spec §9). It is refused as a no-op if
    the profile already serves ``restore_release_root``.
    """
    validate_manifest(manifest)
    check_profile_id(target_profile)
    return make_transition(
        target_profile=target_profile,
        expected_prior_release_root=manifest["profiles"][target_profile],
        new_release_root=restore_release_root,
        resulting_composition_root=resulting_composition_root)


# --------------------------------------------------------------------------- #
# Epoch head: LAZY INHERITANCE + finalization (spec §8, ruling §17.237)
# --------------------------------------------------------------------------- #
def finalize_epoch(manifest: Mapping[str, Any]) -> Dict[str, Any]:
    """The immutable finalization record for the epoch ``manifest`` heads.

    Finalization asserts a fact, it does not change state: the manifest at ``final_root`` is the
    permanent head of ``epoch`` and stays fetchable and replayable forever under this decoder.
    """
    validate_manifest(manifest)
    record = {
        "epoch": manifest["epoch"],
        "final_root": frontier_root(manifest),
        "format": FINALIZATION_FORMAT,
    }
    canonical_bytes(record)                      # fail closed before anyone addresses it
    return record


def inherited_epoch_parent(head_manifest: Mapping[str, Any], *, epoch: Any) -> str:
    """The root ``epoch`` inherits, given the head of the latest preceding epoch that MINED.

    This is the off-chain twin of ``CoreTexMemoryRegistry.resolveEpochParent`` and it is
    deliberately tiny, because lazy inheritance has nothing to compute: the inherited parent IS
    the previous head's root. Nothing is minted, nothing is carried, and no document exists in
    between. What the function actually enforces is the RULE around that root:

      * ``head_manifest`` must be a valid manifest;
      * ``epoch`` must be STRICTLY GREATER than the head's epoch — an epoch never inherits from
        itself or from the future (:class:`EpochRegressionError`).

    There is deliberately NO ``carry_forward``. Under §17.237 an epoch boundary is not an
    operation: an epoch that never mines mints no root and has no head of its own, and the epoch
    field moves on the first real transition via ``apply_transition(..., epoch=N)``. A function
    that produced an epoch-N+1 "seed manifest" would produce exactly the kind of root the chain
    never names — a local pointer with no confirmed event — which is the failure mode the ruling
    exists to remove.

    Empty epochs therefore need no handling here at all: they simply never appear as
    ``head_manifest``, and the caller's walk-back (the contract's ``lastNonEmptyEpoch`` pointer,
    the validator's derivation over confirmed advances) skips them.

    SEAM (ledger §17.238). None, deliberately: this module is pure, total, stdlib-only and has no
    ports at all (spec §1). It is the one component every validator must be able to run
    identically and offline, so it takes the epoch as an ARGUMENT from whoever read the confirmed
    event and never reaches for a chain, a config or a clock to find one. REVENDOR NEEDED: NO.
    """
    validate_manifest(head_manifest)
    target = check_epoch(epoch, "epoch")
    if target <= head_manifest["epoch"]:
        raise EpochRegressionError(
            f"epoch {target} cannot inherit from a head that is already at epoch "
            f"{head_manifest['epoch']}; inheritance always crosses a boundary forwards")
    return frontier_root(head_manifest)


# --------------------------------------------------------------------------- #
# Genesis (spec §10)
# --------------------------------------------------------------------------- #
def load_committed_promotion(evidence_dir: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Read the two COMMITTED promotion-evidence documents (duplicate-key-refusing parse).

    ``evidence_dir`` is ``benchmark-v2/promotion_g6/evidence``; returns
    ``(g8_promotion.json, frontier-live/state.json)``.
    """
    paths = {"promotion": os.path.join(evidence_dir, "g8_promotion.json"),
             "state": os.path.join(evidence_dir, "frontier-live", "state.json")}
    out = {}
    for name, path in paths.items():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                out[name] = parse_json(fh.read())
        except OSError as exc:
            raise GenesisEvidenceError(f"cannot read committed evidence {path}: {exc}") from exc
    return out["promotion"], out["state"]


def promoted_delegation(promotion_evidence: Mapping[str, Any],
                        frontier_state: Mapping[str, Any]) -> Dict[str, str]:
    """The delegation map, agreed across BOTH committed views, or :class:`GenesisEvidenceError`.

    Mirrors the fail-closed cross-check ``integration.provisioning._promoted_delegation`` already
    performs before it materialises a signed composition; the frontier genesis must not be built
    on weaker evidence than the deployment it addresses.
    """
    if not isinstance(frontier_state, dict):
        raise GenesisEvidenceError(
            f"frontier state must be a JSON object, got {type(frontier_state).__name__}")
    if frontier_state.get("format") != FRONTIER_STATE_FORMAT:
        raise GenesisEvidenceError(
            f"frontier state is not {FRONTIER_STATE_FORMAT!r} "
            f"(got {frontier_state.get('format')!r})")
    if not isinstance(promotion_evidence, dict) or \
            promotion_evidence.get("format") != G8_PROMOTION_FORMAT:
        raise GenesisEvidenceError(
            f"promotion evidence is not {G8_PROMOTION_FORMAT!r}")

    default = frontier_state.get("default_champion")
    if not isinstance(default, dict):
        raise GenesisEvidenceError("frontier state carries no default_champion")
    if default.get("origin") != "promote_default":
        raise GenesisEvidenceError(
            f"default champion origin {default.get('origin')!r} is not 'promote_default' — the "
            "composed default was never promoted; genesis refuses an unpromoted frontier")
    composed_hash = default.get("candidate_hash")
    check_root(composed_hash, "default_champion.candidate_hash")

    if (promotion_evidence.get("tier3") or {}).get("ok") is not True:
        raise GenesisEvidenceError("promotion evidence does not record a passing tier 3")
    gate = promotion_evidence.get("downstream_gate") or {}
    if gate.get("mode") != "PAID" or gate.get("passed") is not True:
        raise GenesisEvidenceError(
            f"promotion evidence Layer-C gate is not a PAID pass "
            f"(mode={gate.get('mode')!r}, passed={gate.get('passed')!r})")
    composed = promotion_evidence.get("composed_default") or {}
    if composed.get("candidate_hash") != composed_hash:
        raise GenesisEvidenceError(
            "promotion evidence composed_default disagrees with the store's default champion")
    if (promotion_evidence.get("default_champion_after") or {}).get("candidate_hash") \
            != composed_hash:
        raise GenesisEvidenceError(
            "promotion evidence default_champion_after disagrees with the store's default")

    coverage = default.get("coverage")
    if not isinstance(coverage, dict):
        raise GenesisEvidenceError("promoted default champion carries no coverage map")
    expected_profiles = set(PROFILE_IDS) | {LEGACY_PROFILE_ID}
    if set(coverage) != expected_profiles:
        raise GenesisEvidenceError(
            f"promoted coverage covers {sorted(coverage)} but this manifest version knows "
            f"{sorted(expected_profiles)}; a changed profile set is a NEW manifest version")
    delegation: Dict[str, str] = {}
    for pid in sorted(expected_profiles):
        entry = coverage.get(pid)
        if not (isinstance(entry, dict) and entry.get("mode") == "delegation"
                and isinstance(entry.get("delegate_to"), str)):
            raise GenesisEvidenceError(
                f"promoted default has no composition delegation for {pid}: {entry!r}")
        delegation[pid] = entry["delegate_to"]
    if composed.get("delegation") != delegation:
        raise GenesisEvidenceError(
            f"promotion evidence delegation {composed.get('delegation')} != the promoted "
            f"default's composition {delegation}")
    if delegation[LEGACY_PROFILE_ID] != LEGACY_BASELINE_INCUMBENT:
        raise GenesisEvidenceError(
            f"{LEGACY_PROFILE_ID} delegates to {delegation[LEGACY_PROFILE_ID]!r}, not the frozen "
            f"baseline {LEGACY_BASELINE_INCUMBENT!r}")

    store_profiles = frontier_state.get("profiles") or {}
    for pid in PROFILE_IDS:
        incumbent = (store_profiles.get(pid) or {}).get("incumbent") or {}
        if incumbent.get("id") != delegation[pid]:
            raise GenesisEvidenceError(
                f"{pid}: promoted delegation names {delegation[pid]!r} but the store's standing "
                f"incumbent is {incumbent.get('id')!r}")
        cand = incumbent.get("candidate_hash")
        check_root(cand, f"profiles[{pid}].incumbent.candidate_hash")
        if not cand.startswith(delegation[pid]):
            raise GenesisEvidenceError(
                f"{pid}: incumbent candidate hash {cand[:12]} does not extend the delegation id "
                f"{delegation[pid]!r}")
    return delegation


def genesis_manifest(*, promotion_evidence: Mapping[str, Any],
                     frontier_state: Mapping[str, Any], benchmark_law_root: str,
                     runtime_abi_root: str, default_composition_root: str,
                     release_roots: Mapping[str, str], epoch: int = 0) -> Dict[str, Any]:
    """Build the GENESIS frontier manifest from the COMMITTED promoted state.

    Genesis is not a special document class — it is an ordinary manifest whose
    ``parent_frontier_root`` is the reserved :data:`ZERO_ROOT`, the one place that sentinel is
    legal. Its content is the currently approved composed champion: one release root per
    mineable profile plus the root of the signed composition artifact that binds the whole
    delegation (legacy profile included).

    ``release_roots`` and ``default_composition_root`` are supplied by the caller because they
    address SIGNED DEPLOYMENT artifacts of family :data:`COMPOSITION_ARTIFACT_FORMAT`, which are
    materialised by the operator provisioner, not carried in the promotion evidence. This
    function's job is to refuse to build genesis unless the committed evidence itself is a
    promoted, internally consistent, PAID-gate-passing state (see :func:`promoted_delegation`);
    ``v5/build_genesis.py`` supplies the roots and records their derivation.
    """
    promoted_delegation(promotion_evidence, frontier_state)   # fail closed on the evidence first
    if not isinstance(release_roots, Mapping):
        raise FrontierTypeError(
            f"release_roots must be a mapping, got {type(release_roots).__name__}")
    if set(release_roots) != set(PROFILE_IDS):
        raise GenesisEvidenceError(
            f"release_roots covers {sorted(release_roots)} but the closed frontier profile set "
            f"is {list(PROFILE_IDS)} ({LEGACY_PROFILE_ID} is covered by the composition root, "
            "never by a frontier release root)")
    for pid in PROFILE_IDS:
        check_root(release_roots[pid], f"release_roots[{pid!r}]")
    # NOTE: the delegation ids themselves (12-hex nicknames like "32bcc4b0262e") are deliberately
    # NOT carried in the manifest — the frontier addresses artifacts by FULL root only. They are
    # provenance and belong in GENESIS.json's provenance block, via :func:`promoted_delegation`.
    return new_manifest(
        epoch=epoch,
        parent_frontier_root=ZERO_ROOT,
        benchmark_law_root=benchmark_law_root,
        runtime_abi_root=runtime_abi_root,
        default_composition_root=default_composition_root,
        profiles={pid: release_roots[pid] for pid in PROFILE_IDS})
