# SPDX-License-Identifier: Apache-2.0
"""Reference implementation of ``coretex.memory-frontier.v1`` (Cut V5-A, ledger §17.236).

The normative text is ``v5/spec/MEMORY-FRONTIER-V1.md``; this module is the executable form of
it. Scope is deliberately narrow: **state + transition law only**. Nothing here signs, fetches,
touches a chain, reads a socket, or knows what a Wasm bundle is. Every public function is pure
and total: it either returns a value derived solely from its arguments, or raises a typed
:class:`FrontierError`. There is no silent coercion anywhere — no lower-casing, no
``0x``-stripping, no int/float widening, no "absent means null".

Canonicalization is NOT a new dialect. It is *literally* the rule the shipped runtime already
uses for content-addressed release manifests
(``coretex_memory.release.canonical_manifest_bytes``)::

    json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

The frontier manifest carries no self-address or off-chain signature. Its authority is the
on-chain root, so the canonical body is the whole document.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Tuple

# --------------------------------------------------------------------------- #
# Identity constants
# --------------------------------------------------------------------------- #
#: The public frontier manifest artifact family.
MANIFEST_FORMAT = "coretex.memory-frontier.v1"

#: The transition-edit artifact family — the payload of ``CoreTexMemoryFrontierAdvanced``.
TRANSITION_FORMAT = "coretex.memory-frontier-transition.v1"

#: The epoch-finalization record family (see :func:`finalize_epoch`).
FINALIZATION_FORMAT = "coretex.memory-frontier.v1/epoch-finalization"

#: The CLOSED set of frontier profile ids, in their normative TOTAL ORDER (see the spec §3).
#: The order is the byte order of the UTF-8 id strings; for this all-ASCII set that coincides
#: exactly with what ``json.dumps(..., sort_keys=True)`` emits, so the canonical serializer
#: realizes the normative order with no separate ordering pass.
PROFILE_IDS: Tuple[str, ...] = ("conv.pref.v1", "doc.tool.v1", "event.schema.v1")

#: Required top-level manifest fields. The schema is CLOSED: an unknown field is an error.
MANIFEST_FIELDS: Tuple[str, ...] = (
    "benchmark_law_root", "default_composition_root", "epoch", "format",
    "parent_frontier_root", "profiles", "runtime_abi_root",
)

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

#: Hard upper bound on ``transitionBytes`` — the MEMORY LANE's canonical transition document, NOT
#: the rig receipt's member 25. The exact maximum over the closed profile set is 364 bytes
#: (:func:`max_transition_bytes`); the enforced bound is rounded up to 384 so a future same-shape
#: profile id has room without a law change.
#:
#: The bound applies to this public frontier edit. The deployed descriptor-v3 chain wire carries
#: a fixed commitment to the separately published transition artifact, not this JSON payload.
MAX_TRANSITION_BYTES = 384

#: Manifest epochs are unsigned and fit a uint64 (the on-chain mapping key type).
MAX_EPOCH = 2 ** 64 - 1

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
    target profile — the candidate was built against a non-current parent."""


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
    _check_closed_fields(manifest, MANIFEST_FIELDS, MANIFEST_FORMAT)
    if manifest["format"] != MANIFEST_FORMAT:
        raise FrontierSchemaError(
            f"format {manifest['format']!r} is not {MANIFEST_FORMAT!r}")
    check_epoch(manifest["epoch"])
    check_root(manifest["benchmark_law_root"], "benchmark_law_root")
    check_root(manifest["runtime_abi_root"], "runtime_abi_root")
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
                 profiles: Mapping[str, str]) -> Dict[str, Any]:
    """Construct + validate the closed seven-field public manifest."""
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
#: The frontier-manifest fields an EPOCH CONTEXT pins on chain, and which an advance therefore
#: ADOPTS rather than carries forward. See :func:`apply_transition`.
EPOCH_PINNED_MANIFEST_FIELDS = ("benchmark_law_root", "runtime_abi_root")


def _adopt_or_carry(manifest: Mapping[str, Any], epoch_pins: Any, field: str) -> Any:
    """Use a confirmed epoch pin when supplied; otherwise preserve the parent's current pin."""
    if isinstance(epoch_pins, Mapping):
        pinned = epoch_pins.get(field)
        if isinstance(pinned, str) and pinned:
            return check_root(pinned, f"epoch pin {field}")
    return manifest[field]


def apply_transition(manifest: Mapping[str, Any], transition: Mapping[str, Any], *,
                     epoch: Any = None, epoch_pins: Any = None) -> Dict[str, Any]:
    """Apply ``transition`` to ``manifest``, returning a NEW manifest. Pure, total, fail-closed.

    ``manifest`` is never mutated — the returned document is built fresh, so a caller holding the
    parent (a validator mid-replay, the loser of a race) still has byte-identical parent state.

    The current transition document is deliberately one-profile: its closed schema names one
    ``target_profile`` and one replacement release root.

    Invariants enforced, each with its own error class:

      * the parent is a valid manifest and the transition is a valid transition;
      * ``expected_prior_release_root`` equals the parent's release root for the target profile
        (:class:`StaleParentError` — this is the off-chain twin of the contract's parent-root CAS);
      * the transition is not a no-op (checked in :func:`validate_transition`);
      * ``resulting_composition_root`` differs from the parent's ``default_composition_root``
        (:class:`CompositionUnchangedError`);
      * ``epoch`` never regresses (:class:`EpochRegressionError`).

    ``epoch`` — explicit epoch-context parent
    -------------------------------------------
    ``None`` (the default) means "same epoch as the parent": the ordinary within-epoch advance,
    identical to the pre-§17.237 behaviour.

    An explicit ``epoch`` greater than the parent's is the first transition under an epoch context
    whose operator-supplied ``parentStateRoot`` addresses that manifest. The relationship is
    explicit chain data; this module never searches earlier epochs or infers inheritance. No
    intermediate boundary manifest exists.

    The epoch is NOT read out of the transition (a transition is epoch-neutral, spec §6.3). It
    comes from the confirmed event's own ``epoch`` topic, i.e. from the contract's mapping key —
    which is the chain authority.

    ``epoch_pins``
    --------------
    Supplying the confirmed epoch context's pins makes the child adopt them for
    :data:`EPOCH_PINNED_MANIFEST_FIELDS`. This is how those fields ever move: an operator moves
    them with ``setCoreTexEpochContext``. Without an explicit current pin, the same-format parent
    value is carried forward. Every non-target profile release is carried forward unchanged.
    ``parent_frontier_root`` becomes the parent's root, which is what makes the manifest chain a
    total order (spec §9).
    """
    validate_manifest(manifest)
    validate_transition(transition)
    child_epoch = manifest["epoch"] if epoch is None else check_epoch(epoch, "epoch")
    if child_epoch < manifest["epoch"]:
        raise EpochRegressionError(
            f"transition names epoch {child_epoch} but its parent manifest is already at epoch "
            f"{manifest['epoch']}; epochs only move forward, and a closed epoch's head is "
            "immutable once a later epoch has inherited from it")

    target = transition["target_profile"]
    prior = manifest["profiles"][target]
    if transition["expected_prior_release_root"] != prior:
        raise StaleParentError(
            f"transition for {target!r} expects prior release root "
            f"{transition['expected_prior_release_root']} but the parent frontier holds {prior} "
            "— the candidate was built against a non-current parent and must rebase")
    if transition["resulting_composition_root"] == manifest["default_composition_root"]:
        raise CompositionUnchangedError(
            f"resulting_composition_root {transition['resulting_composition_root']} equals the "
            "parent's default_composition_root, but this transition changes the release serving "
            f"{target!r}: the signed composition binds a release per profile, so it MUST be "
            "rebuilt or the runtime would keep serving the prior bundle")

    profiles = {pid: manifest["profiles"][pid] for pid in PROFILE_IDS}
    profiles[target] = transition["new_release_root"]
    return new_manifest(
        epoch=child_epoch,
        parent_frontier_root=frontier_root(manifest),
        benchmark_law_root=_adopt_or_carry(manifest, epoch_pins, "benchmark_law_root"),
        runtime_abi_root=_adopt_or_carry(manifest, epoch_pins, "runtime_abi_root"),
        default_composition_root=transition["resulting_composition_root"],
        profiles=profiles)


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

    ``epoch_pins`` MUST be threaded through wherever the minting side threaded it, or this
    function reproduces a DIFFERENT child than the one that was minted and every adopting advance
    fails ``RootMismatchError`` — a permanent BACKLOG on the first advance that moves a pin, from
    a replayer that is behaving correctly. Reproduction has to be given the same inputs as
    production; a pin the minter adopted and the replayer did not is exactly such an input.

    Returns ``{parent_root, new_root, new_manifest, transition_hash, target_profile, epoch,
    crossed_epoch}``, where ``crossed_epoch`` is true when the explicit context parent manifest
    carries an earlier product epoch.
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
            "crossed_epoch": child["epoch"] != parent_manifest["epoch"]}


# --------------------------------------------------------------------------- #
# Epoch finalization
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
