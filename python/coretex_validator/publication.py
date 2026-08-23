# SPDX-License-Identifier: Apache-2.0
"""ARTIFACT AVAILABILITY for the V5 memory lane (Cut V5-C, ledger §17.236).

A confirmed ``CoreTexMemoryFrontierAdvanced`` event is only replayable if the objects it points
at can actually be FETCHED. A coordinator that signs a receipt for an artifact it never published
mints a permanently unreplayable state and a permanent validator backlog entry — the exact
failure §17.236 forbids. So availability is a **PRE-SIGN REQUIREMENT**, and the check is a
READ-BACK: publish, then *fetch the object back out of the publication surface* and rehash the
bytes that came back. Hashing the copy still sitting in local memory proves nothing about what a
validator will be served.

    publish -> FETCH FROM THE STORE -> compare bytes -> recompute the root -> compare roots

Every step raises; nothing here returns ``False`` for an unverified object (the ``frontier.py``
discipline).

CONTENT ADDRESSING. Everything is addressed by ``sha256`` rendered as **bare lowercase hex**
(``frontier.check_root``). What differs per object family is which BYTES get hashed, so a root is
always accompanied by a **hash rule**:

======================================  ==================================================
``sha256-bytes``                        the exact published bytes (opaque artifacts: bundle
                                        archives, wasm modules, ``LAW.md``)
``sha256-frontier-canonical-json``      V5-A canonical JSON (``frontier.canonical_bytes``) —
                                        rejects floats/nulls/dup keys, and the published bytes
                                        MUST already be canonical
``sha256-benchmark-canonical-json``     the Benchmark-v2 / canary rule
                                        (``json.dumps(sort_keys, compact, ascii)``) — the SAME
                                        serializer, but float-tolerant, because signed receipts
                                        and sealed canary transcripts legitimately carry floats
``sha256-signed-manifest-body``         ``coretex_memory.release.canonical_manifest_bytes``:
                                        canonical JSON of the body with ``manifest_self_sha256``
                                        and ``operator_signature`` removed. This is what a
                                        release root / composition root already IS.
======================================  ==================================================

The store is an interface. :class:`FilesystemCAS` is the offline default; :class:`InMemoryCAS`
is the test double; a real deployment swaps in IPFS/S3/whatever WITHOUT touching a caller —
:func:`publish_and_read_back` only ever calls ``put``/``get``/``has``.

SEAM (ledger §17.238)
---------------------
SEAM:            :class:`ContentStore` (:206) IS the port, and it is the SECOND port every other
                 V5 surface names (``activation.chain_view``, ``activation.activator``,
                 :mod:`eval_artifact`, ``validator.replay``). An operator's real publication
                 surface — S3, IPFS, an HTTP CAS — is a third implementation of exactly three
                 methods: ``put(root, data)``, ``get(root) -> bytes``, ``has(root) -> bool``.
                 Wiring is supplying that object; no caller and no internal is edited. The
                 coordinator-side twin of this port already exists as
                 ``MemoryArtifactAvailabilityPort``
                 (``coretex-memory-frontier-lane.ts:607``), whose contract cites
                 :func:`verify_availability` by name.
THE RULE AN IMPLEMENTATION MUST NOT BREAK: ``get`` must return what the surface would serve to a
                 THIRD PARTY. An implementation that answers from a local write cache passes
                 read-back while publishing nothing, which is the one way to mint a permanently
                 unreplayable state, so the honesty of ``get`` is the whole integration contract.
                 Publishing is never the assertion; :func:`publish_and_read_back` (:288) and
                 :func:`read_back` (:334) fetch and rehash, and both raise instead of returning
                 ``False``.
MINIMAL DIFF:    construct the store implementation in the guarded block and pass it to the
                 activator / artifact builder. One object, no subclassing of anything else.
REVENDOR NEEDED: NO. stdlib + ``v5/frontier.py``; the signed-manifest hash rule mirrors
                 ``coretex_memory.release.canonical_manifest_bytes`` without importing
                 ``/root/coretex`` or ``vendor/``.
ARM:             none of its own — it is constructed inside the lane's guarded block.
REMOVE:          delete the guarded block. Additive data only: content-addressed objects under a
                 prefix the lane owns. Nothing in the live stack reads them, and there is no
                 schema to migrate (an object either exists at its root or does not).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, Mapping, Optional

from . import frontier as fr
# Hash rules
# --------------------------------------------------------------------------- #
HASH_RULE_BYTES = "sha256-bytes"
HASH_RULE_FRONTIER_JSON = "sha256-frontier-canonical-json"
HASH_RULE_BENCHMARK_JSON = "sha256-benchmark-canonical-json"
HASH_RULE_SIGNED_MANIFEST_BODY = "sha256-signed-manifest-body"

HASH_RULES = (HASH_RULE_BYTES, HASH_RULE_FRONTIER_JSON, HASH_RULE_BENCHMARK_JSON,
              HASH_RULE_SIGNED_MANIFEST_BODY)

#: The two fields ``coretex_memory.release.canonical_manifest_bytes`` removes before serializing
#: (a document cannot hash or sign itself).
SIGNED_MANIFEST_ATTESTATION_FIELDS = ("manifest_self_sha256", "operator_signature")


def check_hash_rule(hash_rule: str) -> str:
    """The single gate every rule-taking entry point passes through."""
    if hash_rule not in HASH_RULES:
        raise HashRuleError(f"unknown hash rule {hash_rule!r}; known rules are {list(HASH_RULES)}")
    return hash_rule


class PublicationError(Exception):
    """Base class for every availability failure."""


class HashRuleError(PublicationError):
    """Unknown hash rule, or bytes that the rule cannot address (non-canonical encoding,
    unparseable JSON, a float under the frontier rule, ...)."""


class ObjectNotFoundError(PublicationError):
    """The publication surface does not serve an object at this root — availability FAILED."""


class ReadBackMismatchError(PublicationError):
    """The store served bytes that do not rehash to the root they were fetched under."""


class StoreIntegrityError(PublicationError):
    """The store served bytes that differ from the bytes that were published under that root."""


class AvailabilityError(PublicationError):
    """An availability manifest entry is malformed, missing, or unsatisfied."""


def benchmark_canonical_bytes(obj: Any) -> bytes:
    """The Benchmark-v2 / canary canonical rule, verbatim.

    ``frontier._canon.canonical_json`` and ``canary.policy.canonical_bytes`` are the same call
    (``ensure_ascii`` defaults to True), so ONE function reproduces both. It is deliberately
    float-tolerant: a signed receipt binds rounded measurement floats and a sealed canary
    transcript binds the policy's float thresholds. Those objects are addressed under THIS rule
    and referenced from the V5 artifact by root; they are never inlined into V5 canonical bytes,
    where floats are illegal (V5-A §2.2).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def signed_manifest_body(document: Mapping[str, Any]) -> Dict[str, Any]:
    """The signable/hashable body of a signed release or composition manifest."""
    if not isinstance(document, dict):
        raise HashRuleError(
            f"a signed manifest must be a JSON object, got {type(document).__name__}")
    return {k: v for k, v in document.items() if k not in SIGNED_MANIFEST_ATTESTATION_FIELDS}


def encode(obj: Any, hash_rule: str) -> bytes:
    """The exact bytes to PUBLISH for ``obj`` under ``hash_rule``."""
    if hash_rule == HASH_RULE_BYTES:
        if not isinstance(obj, (bytes, bytearray, memoryview)):
            raise HashRuleError(
                f"{HASH_RULE_BYTES} addresses raw bytes, got {type(obj).__name__}")
        return bytes(obj)
    if hash_rule == HASH_RULE_FRONTIER_JSON:
        return fr.canonical_bytes(obj)
    if hash_rule in (HASH_RULE_BENCHMARK_JSON, HASH_RULE_SIGNED_MANIFEST_BODY):
        if not isinstance(obj, dict):
            raise HashRuleError(f"{hash_rule} addresses a JSON object, got "
                                f"{type(obj).__name__}")
        return benchmark_canonical_bytes(obj)
    raise HashRuleError(f"unknown hash rule {hash_rule!r}; known rules are {list(HASH_RULES)}")


def root_of(data: bytes, hash_rule: str) -> str:
    """The root of ``data`` under ``hash_rule`` — computed FROM THE BYTES, always.

    For the two canonical-JSON rules the bytes must already BE canonical: a semantically equal
    but differently encoded payload is refused rather than silently re-canonicalized, so one root
    addresses exactly one byte string (the ``frontier.parse_transition_bytes`` discipline).
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise HashRuleError(f"root_of takes bytes, got {type(data).__name__}")
    data = bytes(data)
    if hash_rule == HASH_RULE_BYTES:
        return fr.sha256_hex(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HashRuleError(f"{hash_rule}: published bytes are not UTF-8: {exc}") from exc
    try:
        document = fr.parse_json(text)                 # refuses duplicate object keys
    except fr.FrontierError as exc:
        raise HashRuleError(f"{hash_rule}: {exc}") from exc

    if hash_rule == HASH_RULE_FRONTIER_JSON:
        try:
            canonical = fr.canonical_bytes(document)
        except fr.FrontierError as exc:
            raise HashRuleError(f"{hash_rule}: {exc}") from exc
        if canonical != data:
            raise HashRuleError(
                f"{hash_rule}: published bytes are not in canonical form (they decode but "
                "re-serialize differently) — a root must address exactly one byte string")
        return fr.sha256_hex(canonical)
    if hash_rule == HASH_RULE_BENCHMARK_JSON:
        canonical = benchmark_canonical_bytes(document)
        if canonical != data:
            raise HashRuleError(
                f"{hash_rule}: published bytes are not in canonical form (they decode but "
                "re-serialize differently) — a root must address exactly one byte string")
        return fr.sha256_hex(canonical)
    if hash_rule == HASH_RULE_SIGNED_MANIFEST_BODY:
        # NOT canonicity-checked: the published bytes carry the self-hash + signature, which the
        # body deliberately excludes, so published bytes != hashed bytes by construction.
        return fr.sha256_hex(benchmark_canonical_bytes(signed_manifest_body(document)))
    raise HashRuleError(f"unknown hash rule {hash_rule!r}; known rules are {list(HASH_RULES)}")


# --------------------------------------------------------------------------- #
# The store interface
# --------------------------------------------------------------------------- #
class ContentStore:
    """A content-addressed publication surface.

    Three required methods, no assumptions about locality. Implementations MUST be honest: ``get``
    returns the bytes the surface would serve to a third party, and raises
    :class:`ObjectNotFoundError` when it has nothing at that root. An implementation that
    "helpfully" returns a locally cached copy defeats the entire point of the read-back.

    :meth:`get_for_rule` is the FOURTH method and the only one with a default. It exists because
    an address alone does not tell a surface how the object was committed, and some surfaces need
    to be told: the coordinator's public object route refuses a request that names no rule, and
    it decides between an envelope and raw octets from it. A store whose transport does not vary
    by rule — every LOCAL store — inherits the default, which validates the rule and answers with
    ``get``. Nothing about VERIFICATION moves here: the rule is transport metadata, the caller
    still recomputes the root from the bytes that arrived (:func:`read_back`), and a surface that
    reports its own successful verification is not thereby believed.
    """

    def put(self, root: str, data: bytes) -> None:
        raise NotImplementedError

    def get(self, root: str) -> bytes:
        raise NotImplementedError

    def has(self, root: str) -> bool:
        raise NotImplementedError

    def get_for_rule(self, root: str, hash_rule: str) -> bytes:
        """The bytes at ``root``, told which rule the caller committed to. Default: :meth:`get`.

        An unknown rule is refused BEFORE any transport happens — a request this client cannot
        verify the answer to is one it must never make.
        """
        check_hash_rule(hash_rule)
        return self.get(root)


class InMemoryCAS(ContentStore):
    """Dict-backed store. Test double, and the reference for what an implementation must do."""

    def __init__(self) -> None:
        self._objects: Dict[str, bytes] = {}

    def put(self, root: str, data: bytes) -> None:
        fr.check_root(root, "root")
        self._objects[root] = bytes(data)

    def get(self, root: str) -> bytes:
        fr.check_root(root, "root")
        if root not in self._objects:
            raise ObjectNotFoundError(f"no object published at {root}")
        return self._objects[root]

    def has(self, root: str) -> bool:
        fr.check_root(root, "root")
        return root in self._objects

    def __len__(self) -> int:
        return len(self._objects)


class FilesystemCAS(ContentStore):
    """Local filesystem CAS — the offline default (no network anywhere in the V5 lane).

    One file per root, named by the root, written atomically (temp + ``os.replace``) so a reader
    never observes a half-published object.
    """

    def __init__(self, root_dir: str) -> None:
        self.root_dir = os.path.abspath(root_dir)
        os.makedirs(self.root_dir, exist_ok=True)

    def _path(self, root: str) -> str:
        fr.check_root(root, "root")                    # also stops any path traversal
        return os.path.join(self.root_dir, root)

    def put(self, root: str, data: bytes) -> None:
        path = self._path(root)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "wb") as fh:
            fh.write(bytes(data))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def get(self, root: str) -> bytes:
        path = self._path(root)
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError as exc:
            raise ObjectNotFoundError(f"no object published at {root}: {exc}") from exc

    def has(self, root: str) -> bool:
        return os.path.exists(self._path(root))


# --------------------------------------------------------------------------- #
# publish + read back
# --------------------------------------------------------------------------- #
def publish_and_read_back(obj: Any, *, hash_rule: str = HASH_RULE_FRONTIER_JSON,
                          store: ContentStore, expected_root: Optional[str] = None) -> str:
    """Publish ``obj``, FETCH IT BACK OUT of ``store``, rehash the fetched bytes, return the root.

    THE READ-BACK RULE, in order, all fail-closed:

      1. encode ``obj`` under ``hash_rule`` and compute ``expected`` from those bytes;
      2. if ``expected_root`` was supplied and differs -> :class:`ReadBackMismatchError` (the
         object is not the one the caller believes it is publishing);
      3. ``store.put(expected, data)``;
      4. ``fetched = store.get(expected)`` — absence is :class:`ObjectNotFoundError`, NOT a
         "probably fine, we just wrote it";
      5. ``fetched == data`` else :class:`StoreIntegrityError` (the surface mutated the bytes);
      6. recompute the root FROM ``fetched`` and require it to equal ``expected``, else
         :class:`ReadBackMismatchError`.

    Steps 5 and 6 are both kept on purpose. 5 catches a store that rewrites bytes; 6 catches a
    store whose addressing disagrees with ours even when the bytes survived — e.g. one that
    re-pretty-prints JSON, which would still be *decodable* but would no longer be the canonical
    byte string this root names.
    """
    data = encode(obj, hash_rule)
    expected = root_of(data, hash_rule)
    if expected_root is not None:
        fr.check_root(expected_root, "expected_root")
        if expected_root != expected:
            raise ReadBackMismatchError(
                f"object hashes to {expected} under {hash_rule}, but the caller expected "
                f"{expected_root}")
    store.put(expected, data)
    fetched = store.get(expected)                      # raises ObjectNotFoundError if absent
    if not isinstance(fetched, (bytes, bytearray)):
        raise StoreIntegrityError(
            f"store returned {type(fetched).__name__}, not bytes, for {expected}")
    fetched = bytes(fetched)
    if fetched != data:
        raise StoreIntegrityError(
            f"store served {len(fetched)} bytes at {expected} that differ from the "
            f"{len(data)} bytes published there — the publication surface is not honest")
    actual = root_of(fetched, hash_rule)
    if actual != expected:
        raise ReadBackMismatchError(
            f"bytes fetched back from the store rehash to {actual}, not {expected}")
    return expected


def read_back(root: str, *, hash_rule: str, store: ContentStore,
              expected_bytes_len: Optional[int] = None) -> bytes:
    """Fetch ``root`` from ``store`` and re-verify it addresses itself. Raises on any failure.

    This is the check a coordinator runs at PRE-SIGN time for objects published earlier (a
    candidate bundle uploaded during submission, the composition manifest minted at compose time)
    and the check a validator runs at replay time. It never trusts a local copy.

    THE FETCH CARRIES THE RULE (:meth:`ContentStore.get_for_rule`), because a remote surface may
    need it to answer at all — the coordinator's public object route refuses a request that names
    no rule, and serves raw octets rather than an envelope when one is named. What the rule NEVER
    does is move verification: the root is recomputed below, here, from the bytes that arrived,
    under the rule the caller committed to. A surface may report that it verified the transport
    itself; that report is not evidence and is not read. For the float-bearing benchmark rule this
    matters most — a server can only check that ``sha256(bytes)`` equals the root, while THIS side
    additionally requires the bytes to BE the canonical serialisation the root names.
    """
    fr.check_root(root, "root")
    check_hash_rule(hash_rule)
    data = store.get_for_rule(root, hash_rule)         # ObjectNotFoundError on absence
    if not isinstance(data, (bytes, bytearray)):
        raise StoreIntegrityError(
            f"store returned {type(data).__name__}, not bytes, for {root}")
    data = bytes(data)
    actual = root_of(data, hash_rule)
    if actual != root:
        raise ReadBackMismatchError(
            f"object served at {root} rehashes to {actual} under {hash_rule} — the publication "
            "surface is serving different content than the root names")
    if expected_bytes_len is not None and len(data) != expected_bytes_len:
        raise ReadBackMismatchError(
            f"object at {root} is {len(data)} bytes, the availability record says "
            f"{expected_bytes_len}")
    return data


def fetch_json(root: str, *, hash_rule: str, store: ContentStore,
               expected_bytes_len: Optional[int] = None) -> Any:
    """:func:`read_back` + duplicate-key-refusing parse. For JSON-family hash rules only."""
    if hash_rule == HASH_RULE_BYTES:
        raise HashRuleError("fetch_json needs a JSON hash rule, not sha256-bytes")
    data = read_back(root, hash_rule=hash_rule, store=store,
                     expected_bytes_len=expected_bytes_len)
    return fr.parse_json(data.decode("utf-8"))


# --------------------------------------------------------------------------- #
# availability records (the block a V5 eval artifact carries)
# --------------------------------------------------------------------------- #
AVAILABILITY_ITEM_FIELDS = ("bytes", "hash_rule", "root")


def availability_item(root: str, hash_rule: str, byte_len: int) -> Dict[str, Any]:
    """One closed availability record: ``{bytes, hash_rule, root}``."""
    fr.check_root(root, "availability root")
    if hash_rule not in HASH_RULES:
        raise HashRuleError(f"unknown hash rule {hash_rule!r}")
    if not isinstance(byte_len, int) or isinstance(byte_len, bool) or byte_len < 0:
        raise AvailabilityError(f"availability bytes must be a non-negative int: {byte_len!r}")
    return {"bytes": byte_len, "hash_rule": hash_rule, "root": root}


def publish_item(obj: Any, *, hash_rule: str, store: ContentStore) -> Dict[str, Any]:
    """:func:`publish_and_read_back` + the availability record for what was published."""
    data = encode(obj, hash_rule)
    root = publish_and_read_back(obj, hash_rule=hash_rule, store=store)
    return availability_item(root, hash_rule, len(data))


def validate_availability(items: Any) -> Dict[str, Any]:
    """Structural validation of an availability map ``{name: {bytes, hash_rule, root}}``."""
    if not isinstance(items, dict):
        raise AvailabilityError(
            f"availability items must be an object, got {type(items).__name__}")
    if not items:
        raise AvailabilityError("availability items must not be empty")
    for name, item in items.items():
        if not isinstance(name, str) or not name:
            raise AvailabilityError(f"availability key {name!r} must be a non-empty string")
        if not isinstance(item, dict):
            raise AvailabilityError(f"availability[{name!r}] must be an object")
        missing = [f for f in AVAILABILITY_ITEM_FIELDS if f not in item]
        if missing:
            raise AvailabilityError(f"availability[{name!r}] missing {missing}")
        unknown = sorted(set(item) - set(AVAILABILITY_ITEM_FIELDS))
        if unknown:
            raise AvailabilityError(
                f"availability[{name!r}] carries unknown field(s) {unknown}; the record schema "
                "is CLOSED")
        availability_item(item["root"], item["hash_rule"], item["bytes"])
    return items


def verify_availability(items: Mapping[str, Any], *, store: ContentStore,
                        required: Iterable[str] = ()) -> Dict[str, str]:
    """Read back EVERY availability record from ``store``. Fail-closed, raises on the first miss.

    Returns ``{name: root}``. A missing required name is an :class:`AvailabilityError`, not a
    silent skip: "the artifact did not mention it" must never be a way to avoid publishing it.
    """
    validate_availability(items)
    required = tuple(required)
    absent = [name for name in required if name not in items]
    if absent:
        raise AvailabilityError(
            f"availability block does not cover required object(s) {absent}; a broadcastable "
            "receipt requires every one of them to be published and readable")
    out: Dict[str, str] = {}
    for name in sorted(items):
        item = items[name]
        try:
            read_back(item["root"], hash_rule=item["hash_rule"], store=store,
                      expected_bytes_len=item["bytes"])
        except PublicationError as exc:
            raise AvailabilityError(f"availability read-back failed for {name!r}: {exc}") from exc
        out[name] = item["root"]
    return out
