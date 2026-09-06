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
``sha256-benchmark-canonical-json``     Benchmark-v2 canonical JSON
                                        (``json.dumps(sort_keys, compact, ascii)``),
                                        float-tolerant for rounded measurement values
``sha256-manifest-body``                ``coretex_memory.release.canonical_manifest_bytes``:
                                        canonical JSON of the body with only
                                        ``manifest_self_sha256`` removed. This is what a release
                                        root / composition root already IS.
======================================  ==================================================

The store is an interface. :class:`FilesystemCAS` is the offline default; :class:`InMemoryCAS`
is the test double; :class:`HttpCAS` is the READ-ONLY mirror client an auditor points at somebody
else's publication surface (it rehashes every byte before returning it, so the mirror is used and
never trusted); a real deployment swaps in IPFS/S3/whatever WITHOUT touching a caller —
:func:`publish_and_read_back` only ever calls ``put``/``get``/``has``.

SEAM (ledger §17.238)
---------------------
SEAM:            :class:`ContentStore` IS the port used by :mod:`eval_artifact`,
                 ``validator.replay``, and the coordinator. An operator's real publication
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
MINIMAL DIFF:    construct the store implementation and pass it to the artifact builder. One
                 object, no subclassing of anything else.
REVENDOR NEEDED: NO. stdlib + ``v5/frontier.py``; the manifest-body hash rule mirrors
                 ``coretex_memory.release.canonical_manifest_bytes`` without importing
                 ``/root/coretex`` or ``vendor/``.
ARM:             none of its own — it is constructed inside the lane's guarded block.
REMOVE:          delete the guarded block. Additive data only: content-addressed objects under a
                 prefix the lane owns. An object either exists at its root or does not.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from typing import Any, Dict, Iterable, Mapping, Optional

from . import frontier as fr

# --------------------------------------------------------------------------- #
# Hash rules
# --------------------------------------------------------------------------- #
HASH_RULE_BYTES = "sha256-bytes"
HASH_RULE_FRONTIER_JSON = "sha256-frontier-canonical-json"
HASH_RULE_BENCHMARK_JSON = "sha256-benchmark-canonical-json"
HASH_RULE_MANIFEST_BODY = "sha256-manifest-body"

#: The compatibility lock is addressed BY ITS OWN LOCK ROOT — the value an epoch's
#: ``coreVersionHash`` carries. That is the whole point of the binding: the chain word IS the
#: content address, so "fetch what this epoch declared it is compatible with" is a store read
#: keyed by a value the chain already committed to, with nothing in between to disagree with.
#:
#: Published bytes are the canonical bytes of the WHOLE document (including its own
#: ``lock_root``); the hashed body deliberately excludes that field, exactly as
#: :data:`HASH_RULE_MANIFEST_BODY` excludes a manifest's self-hash. Canonicity of the
#: published bytes is still enforced, so one root addresses exactly one byte string.
HASH_RULE_COMPATIBILITY_LOCK = "compatibility-lock-root"

HASH_RULES = (HASH_RULE_BYTES, HASH_RULE_FRONTIER_JSON, HASH_RULE_BENCHMARK_JSON,
              HASH_RULE_MANIFEST_BODY, HASH_RULE_COMPATIBILITY_LOCK)

#: The only field ``coretex_memory.release.canonical_manifest_bytes`` removes before serializing.
MANIFEST_BODY_EXCLUDED_FIELDS = ("manifest_self_sha256",)


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
    """The Benchmark-v2 canonical rule.

    It is deliberately float-tolerant because evaluation reports bind rounded measurement values.
    Those documents are addressed under this rule and referenced by root; they are never inlined
    into frontier-canonical documents, where floats are illegal.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def manifest_body(document: Mapping[str, Any]) -> Dict[str, Any]:
    """The hashable body of a current release or composition manifest."""
    if not isinstance(document, dict):
        raise HashRuleError(
            f"a manifest must be a JSON object, got {type(document).__name__}")
    return {k: v for k, v in document.items() if k not in MANIFEST_BODY_EXCLUDED_FIELDS}


def encode(obj: Any, hash_rule: str) -> bytes:
    """The exact bytes to PUBLISH for ``obj`` under ``hash_rule``."""
    if hash_rule == HASH_RULE_BYTES:
        if not isinstance(obj, (bytes, bytearray, memoryview)):
            raise HashRuleError(
                f"{HASH_RULE_BYTES} addresses raw bytes, got {type(obj).__name__}")
        return bytes(obj)
    if hash_rule in (HASH_RULE_FRONTIER_JSON, HASH_RULE_COMPATIBILITY_LOCK):
        return fr.canonical_bytes(obj)
    if hash_rule in (HASH_RULE_BENCHMARK_JSON, HASH_RULE_MANIFEST_BODY):
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
    if hash_rule == HASH_RULE_MANIFEST_BODY:
        # NOT canonicity-checked: the published bytes carry the self-hash, which the body excludes,
        # so published bytes differ from hashed bytes by construction.
        return fr.sha256_hex(benchmark_canonical_bytes(manifest_body(document)))
    if hash_rule == HASH_RULE_COMPATIBILITY_LOCK:
        # Canonicity IS checked: the lock's published bytes are exactly the canonical bytes of the
        # document.
        try:
            canonical = fr.canonical_bytes(document)
        except fr.FrontierError as exc:
            raise HashRuleError(f"{hash_rule}: {exc}") from exc
        if canonical != data:
            raise HashRuleError(
                f"{hash_rule}: published bytes are not in canonical form (they decode but "
                "re-serialize differently) — a root must address exactly one byte string")
        # `verify_lock` VALIDATES and RECOMPUTES; a document whose own recorded root disagrees with
        # its body has no address at all rather than an address nobody can reproduce. The rule is
        # imported from the one shared library — this module owns no lock hash of its own.
        from . import compat_lock as cl
        try:
            return cl.verify_lock(document)
        except cl.CompatibilityLockError as exc:
            raise HashRuleError(f"{hash_rule}: {exc}") from exc
    raise HashRuleError(f"unknown hash rule {hash_rule!r}; known rules are {list(HASH_RULES)}")


# --------------------------------------------------------------------------- #
# The store interface
# --------------------------------------------------------------------------- #
class ContentStore:
    """A content-addressed publication surface.

    Three methods, no assumptions about locality. Implementations MUST be honest: ``get`` returns
    the bytes the surface would serve to a third party, and raises :class:`ObjectNotFoundError`
    when it has nothing at that root. An implementation that "helpfully" returns a locally cached
    copy defeats the entire point of the read-back.
    """

    def put(self, root: str, data: bytes) -> None:
        raise NotImplementedError

    def get(self, root: str) -> bytes:
        raise NotImplementedError

    def has(self, root: str) -> bool:
        raise NotImplementedError


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


#: A published object is a code tree, a bundle archive or a manifest; 64 MiB is an order of
#: magnitude above the largest thing this lane has ever addressed (the 614 KiB runtime tree tar) and
#: still small enough that a hostile or broken mirror cannot exhaust a validator's memory. The cap
#: is enforced on the STREAM, not on a Content-Length header, because a header is the server's claim
#: and the body is the fact.
HTTP_MAX_OBJECT_BYTES = 64 * 1024 * 1024
#: Read granularity. Small enough that the cap is hit promptly on an endless response.
HTTP_CHUNK_BYTES = 64 * 1024


class HttpTransportError(PublicationError):
    """The mirror never produced a usable answer: status, timeout, DNS, reset, oversize body.

    Deliberately NOT :class:`ObjectNotFoundError`. "the surface does not hold this object" (404)
    and "I could not ask" (timeout, 502, truncated read) are different facts, and a validator that
    reported the second as the first would tell an operator to go re-publish an object that is
    published perfectly well.
    """


class HttpCAS(ContentStore):
    """A READ-ONLY content-addressed surface over plain HTTP(S). Standard library only.

    THE ONE PROPERTY THAT MATTERS: every byte this returns has been rehashed under
    :data:`HASH_RULE_BYTES` and compared to the root it was requested under, before it is returned
    to anybody. A mirror is therefore never trusted — it is only ever *used*. That is what lets an
    auditor point this at an arbitrary third-party mirror, a CDN, an S3 bucket or a coordinator's
    ``/coretex/v5/object/{root}`` route and still get the same guarantee the offline
    :class:`FilesystemCAS` gives: the address IS the content.

    Consequences of that property, each deliberate:

    * ``put`` RAISES. A mirror is somebody else's publication surface; a validator that could write
      to it could manufacture the availability it is supposed to be checking. This class is the
      READ half of the port and says so rather than silently no-op'ing.
    * ``has`` performs a real conditional fetch, not a ``HEAD``. Many static hosts answer ``HEAD``
      from metadata that outlives the object, and some answer ``200`` for everything (a soft-404
      HTML page). Only fetching and rehashing distinguishes "serves this object" from "serves
      something".
    * Bodies are read in bounded chunks with a hard ceiling. An unbounded ``response.read()``
      against a hostile endpoint is a memory-exhaustion hole in the one process whose job is to
      refuse hostile inputs.
    * NO AUTHENTICATION IS SENT, EVER — no Authorization header, no cookies, no credentials in the
      URL. Public verifiability is the point: a check an auditor cannot repeat without a secret is
      not a public check. A URL carrying userinfo is refused at construction rather than quietly
      stripped, so the operator learns their mirror URL is not usable as published.
    * Redirects are followed by ``urllib`` (a mirror behind a CDN needs them) and cannot subvert
      anything: whatever the final host serves must still rehash to the requested root.

    ``root_hash_rule`` exists because a store's addressing must match how its objects were
    published. It defaults to :data:`HASH_RULE_BYTES` — the rule under which a root names exactly
    one byte string, which is the only rule an opaque transport can check without parsing.
    """

    def __init__(self, base_url: str, *, timeout: float = 30.0, retries: int = 3,
                 backoff: float = 0.5, max_object_bytes: int = HTTP_MAX_OBJECT_BYTES,
                 user_agent: str = "coretex-v5-validator/1 (+publication.HttpCAS)",
                 root_hash_rule: str = HASH_RULE_BYTES,
                 send_hash_rule: bool = False) -> None:
        import urllib.parse

        if not isinstance(base_url, str) or not base_url.strip():
            raise HttpTransportError("HttpCAS needs a base url")
        parsed = urllib.parse.urlsplit(base_url.strip())
        if parsed.scheme not in ("http", "https"):
            raise HttpTransportError(
                f"HttpCAS speaks http(s); {base_url!r} uses {parsed.scheme!r}. A local directory "
                "is FilesystemCAS's job, not a URL scheme this class should pretend to handle")
        if not parsed.hostname:
            raise HttpTransportError(f"{base_url!r} carries no hostname")
        if parsed.username is not None or parsed.password is not None:
            raise HttpTransportError(
                "HttpCAS refuses a url carrying credentials: an availability proof that only "
                "somebody holding a secret can repeat is not a public availability proof")
        if root_hash_rule not in HASH_RULES:
            raise HashRuleError(f"unknown hash rule {root_hash_rule!r}")
        #: Kept WITH its trailing slash so ``urljoin``-free concatenation cannot eat a path segment.
        self.base_url = base_url.strip().rstrip("/") + "/"
        self.timeout = float(timeout)
        self.retries = max(1, int(retries))
        self.backoff = float(backoff)
        self.max_object_bytes = int(max_object_bytes)
        self.user_agent = user_agent
        self.root_hash_rule = root_hash_rule
        #: Whether the rule goes ON THE WIRE as a ``?hashRule=`` query parameter. OFF by default:
        #: a generic mirror (S3, an IPFS gateway, a static file tree) addresses objects by path
        #: alone and answers 404 for an unexpected query string, and that is the shape this class
        #: was written for. It MUST be ON against the CoreTex coordinator's public object route,
        #: which requires the parameter and answers ``400 hash_rule_unsupported`` without it. See
        #: :meth:`url_for`.
        self.send_hash_rule = bool(send_hash_rule)
        #: Observability, not policy: a run that silently absorbed twenty retries took twenty times
        #: longer than it should have and nobody was told why.
        self.requests = 0
        self.retried = 0

    # -- transport ---------------------------------------------------------- #
    def url_for(self, root: str) -> str:
        """The object URL, carrying the hash rule iff ``send_hash_rule`` is on.

        WHY THIS IS A SWITCH AND NOT A CONSTANT. Two incompatible server shapes are both legitimate
        targets for this class:

        * a GENERIC MIRROR (S3, an IPFS gateway, a static file tree) addresses an object by path
          alone. An unexpected query string is a 404 there, so the rule must NOT be sent — this is
          the default, and it is the shape the offline tests exercise;
        * the CORETEX COORDINATOR's public object route REQUIRES the rule
          (`GET /coretex/v5/object/{root}?hashRule=…`) and answers `400 hash_rule_unsupported`
          without it. Against that route ``send_hash_rule=True`` is MANDATORY: a client that
          carried ``root_hash_rule`` only as a constructor field and never put it on the wire got
          400 on EVERY object class — not a partial failure but a total one, no third party
          pointing this CAS at the public route could complete a replay at all.

        The rule also has to be the COMMITTED one, not merely present: the route re-canonicalizes
        the stored bytes under the rule it is asked for, and a signed composition manifest fetched
        under a rule it was not committed under legitimately fails to re-render (it carries nulls
        the frontier rule rejects) and comes back 502 `artifact_integrity_failure`. Sending the
        committed rule is what turns that into the 200 the object always had.
        """
        fr.check_root(root, "root")            # also stops any path traversal in the URL we build
        url = self.base_url + root
        rule = getattr(self, "root_hash_rule", None) if getattr(self, "send_hash_rule", False) else None
        if rule:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}hashRule={urllib.parse.quote(str(rule), safe='')}"
        return url

    def _read_bounded(self, response) -> bytes:
        limit = self.max_object_bytes
        chunks = []
        total = 0
        while True:
            chunk = response.read(HTTP_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise HttpTransportError(
                    f"the mirror is serving more than the {limit}-byte object ceiling; the "
                    "response was abandoned rather than buffered")
            chunks.append(chunk)
        return b"".join(chunks)

    def _fetch(self, root: str) -> bytes:
        import urllib.error
        import urllib.request

        url = self.url_for(root)
        request = urllib.request.Request(
            url, headers={"accept": "application/octet-stream", "user-agent": self.user_agent})
        last: Optional[BaseException] = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    self.requests += 1
                    return self._read_bounded(response)
            except urllib.error.HTTPError as exc:
                if exc.code == 404 or exc.code == 410:
                    # The surface answered, and its answer was "I do not hold that". Not retried:
                    # a 404 is a fact about the store, and asking again is asking the same question.
                    raise ObjectNotFoundError(
                        f"no object published at {root}: the mirror answered HTTP {exc.code} for "
                        f"{url}") from exc
                last = HttpTransportError(f"{url}: HTTP {exc.code}")
            except (urllib.error.URLError, OSError) as exc:
                # NOTE an oversize body raises HttpTransportError from `_read_bounded`, which is
                # NOT an OSError and so is not caught here: retrying will not make the response
                # smaller, so it propagates on the first attempt.
                last = HttpTransportError(f"{url}: {exc}")
            if attempt + 1 < self.retries:
                self.retried += 1
                time.sleep(self.backoff * (2 ** attempt))
        raise last if last is not None else HttpTransportError(f"{url}: unreachable")

    # -- the ContentStore port ---------------------------------------------- #
    def put(self, root: str, data: bytes) -> None:
        raise PublicationError(
            "HttpCAS is READ-ONLY. Publishing over somebody else's mirror would let a validator "
            "manufacture the availability it exists to check; publish with FilesystemCAS (or the "
            "operator's real surface) and point this at the result")

    def get(self, root: str) -> bytes:
        """Fetch ``root`` and REHASH IT before returning a single byte to the caller."""
        fr.check_root(root, "root")
        data = self._fetch(root)
        served = root_of(data, self.root_hash_rule)
        if served != root:
            raise ReadBackMismatchError(
                f"the mirror served {len(data)} bytes at {self.url_for(root)} that rehash to "
                f"{served} under {self.root_hash_rule}, not to the requested {root} — the surface "
                "is serving different content than the address names")
        return data

    def has(self, root: str) -> bool:
        """A real fetch + rehash. See the class docstring on why ``HEAD`` would be a lie."""
        try:
            self.get(root)
        except ObjectNotFoundError:
            return False
        return True


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
    """
    fr.check_root(root, "root")
    data = store.get(root)                             # ObjectNotFoundError on absence
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


#: The record shape the coordinator's ``MemoryArtifactAvailabilityPort`` consumes
#: (``coretex-memory-frontier-lane.ts::MemoryArtifactAvailabilityRecord``). It is NOT the
#: availability record the artifact carries — that one is ``{bytes, hash_rule, root}`` and is
#: CLOSED — because the two answer different questions: the artifact's entry says "this is the
#: address I committed to", this one says "I fetched that address again just now and here is what
#: came back".
AVAILABILITY_REPORT_FIELDS = ("available", "hash", "kind", "read_back_hash", "readBackHash")


def read_back_record(kind: str, item: Mapping[str, Any], *, store: ContentStore) -> Dict[str, Any]:
    """One availability record, with a ``readBackHash`` RECOMPUTED FROM A FRESH FETCH.

    THE ECHO IS THE FAILURE MODE THIS EXISTS TO PREVENT. A port that returns
    ``{hash: X, readBackHash: X}`` without fetching anything satisfies every equality a consumer
    can check, so the value of the field is entirely in how it was produced. Here it is produced by
    calling ``store.get`` again and hashing what came back under the item's own hash rule — never
    by copying ``item["root"]`` across.

    ``available`` is never ``False``-and-fine: an unfetchable object raises, exactly as everything
    else in this module does. The flag exists because the consumer's wire format carries it, and it
    is always ``True`` in a record this function returns.
    """
    root = item["root"]
    hash_rule = item["hash_rule"]
    data = store.get(root)                                     # FRESH read; ObjectNotFoundError
    if not isinstance(data, (bytes, bytearray)):
        raise StoreIntegrityError(
            f"store returned {type(data).__name__}, not bytes, for {kind} at {root}")
    data = bytes(data)
    served_root = root_of(data, hash_rule)                     # recomputed FROM THE SERVED BYTES
    if served_root != root:
        raise ReadBackMismatchError(
            f"{kind}: the store serves bytes at {root} that rehash to {served_root} under "
            f"{hash_rule}")
    if int(item["bytes"]) != len(data):
        raise ReadBackMismatchError(
            f"{kind}: object at {root} is {len(data)} bytes, the availability record says "
            f"{item['bytes']}")
    return {"kind": kind, "hash": root, "available": True,
            "readBackHash": served_root, "read_back_hash": served_root, "bytes": len(data)}


def availability_report(items: Mapping[str, Any], *, store: ContentStore,
                        required: Iterable[str] = ()) -> list:
    """:func:`verify_availability`'s answer, rendered as the coordinator port's record list.

    Same reads, same refusals, one extra deliverable: the consumer gets the pair of hashes it
    compares rather than a bare ``{name: root}`` map it has to take on trust.
    """
    verify_availability(items, store=store, required=required)
    return [read_back_record(name, items[name], store=store) for name in sorted(items)]


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
