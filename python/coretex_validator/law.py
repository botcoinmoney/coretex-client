# SPDX-License-Identifier: Apache-2.0
"""``sync-law``: fetch, VERIFY and materialize the published admission law (spec §9.3).

THE PROBLEM THIS REMOVES. Step 5 of ``coretex-validator reproduce`` is deterministic admission: the
candidate is re-executed against the pinned generators, scorer, ABI seam and runtime, and the
receipt body is rebuilt byte for byte. That needs six code trees, and on a clean machine it
BACKLOGs — not because anything is wrong, but because the trees are not on the host and the three
env pins (``CORETEX_ADMISSION_REPO_ROOT``, ``CORETEX_BENCHMARK_V2_DIR``,
``CORETEX_MEMORY_RUNTIME_DIR``) have to be set by hand to trees the operator obtained by some
unspecified means. "Obtain six trees by some unspecified means" is not an auditable step.

The trees ARE published (finding F4), as content-addressed objects under a publication root, and
they are addressed by THE SAME tree-hash rule the signed Benchmark-v2 receipt's ``code_roots``
binds. So the address is the chain-bound identity, not a courier's promise. This module fetches
them by that address from any mirror, re-derives every address from the bytes that arrived,
materializes a verified local cache, and hands back the three pins. (Six trees plus one FILE — see
:data:`POSTURE_RELPATH`; the seventh sealed root was never a tree and cannot be packed as one.) Step 5 then runs the real
pinned admission on a machine that started with nothing but a URL.

WHY THE RULE IS REIMPLEMENTED HERE RATHER THAN IMPORTED
=======================================================
This package is Apache-2.0 and declares zero runtime dependencies; the six trees are UNLICENSED
and are DATA to this client, never an import. Verifying them by importing code out of them would
also be circular — a tree that vouched for itself would vouch for anything.

So :func:`tree_hash` is a from-the-specification reimplementation on the standard library, and the
two implementations are pinned to each other by GOLDEN VECTORS: the coordinator generates
``tests/fixtures/tree-hash-golden.v1.json`` from ``benchmark-v2/validator/receipt.py::tree_hash``,
a byte-identical copy lives in this repository, and both repositories test against it (and against
its sha256, so the copies cannot drift). ``tests/test_tree_hash_golden.py`` is this side of it.

THE RULE (transcribed; the fixture carries the same words)
==========================================================
``sha256`` over the concatenation, **in ascending byte order of the LINES**, of one line per file::

    <relpath> NUL <sha256-hex-of-file-bytes> LF          (utf-8)

``relpath`` is POSIX-separated, relative to the tree root. Directories named ``__pycache__``,
``.pytest_cache`` or ``evidence`` are skipped wherever they occur, with everything beneath them;
files whose name ends in ``.pyc`` are skipped. The named private key-material paths
(:data:`KEY_MATERIAL_EXCLUSIONS`) are skipped, and their ABSENCE is not an error — that is what
lets a key-free image and a minting host agree on one root. An empty tree hashes to ``sha256(b"")``.

Sorting the LINES rather than the paths matters: ``b.py`` precedes ``b/a.py`` because ``.`` (0x2E)
sorts before ``/`` (0x2F). A path-component sort produces a different root. The golden vectors
contain that exact case.

WHAT "FAIL CLOSED" MEANS HERE, CONCRETELY
=========================================
Every one of these refuses, loudly, and none of them is recoverable by a flag:

* the manifest does not hash to the publication root the caller named;
* an object does not hash to the address it was fetched under, under either the tar-byte digest
  the manifest binds or the TREE-HASH rule its own name is;
* a tar carries a member the tree-hash rule would NOT hash. This one is subtle and is the reason it
  is checked: such a file is invisible to the address and would still land in the cache, which is
  exactly how a mirror would smuggle code past a content check. The only tolerated exception is a
  documented key-material path, and using one is recorded in the cache receipt;
* a tar carries an absolute path, a ``..`` component, a symlink, a hard link, a device or a
  duplicate name; or exceeds the member/size ceilings;
* a required tree is missing from the publication set;
* a required single-file object is missing, or its bytes do not reproduce the address they were
  served under. The seventh sealed root — ``candidate_isolation_posture`` — is the plain sha256 of
  ONE FILE rather than a tree hash, so it is published as a single-file entry and installed at
  ``v5/production/CANDIDATE-ISOLATION.production.json`` inside the cache, which is exactly where
  ``receipt.py::code_roots`` opens it. A cache without it cannot compute the roots any receipt
  binds, so it is refused at install time rather than at the first replay;
* a download exceeds its byte ceiling, or the transport fails.

A verified cache is re-verified when it is LOADED, not merely when it is written: a cache is a
directory on a shared machine, and "we checked it last Tuesday" is not a property of what is on
disk now.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

# --------------------------------------------------------------------------- #
# the rule
# --------------------------------------------------------------------------- #
#: Directories skipped wherever they occur, together with everything beneath them.
TREE_EXCLUDE_DIRS = frozenset({"__pycache__", ".pytest_cache", "evidence"})
#: File-name suffixes skipped.
TREE_EXCLUDE_SUFFIXES = (".pyc",)
#: Private key material: not identity-bearing, and MISSING is the expected state. Keyed by the
#: repo-relative tree path, exactly as the canonical implementation keys it.
KEY_MATERIAL_EXCLUSIONS = {
    "benchmark-v2/validator": ("keys/validator_seed.test.hex",),
}

#: The six trees deterministic admission needs, by the path each extracts to. A publication set
#: that is missing any of them cannot satisfy step 5 and is refused rather than half-installed.
REQUIRED_TREES: Tuple[str, ...] = (
    "benchmark-v2/generators",
    "benchmark-v2/frontier",
    "benchmark-v2/validator",
    "benchmark-v2/scoring",
    "benchmark-v2/miner_abi",
    "coretex-memory/coretex_memory",
)

# --------------------------------------------------------------------------- #
# THE SEVENTH SEALED ROOT IS A FILE, NOT A TREE
# --------------------------------------------------------------------------- #
#: ``benchmark-v2/validator/receipt.py::code_roots`` computes six roots with the tree-hash rule
#: and one — ``candidate_isolation_posture`` — as the plain ``sha256`` of ONE FILE, opened at
#: ``<repo_root>/v5/production/CANDIDATE-ISOLATION.production.json``. For a validator running on a
#: law cache, ``repo_root`` IS the cache (``CORETEX_ADMISSION_REPO_ROOT``), so the file has to land
#: at exactly this relative path inside it or the seventh root is unobtainable.
#:
#: Until this existed, ``verify-receipt`` on a real production receipt refused at ``code_roots``
#: with ``[Errno 2] No such file or directory`` and the publication had no way to supply it: the
#: manifest's own ``code_roots_note`` records that the posture "is the sha256 of a single posture
#: FILE, not a tree hash, so it is gated here but is not published as a tar".
POSTURE_RELPATH = "v5/production/CANDIDATE-ISOLATION.production.json"
POSTURE_CODE_ROOTS_FIELD = "candidate_isolation_posture"

#: ``code_roots`` field -> the relative path its bytes install to. A manifest entry naming one of
#: these fields is a SINGLE-FILE object: addressed by the raw ``sha256`` of its bytes (which is
#: what ``code_roots`` computes), never unpacked, never tree-hashed.
SINGLE_FILE_CODE_ROOTS: Dict[str, str] = {POSTURE_CODE_ROOTS_FIELD: POSTURE_RELPATH}

#: Single-file objects a publication MUST carry, by install path.
#:
#: Required rather than tolerated-when-absent, for the reason the six trees are: a cache that
#: cannot satisfy ``code_roots()`` cannot replay a single receipt, and discovering that at the
#: first replay instead of at install time is exactly the failure D-3 reported. "A partially
#: installed law is worse than none" applies to the seventh root as much as to the other six.
REQUIRED_FILES: Tuple[str, ...] = (POSTURE_RELPATH,)

#: THERE IS NO DEFAULT PUBLICATION ROOT, deliberately.
#:
#: One used to live here — the 2026-08-04 REHEARSAL closure — on the reasoning that a default is
#: not a trust anchor because whatever is named is verified from the bytes. That reasoning was
#: wrong by one step: verification proves the trees hash to the root that was asked for, and says
#: nothing about whether that root is the one the CHAIN HEAD binds. So the default silently
#: installed rehearsal law on live hosts, every later command picked it up, and the run reported
#: a verified cache the whole time.
#:
#: The publication a validator wants is a property of the deployment it is verifying, so it is
#: DISCOVERED (``setup`` reads it from the coordinator kit) or named explicitly. Absence is the
#: only behaviour: the root is a required argument, here and on the command line.

#: Bounded downloads, in the style of the rest of this package. The largest object the publication
#: lane has ever addressed is a 614 KiB tar; these ceilings are orders of magnitude above that and
#: still small enough that a hostile mirror cannot exhaust a validator.
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_OBJECT_BYTES = 64 * 1024 * 1024
#: Extraction ceilings — a decompression bomb is a supply-chain attack, not a big file.
MAX_TAR_MEMBERS = 20000
MAX_TAR_TOTAL_BYTES = 256 * 1024 * 1024
_READ_CHUNK = 256 * 1024

#: The env pins a verified cache satisfies. ORDER IS THE PUBLIC CONTRACT (F4's snippet).
ENV_REPO_ROOT = "CORETEX_ADMISSION_REPO_ROOT"
ENV_BENCHMARK_V2 = "CORETEX_BENCHMARK_V2_DIR"
ENV_MEMORY_RUNTIME = "CORETEX_MEMORY_RUNTIME_DIR"
ENV_PINS = (ENV_REPO_ROOT, ENV_BENCHMARK_V2, ENV_MEMORY_RUNTIME)

CACHE_RECEIPT = "LAW.json"
CACHE_RECEIPT_FORMAT = "coretex-validator/law-cache/v1"

MANIFEST_FORMATS = ("coretex.rig-state.admission-closure-manifest/v1",)


class LawError(Exception):
    """Base of every ``sync-law`` failure."""


class LawTransportError(LawError):
    """The mirror never produced a usable answer. NOT the same fact as 'it does not hold that'."""


class LawNotFound(LawError):
    """The mirror answered, and its answer was that it does not serve this address."""


class LawVerifyError(LawError):
    """Something did not hash to the address it was served under. Never recoverable by a flag."""


class LawCacheError(LawError):
    """The local cache is absent, incomplete, or no longer verifies against its own receipt."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_root(value: Any) -> bool:
    """A content address: 64 lowercase hex characters, bare. Also the path-traversal guard."""
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def check_root(value: Any, field: str = "root") -> str:
    if not is_root(value):
        raise LawVerifyError(
            f"{field} must be 64 lowercase hex characters (a bare sha256), got {value!r}")
    return value


def key_material_exclusions(tree_relpath: str) -> Tuple[str, ...]:
    """The not-identity-bearing paths inside ``tree_relpath``. Mirrors the canonical mapping."""
    return tuple(sorted(KEY_MATERIAL_EXCLUSIONS.get(tree_relpath.replace(os.sep, "/"), ())))


def is_hashed_path(relpath: str, exclude_relpaths: Sequence[str] = ()) -> bool:
    """Does the rule hash this relpath? The single place the exclusion clauses are decided."""
    parts = relpath.split("/")
    if any(part in TREE_EXCLUDE_DIRS for part in parts[:-1]):
        return False
    if parts[-1].endswith(TREE_EXCLUDE_SUFFIXES):
        return False
    if relpath in set(exclude_relpaths):
        return False
    return True


def tree_hash_from_files(files: Mapping[str, bytes],
                         exclude_relpaths: Sequence[str] = ()) -> str:
    """The rule, over an in-memory ``{relpath: bytes}`` mapping. See the module docstring."""
    lines = []
    for relpath, data in files.items():
        if not is_hashed_path(relpath, exclude_relpaths):
            continue
        lines.append(f"{relpath}\0{_sha256(data)}\n")
    acc = hashlib.sha256()
    for line in sorted(lines):
        acc.update(line.encode("utf-8"))
    return acc.hexdigest()


def tree_hash(root_dir: str, exclude_relpaths: Sequence[str] = ()) -> str:
    """The rule, over a directory on disk. Streams file bytes rather than buffering a tree."""
    root_dir = os.path.abspath(root_dir)
    if not os.path.isdir(root_dir):
        raise LawVerifyError(f"code tree does not exist: {root_dir}")
    excluded = {p.replace(os.sep, "/") for p in exclude_relpaths}
    lines = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in TREE_EXCLUDE_DIRS)
        for name in filenames:
            if name.endswith(TREE_EXCLUDE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            relpath = os.path.relpath(full, root_dir).replace(os.sep, "/")
            if relpath in excluded:
                continue
            digest = hashlib.sha256()
            with open(full, "rb") as fh:
                while True:
                    chunk = fh.read(_READ_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
            lines.append(f"{relpath}\0{digest.hexdigest()}\n")
    acc = hashlib.sha256()
    for line in sorted(lines):
        acc.update(line.encode("utf-8"))
    return acc.hexdigest()


# --------------------------------------------------------------------------- #
# the publication root
# --------------------------------------------------------------------------- #
#: The two spellings a publication manifest's own address is written under, tried in this order.
#:
#: ``sha256-bytes`` is what a content-addressed object endpoint serves under. The published
#: epoch-180 set instead records its root as the sha256 of the manifest WITHOUT its trailing
#: newline (``LICENSE-SCOPE.md``: "recomputed as sha256(MANIFEST.json minus trailing newline)"),
#: because the file on disk ends in one and the digest was taken over the document.
#:
#: Both are EXACT preimages of the bytes that arrived — this is not a fuzzy match. Which one
#: matched is recorded in the cache receipt, so an auditor is never left guessing which rule a
#: given publication set used.
MANIFEST_HASH_RULES = ("sha256-bytes", "sha256-bytes-without-trailing-newline")


def manifest_root_candidates(data: bytes) -> List[Tuple[str, str]]:
    """``[(rule, root)]`` for the manifest bytes, in preference order."""
    out = [("sha256-bytes", _sha256(data))]
    if data.endswith(b"\n"):
        out.append(("sha256-bytes-without-trailing-newline", _sha256(data[:-1])))
    return out


def manifest_matches(data: bytes, publication_root: str) -> Optional[str]:
    """The rule under which ``data`` addresses ``publication_root``, or ``None``."""
    for rule, root in manifest_root_candidates(data):
        if root == publication_root:
            return rule
    return None


# --------------------------------------------------------------------------- #
# mirrors
# --------------------------------------------------------------------------- #
#: How a mirror lays its objects out. Discovered once, from where the MANIFEST verifies, and then
#: fixed for every object — so a set cannot be assembled from two different layouts.
#:
#: A ``coretex-v5-object`` layout used to head this list, fetching
#: ``{base}/coretex/v5/object/{root}`` raw from a coordinator. It could never verify against a
#: real one: that route refuses a request carrying no ``?hashRule`` and envelopes its answer by
#: default, and law tars are not in the object CAS at all — they are published through the KIT.
#: A layout that cannot succeed is not a fallback, it is a wasted fetch and a misleading
#: "not found", so it is gone rather than repaired. ``setup`` mirrors the kit's publication into
#: a local ``flat-cas`` directory, which is what a coordinator-served law sync actually is.
LAYOUTS = (
    # a bare content-addressed mirror: one file per address
    {"name": "flat-cas", "manifest": "{root}", "object": "{root}"},
    # a published evidence set, as it sits in the repository / in a release tarball
    {"name": "publication-set", "manifest": "MANIFEST.json", "object": "artifacts/{root}"},
)


class Mirror:
    """Bounded, read-only fetching from ``http(s)://``, ``file://`` or a local directory.

    NO CREDENTIALS ARE EVER SENT and a URL carrying userinfo is refused rather than quietly
    stripped: a law cache an auditor cannot rebuild without somebody's secret is not public law.

    The mirror is never trusted. Nothing this class returns has been checked; every caller in this
    module rehashes what it gets. What the class DOES guarantee is that a hostile endpoint cannot
    make the client read forever or read something enormous.
    """

    def __init__(self, location: str, *, timeout: float = 30.0, retries: int = 3,
                 backoff: float = 0.5) -> None:
        if not isinstance(location, str) or not location.strip():
            raise LawTransportError("a mirror location is required")
        location = location.strip()
        parsed = urllib.parse.urlsplit(location)
        if parsed.scheme in ("http", "https"):
            if parsed.username is not None or parsed.password is not None:
                raise LawTransportError(
                    "a mirror url may not carry credentials: a law cache that only somebody "
                    "holding a secret can rebuild is not publicly verifiable")
            if not parsed.hostname:
                raise LawTransportError(f"{location!r} carries no hostname")
            self.kind = "http"
            self.base = location.rstrip("/") + "/"
        elif parsed.scheme == "file":
            self.kind = "file"
            self.base = os.path.abspath(urllib.parse.unquote(parsed.path)).rstrip("/") + "/"
        elif parsed.scheme in ("", None) or (len(parsed.scheme) == 1 and os.name == "nt"):
            self.kind = "file"
            self.base = os.path.abspath(os.path.expanduser(location)).rstrip("/") + "/"
        else:
            raise LawTransportError(
                f"a mirror is an http(s) url, a file:// url or a local directory; "
                f"{location!r} uses scheme {parsed.scheme!r}")
        self.location = location
        self.timeout = float(timeout)
        self.retries = max(1, int(retries))
        self.backoff = float(backoff)
        self.fetches = 0
        self.bytes_fetched = 0

    def url_for(self, relative: str) -> str:
        # `relative` is always built from a checked root or a literal, never from mirror input.
        if ".." in relative.split("/"):                         # pragma: no cover - defensive
            raise LawTransportError(f"refusing a traversing path {relative!r}")
        return self.base + relative

    def fetch(self, relative: str, *, limit: int) -> bytes:
        """The bytes at ``relative``, or :class:`LawNotFound` / :class:`LawTransportError`."""
        target = self.url_for(relative)
        data = (self._fetch_file(target, limit) if self.kind == "file"
                else self._fetch_http(target, limit))
        self.fetches += 1
        self.bytes_fetched += len(data)
        return data

    # -- local -------------------------------------------------------------- #
    def _fetch_file(self, path: str, limit: int) -> bytes:
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            raise LawNotFound(f"the mirror holds nothing at {path}: {exc}") from exc
        if size > limit:
            raise LawTransportError(
                f"{path} is {size} bytes, above the {limit}-byte ceiling; it was not read")
        try:
            with open(path, "rb") as fh:
                return fh.read(limit + 1)[:limit + 1]
        except OSError as exc:                                 # pragma: no cover - race
            raise LawTransportError(f"{path}: {exc}") from exc

    # -- http --------------------------------------------------------------- #
    def _fetch_http(self, url: str, limit: int) -> bytes:
        import time

        request = urllib.request.Request(
            url, headers={"accept": "application/octet-stream",
                          "user-agent": "coretex-validator sync-law"})
        last: Optional[BaseException] = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    return self._read_bounded(response, limit, url)
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):
                    # A fact about the store, not a transport blip: asking again asks the same
                    # question. Not retried, and never conflated with "I could not ask".
                    raise LawNotFound(
                        f"the mirror answered HTTP {exc.code} for {url}") from exc
                last = LawTransportError(f"{url}: HTTP {exc.code}")
            except (urllib.error.URLError, OSError) as exc:
                last = LawTransportError(f"{url}: {exc}")
            if attempt + 1 < self.retries:
                time.sleep(self.backoff * (2 ** attempt))
        raise last if last is not None else LawTransportError(f"{url}: unreachable")

    @staticmethod
    def _read_bounded(response, limit: int, url: str) -> bytes:
        chunks = []
        total = 0
        while True:
            chunk = response.read(_READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise LawTransportError(
                    f"{url} is serving more than the {limit}-byte ceiling; the response was "
                    "abandoned rather than buffered")
            chunks.append(chunk)
        return b"".join(chunks)


# --------------------------------------------------------------------------- #
# tar objects
# --------------------------------------------------------------------------- #
def _tar_members(data: bytes) -> List[tarfile.TarInfo]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as exc:
        raise LawVerifyError(f"the object is not a readable tar archive: {exc}") from exc
    return archive


def read_tree_object(data: bytes, *, root: str) -> Tuple[str, Dict[str, bytes]]:
    """Unpack ONE published tree object into ``(extract_to, {relpath: bytes})``, checked.

    Refusals here are the difference between "content-addressed" and "content-addressed and safe to
    write to disk": the address covers the bytes the RULE hashes, so anything in the container that
    the rule would not hash must not exist, or a mirror could ship code the address says nothing
    about. See the module docstring.
    """
    archive = _tar_members(data)
    try:
        members = archive.getmembers()
    except tarfile.TarError as exc:
        raise LawVerifyError(f"the object's tar index is unreadable: {exc}") from exc
    if not members:
        raise LawVerifyError(f"object {root} is an empty archive")
    if len(members) > MAX_TAR_MEMBERS:
        raise LawVerifyError(
            f"object {root} carries {len(members)} members, above the {MAX_TAR_MEMBERS} ceiling")

    names = []
    total = 0
    for member in members:
        name = member.name
        if member.isdir():
            # Directories carry no content and no address; they are recreated implicitly.
            continue
        if not member.isfile():
            raise LawVerifyError(
                f"object {root} carries {name!r}, which is a {_member_kind(member)} rather than a "
                "regular file. A published code tree is files; a link or device in the container "
                "is a way to write outside it")
        parts = name.replace("\\", "/").split("/")
        if name.startswith("/") or name.startswith("\\") or ".." in parts:
            raise LawVerifyError(
                f"object {root} carries the escaping path {name!r}; it was not extracted")
        if total + max(0, member.size) > MAX_TAR_TOTAL_BYTES:
            raise LawVerifyError(
                f"object {root} expands past the {MAX_TAR_TOTAL_BYTES}-byte ceiling")
        total += max(0, member.size)
        names.append(name)
    if len(set(names)) != len(names):
        duplicates = sorted({n for n in names if names.count(n) > 1})
        raise LawVerifyError(
            f"object {root} names {duplicates} more than once; one path must mean one file")

    extract_to = _common_prefix(names, root=root)
    prefix = extract_to + "/"
    files: Dict[str, bytes] = {}
    for member in members:
        if not member.isfile():
            continue
        handle = archive.extractfile(member)
        if handle is None:                                     # pragma: no cover - defensive
            raise LawVerifyError(f"object {root}: {member.name!r} has no readable content")
        files[member.name[len(prefix):]] = handle.read()
    return extract_to, files


def _member_kind(member: tarfile.TarInfo) -> str:
    for flag, label in ((member.issym, "symlink"), (member.islnk, "hard link"),
                        (member.ischr, "character device"), (member.isblk, "block device"),
                        (member.isfifo, "fifo")):
        if flag():
            return label
    return "non-regular entry"                                 # pragma: no cover - defensive


def _common_prefix(names: Sequence[str], *, root: str) -> str:
    """The single directory every member sits under — the tree's ``extract_to``.

    Derived from the container rather than read out of an index, so the destination a caller
    materializes to is a property of the object itself. A set of members with no common directory
    is refused: a "tree" that spans two destinations is not one tree.
    """
    parts = [name.split("/") for name in names]
    if any(len(p) < 2 for p in parts):
        raise LawVerifyError(
            f"object {root} carries a member at the archive root; a published tree is packed under "
            "the path it extracts to (e.g. 'benchmark-v2/frontier/...')")
    prefix = parts[0][:-1]
    for candidate in parts[1:]:
        head = candidate[:-1]
        limit = min(len(prefix), len(head))
        common = 0
        while common < limit and prefix[common] == head[common]:
            common += 1
        prefix = prefix[:common]
        if not prefix:
            raise LawVerifyError(
                f"object {root} spans more than one destination directory; a published tree "
                "object holds exactly one tree")
    return "/".join(prefix)


def verify_tree_object(data: bytes, *, root: str) -> Dict[str, Any]:
    """Full verification of ONE object: container safety, the rule, and the address.

    Returns ``{root, extract_to, files, hashed, excluded_key_material, tar_sha256}``.
    """
    check_root(root, "object root")
    extract_to, files = read_tree_object(data, root=root)
    allowed_unhashed = set(key_material_exclusions(extract_to))
    unhashed = sorted(rel for rel in files
                      if not is_hashed_path(rel) and rel not in allowed_unhashed)
    if unhashed:
        raise LawVerifyError(
            f"object {root} ({extract_to}) carries {unhashed[:5]} — file(s) the tree-hash rule "
            "does NOT hash, so the address says nothing about them, and extracting them would put "
            "unaddressed content in the law cache. The only tolerated exception is a documented "
            f"key-material path ({sorted(allowed_unhashed) or 'none for this tree'})")
    present_key_material = sorted(rel for rel in files if rel in allowed_unhashed)
    computed = tree_hash_from_files(files, key_material_exclusions(extract_to))
    if computed != root:
        raise LawVerifyError(
            f"the object served at {root} extracts to a {extract_to} tree whose tree hash is "
            f"{computed}. The address IS the identity the signed receipt's code_roots binds, so a "
            "tree that does not reproduce it is not the published law, whatever it claims to be")
    return {"root": root, "extract_to": extract_to, "files": files,
            "hashed": sum(1 for rel in files if is_hashed_path(rel, allowed_unhashed)),
            "excluded_key_material": present_key_material,
            "tar_sha256": _sha256(data)}


# --------------------------------------------------------------------------- #
# the publication manifest
# --------------------------------------------------------------------------- #
def _parse_json_strict(data: bytes, what: str) -> Any:
    def no_duplicates(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise LawVerifyError(f"{what}: duplicate object key {key!r}")
            seen[key] = value
        return seen

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except UnicodeDecodeError as exc:
        raise LawVerifyError(f"{what} is not UTF-8: {exc}") from exc
    except ValueError as exc:
        raise LawVerifyError(f"{what} is not JSON: {exc}") from exc


def parse_manifest(data: bytes) -> Dict[str, Any]:
    """Structural validation of a publication manifest. Says what it needs, refuses the rest."""
    document = _parse_json_strict(data, "the publication manifest")
    if not isinstance(document, dict):
        raise LawVerifyError("the publication manifest must be a JSON object")
    fmt = document.get("format")
    if fmt not in MANIFEST_FORMATS:
        raise LawVerifyError(
            f"unknown publication manifest format {fmt!r}; this client understands "
            f"{list(MANIFEST_FORMATS)}")
    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise LawVerifyError("the publication manifest carries no files list")
    for entry in files:
        if not isinstance(entry, dict):
            raise LawVerifyError("every manifest files[] entry must be an object")
        for field in ("file", "sha256", "bytes"):
            if field not in entry:
                raise LawVerifyError(f"a manifest files[] entry is missing {field!r}")
        check_root(entry["sha256"], f"files[{entry['file']!r}].sha256")
        if not isinstance(entry["bytes"], int) or isinstance(entry["bytes"], bool) \
                or entry["bytes"] < 0:
            raise LawVerifyError(f"files[{entry['file']!r}].bytes must be a non-negative int")
    return document


#: Manifest spellings for "install these bytes at this relative path". Both are accepted because
#: the builder and this client are deliberately independent implementations of one format.
INSTALL_PATH_FIELDS = ("install_to", "install_path")
#: Spellings a publication may use to say "this entry is one FILE, not a packed tree".
SINGLE_FILE_KINDS = frozenset({"file", "single-file", "raw", "bytes"})


def _single_file_install_path(entry: Mapping[str, Any]) -> Optional[str]:
    """Where a single-file entry installs, or ``None`` when the entry is a packed tree.

    An explicit ``install_to``/``install_path`` wins. Otherwise a known ``code_roots_field`` names
    it — the publication builder already tags each entry with the field it satisfies, and the two
    single-file fields are a closed set here rather than a pattern, because "which code root is a
    file" is law, not a naming convention.
    """
    for field in INSTALL_PATH_FIELDS:
        value = entry.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().replace("\\", "/")
    field_name = entry.get("code_roots_field")
    if isinstance(field_name, str) and field_name in SINGLE_FILE_CODE_ROOTS:
        return SINGLE_FILE_CODE_ROOTS[field_name]
    kind = str(entry.get("object_kind") or "").strip().lower()
    if kind in SINGLE_FILE_KINDS:
        raise LawVerifyError(
            f"manifest entry {entry.get('file')!r} declares object_kind={kind!r} but names no "
            f"install path ({' / '.join(INSTALL_PATH_FIELDS)}) and no known "
            "code_roots_field. A file the publication will not say where to put is not something "
            "this client will guess at — guessing would put unaddressed content in the law cache")
    return None


def check_install_path(relpath: str, *, root: str) -> str:
    """A relative, non-escaping, POSIX path inside the cache. The path-traversal guard."""
    text = str(relpath or "").replace("\\", "/").strip()
    parts = text.split("/")
    if (not text or text.startswith("/") or ".." in parts or "" in parts
            or (len(text) > 1 and text[1] == ":")):
        raise LawVerifyError(
            f"object {root} declares the install path {relpath!r}, which is absolute or escaping. "
            "A published file installs INSIDE the law cache or not at all")
    return text


def law_objects(manifest: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """The manifest entries that are content-addressed TREE objects.

    An entry qualifies when its path's basename is a bare sha256 — which is how the publication set
    names an object by its code root — AND it is not a single-file object. Everything else in the
    set (README, AUDIT, the index) is documentation; this client does not need it to verify the law
    and does not fetch it, which keeps the trust surface to "the manifest, the six trees and the
    one posture file".
    """
    out = []
    for entry in manifest["files"]:
        name = str(entry["file"]).replace("\\", "/")
        base = name.rsplit("/", 1)[-1]
        if is_root(base) and _single_file_install_path(entry) is None:
            out.append({"root": base, "path": name, "sha256": entry["sha256"],
                        "bytes": int(entry["bytes"])})
    if not out:
        raise LawVerifyError(
            "the publication manifest names no content-addressed objects; a law publication set "
            "addresses each tree by its code root")
    return out


def law_files(manifest: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """The manifest entries that are content-addressed SINGLE FILES (spec D-3).

    Address rule: the raw ``sha256`` of the bytes, which is exactly what
    ``receipt.py::code_roots`` computes for the posture file. There is no container, so there is
    no container digest distinct from the address, and both are checked against the same value.
    """
    out = []
    for entry in manifest["files"]:
        name = str(entry["file"]).replace("\\", "/")
        base = name.rsplit("/", 1)[-1]
        install_to = _single_file_install_path(entry)
        if install_to is None:
            continue
        if not is_root(base):
            raise LawVerifyError(
                f"manifest entry {name!r} installs to {install_to!r} but is not addressed by a "
                "bare sha256; a published file is named by its own digest")
        out.append({"root": base, "path": name, "sha256": entry["sha256"],
                    "bytes": int(entry["bytes"]),
                    "install_to": check_install_path(install_to, root=base),
                    "code_roots_field": entry.get("code_roots_field")})
    return out


# --------------------------------------------------------------------------- #
# the local cache
# --------------------------------------------------------------------------- #
def default_cache_dir() -> str:
    """``$XDG_DATA_HOME/coretex/law``, else ``~/.local/share/coretex/law`` (spec §9.3)."""
    base = os.environ.get("XDG_DATA_HOME", "").strip()
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "coretex", "law")


class LawCache:
    """A materialized, verified law cache. Carries the three env pins and how it was obtained."""

    def __init__(self, root_dir: str, receipt: Mapping[str, Any]) -> None:
        self.root_dir = os.path.abspath(root_dir)
        self.receipt = dict(receipt)

    @property
    def publication_root(self) -> str:
        return self.receipt["publication_root"]

    @property
    def benchmark_v2_dir(self) -> str:
        return os.path.join(self.root_dir, "benchmark-v2")

    @property
    def coretex_memory_dir(self) -> str:
        return os.path.join(self.root_dir, "coretex-memory")

    def env(self) -> Dict[str, str]:
        """The three pins, exactly as F4 documents them."""
        return {ENV_REPO_ROOT: self.root_dir,
                ENV_BENCHMARK_V2: self.benchmark_v2_dir,
                ENV_MEMORY_RUNTIME: self.coretex_memory_dir}

    def export_lines(self) -> List[str]:
        return [f"export {key}={value}" for key, value in self.env().items()]

    def apply(self, environ=None) -> Dict[str, str]:
        """Set the pins in a process environment. See :func:`activate` for the import-order rule."""
        environ = os.environ if environ is None else environ
        pins = self.env()
        environ.update(pins)
        return pins

    @property
    def files(self) -> Dict[str, str]:
        """``{relpath: sha256}`` for the SINGLE-FILE objects this cache installed (D-3)."""
        recorded = self.receipt.get("files")
        return dict(recorded) if isinstance(recorded, Mapping) else {}

    @property
    def posture_path(self) -> Optional[str]:
        """Where ``receipt.py::code_roots`` will look for the candidate-isolation posture."""
        if POSTURE_RELPATH not in self.files:
            return None
        return os.path.join(self.root_dir, *POSTURE_RELPATH.split("/"))

    def as_dict(self) -> Dict[str, Any]:
        return {"cache_dir": self.root_dir, "publication_root": self.publication_root,
                "env": self.env(), "receipt": self.receipt}

    # -- verification ------------------------------------------------------- #
    def verify(self) -> Dict[str, str]:
        """Recompute EVERY tree hash AND every single-file digest from what is on disk right now.

        Run at load, not only at write. A cache is a directory on a machine other processes and
        other people can reach, so its integrity is a property of the present tense — and that
        applies to the seventh sealed root exactly as it applies to the six trees.
        """
        observed: Dict[str, str] = {}
        for extract_to, expected in sorted(self.receipt["trees"].items()):
            path = os.path.join(self.root_dir, *extract_to.split("/"))
            if not os.path.isdir(path):
                raise LawCacheError(
                    f"the law cache at {self.root_dir} is missing {extract_to}; it is incomplete "
                    "and will not be used")
            actual = tree_hash(path, key_material_exclusions(extract_to))
            if actual != expected:
                raise LawCacheError(
                    f"the law cache at {self.root_dir} no longer verifies: {extract_to} hashes to "
                    f"{actual}, the cache receipt binds {expected}. Something changed it after it "
                    "was written. Re-run sync-law (with --force) rather than trusting it")
            observed[extract_to] = actual
        for relpath, expected in sorted(self.files.items()):
            path = os.path.join(self.root_dir, *relpath.split("/"))
            try:
                with open(path, "rb") as handle:
                    actual = _sha256(handle.read())
            except OSError as exc:
                raise LawCacheError(
                    f"the law cache at {self.root_dir} is missing {relpath}: {exc}. It is "
                    "incomplete and will not be used") from exc
            if actual != expected:
                raise LawCacheError(
                    f"the law cache at {self.root_dir} no longer verifies: {relpath} hashes to "
                    f"{actual}, the cache receipt binds {expected}. Something changed it after it "
                    "was written. Re-run sync-law (with --force) rather than trusting it")
            observed[relpath] = actual
        return observed


def _write_receipt(dest: str, receipt: Mapping[str, Any]) -> None:
    with open(os.path.join(dest, CACHE_RECEIPT), "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=1, sort_keys=True)
        fh.write("\n")


def load_cache(publication_root: str, *, cache_dir: Optional[str] = None,
               verify: bool = True) -> LawCache:
    """An already-materialized cache for ``publication_root``, re-verified unless told otherwise."""
    check_root(publication_root, "publication root")
    base = cache_dir or default_cache_dir()
    root_dir = os.path.join(os.path.abspath(os.path.expanduser(base)), publication_root)
    receipt_path = os.path.join(root_dir, CACHE_RECEIPT)
    if not os.path.isfile(receipt_path):
        raise LawCacheError(
            f"no verified law cache for {publication_root} under {base}. Run "
            f"`coretex-validator sync-law --mirror URL` first")
    with open(receipt_path, "r", encoding="utf-8") as fh:
        receipt = json.load(fh)
    if receipt.get("format") != CACHE_RECEIPT_FORMAT:
        raise LawCacheError(f"{receipt_path} is not a {CACHE_RECEIPT_FORMAT} receipt")
    if receipt.get("publication_root") != publication_root:
        raise LawCacheError(
            f"{receipt_path} belongs to publication {receipt.get('publication_root')}, not "
            f"{publication_root}")
    cache = LawCache(root_dir, receipt)
    if verify:
        cache.verify()
    return cache


def find_cache(*, cache_dir: Optional[str] = None,
               publication_root: Optional[str] = None) -> Optional[LawCache]:
    """The cache a later command should use, or ``None``. Never guesses between two.

    With no root named: the single cache in the directory, if there is exactly one. If there are
    several, ``None`` is returned and the caller reports that the pin is ambiguous — picking one
    would make the active law a function of directory listing order. There is no baked-in root to
    break the tie, and there deliberately never was a good one to use for it.
    """
    base = os.path.abspath(os.path.expanduser(cache_dir or default_cache_dir()))
    if publication_root:
        try:
            return load_cache(publication_root, cache_dir=base)
        except LawCacheError:
            return None
    if not os.path.isdir(base):
        return None
    present = sorted(name for name in os.listdir(base)
                     if is_root(name) and os.path.isfile(os.path.join(base, name, CACHE_RECEIPT)))
    if not present:
        return None
    if len(present) != 1:
        return None
    try:
        return load_cache(present[0], cache_dir=base)
    except LawCacheError:
        return None


# --------------------------------------------------------------------------- #
# sync-law
# --------------------------------------------------------------------------- #
def sync_law(publication_root: str, *, mirror: str,
             cache_dir: Optional[str] = None, force: bool = False,
             timeout: float = 30.0, retries: int = 3,
             max_object_bytes: int = MAX_OBJECT_BYTES,
             required_trees: Sequence[str] = REQUIRED_TREES,
             required_files: Sequence[str] = REQUIRED_FILES) -> LawCache:
    """Fetch, verify and materialize the published admission law. The whole of §9.3.

    Order matters and is fail-closed at every step:

      1. locate the MANIFEST on the mirror, trying each known layout, and accept only bytes that
         hash to ``publication_root``. The layout that verified is then FIXED — later objects are
         never fetched from a different one, so a set cannot be assembled from two mirrors;
      2. parse it strictly (duplicate JSON keys refused) and take its content-addressed entries;
      3. fetch each object under a byte ceiling, check its tar digest against the manifest AND its
         byte length, then unpack it under the container-safety rules and recompute the TREE hash
         its own name is;
      4. refuse unless every required tree is present;
      5. materialize into a private temporary directory and ``os.replace`` it into place, so a
         reader never sees a half-installed cache;
      6. write the receipt recording exactly what was verified and how.

    ``force`` re-materializes over an existing cache. Without it, an existing cache that still
    verifies is returned untouched — and one that does NOT verify is an error, never a silent
    refresh, because "the cache was tampered with" is something an operator must be told.
    """
    check_root(publication_root, "publication root")
    base = os.path.abspath(os.path.expanduser(cache_dir or default_cache_dir()))
    dest = os.path.join(base, publication_root)
    if not force and os.path.isfile(os.path.join(dest, CACHE_RECEIPT)):
        return load_cache(publication_root, cache_dir=base)

    source = Mirror(mirror, timeout=timeout, retries=retries)
    layout, manifest_bytes, manifest_rule = _locate_manifest(source, publication_root)
    manifest = parse_manifest(manifest_bytes)
    entries = law_objects(manifest)
    file_entries = law_files(manifest)

    verified_files: List[Dict[str, Any]] = []
    for entry in file_entries:
        data = source.fetch(layout["object"].format(root=entry["root"]), limit=max_object_bytes)
        # NO CONTAINER, so the address and the "container digest" are one value, and both the
        # manifest's `sha256` and the address itself must equal sha256(bytes). That value is
        # precisely what `receipt.py::code_roots` computes for this file, which is why a raw-sha
        # check here is the whole verification rather than a transport check on top of one.
        if len(data) != entry["bytes"]:
            raise LawVerifyError(
                f"file object {entry['root']} is {len(data)} bytes; the publication manifest "
                f"binds {entry['bytes']}")
        digest = _sha256(data)
        if digest != entry["root"] or digest != entry["sha256"]:
            raise LawVerifyError(
                f"the bytes served for file object {entry['root']} hash to {digest}. The address "
                "IS the identity a signed receipt's code_roots binds, so bytes that do not "
                "reproduce it are not the published law, whatever they claim to be")
        verified_files.append({**entry, "data": data, "sha256_bytes": digest})

    verified: List[Dict[str, Any]] = []
    for entry in entries:
        data = source.fetch(layout["object"].format(root=entry["root"]), limit=max_object_bytes)
        if len(data) != entry["bytes"]:
            raise LawVerifyError(
                f"object {entry['root']} is {len(data)} bytes; the publication manifest binds "
                f"{entry['bytes']}")
        digest = _sha256(data)
        if digest != entry["sha256"]:
            raise LawVerifyError(
                f"the container served for {entry['root']} has sha256 {digest}; the publication "
                f"manifest binds {entry['sha256']}")
        verified.append(verify_tree_object(data, root=entry["root"]))

    trees = {item["extract_to"]: item["root"] for item in verified}
    missing = [name for name in required_trees if name not in trees]
    if missing:
        raise LawVerifyError(
            f"publication {publication_root} does not carry {missing}; deterministic admission "
            "needs all of "
            f"{list(required_trees)} and a partially-installed law is worse than none")
    files = {item["install_to"]: item["root"] for item in verified_files}
    missing_files = [name for name in required_files if name not in files]
    if missing_files:
        fields = ", ".join(sorted(
            field for field, path in SINGLE_FILE_CODE_ROOTS.items() if path in missing_files))
        raise LawVerifyError(
            f"publication {publication_root} does not carry {missing_files}. That file is a "
            f"SEALED code root ({fields}): benchmark-v2/validator/receipt.py::code_roots opens it "
            "at <repo_root>/" + POSTURE_RELPATH + " and hashes its bytes, so a cache without it "
            "cannot compute the roots any receipt binds and every replay refuses at code_roots. "
            "It is a single FILE rather than a tree, so it is published as a single-file object "
            "(one manifest entry addressed by sha256(bytes), with an install_to path) rather than "
            "as a tar")

    receipt = {
        "format": CACHE_RECEIPT_FORMAT,
        "publication_root": publication_root,
        "manifest_hash_rule": manifest_rule,
        "manifest_sha256": _sha256(manifest_bytes),
        "manifest_format": manifest["format"],
        "mirror": source.location,
        "mirror_layout": layout["name"],
        "tree_hash_rule": ("benchmark-v2/validator/receipt.py::tree_hash — sha256 over sorted "
                           "'<relpath> NUL <filesha> LF' lines; recomputed here from the bytes "
                           "that arrived, never taken from the container"),
        "trees": trees,
        "files": files,
        "file_objects": [{"root": item["root"], "install_to": item["install_to"],
                          "bytes": len(item["data"]),
                          "code_roots_field": item.get("code_roots_field"),
                          "hash_rule": "sha256-bytes"}
                         for item in sorted(verified_files, key=lambda i: i["install_to"])],
        "objects": [{"root": item["root"], "extract_to": item["extract_to"],
                     "files": len(item["files"]), "hashed_files": item["hashed"],
                     "tar_sha256": item["tar_sha256"],
                     "excluded_key_material": item["excluded_key_material"]}
                    for item in sorted(verified, key=lambda i: i["extract_to"])],
        "bytes_fetched": source.bytes_fetched,
        "required_trees": list(required_trees),
        "required_files": list(required_files),
    }
    _materialize(base, dest, verified, receipt, files=verified_files)
    return load_cache(publication_root, cache_dir=base)


def _locate_manifest(source: Mirror, publication_root: str):
    """The first layout whose MANIFEST verifies against ``publication_root``.

    A candidate that serves bytes which do not hash to the root is passed over rather than treated
    as an attack: during DISCOVERY, wrong bytes usually mean "that layout is not this mirror's"
    (a soft-404 HTML page hashes wrong too). Once a layout has verified it is fixed, and from then
    on wrong bytes are fatal. Every attempt is reported when none succeeds, so a failure names what
    was actually tried rather than "not found".
    """
    attempts = []
    for layout in LAYOUTS:
        relative = layout["manifest"].format(root=publication_root)
        try:
            data = source.fetch(relative, limit=MAX_MANIFEST_BYTES)
        except LawNotFound as exc:
            attempts.append(f"{layout['name']} ({relative}): {exc}")
            continue
        except LawTransportError as exc:
            attempts.append(f"{layout['name']} ({relative}): {exc}")
            continue
        rule = manifest_matches(data, publication_root)
        if rule is None:
            attempts.append(
                f"{layout['name']} ({relative}): served {len(data)} bytes hashing to "
                f"{_sha256(data)}, not {publication_root}")
            continue
        return layout, data, rule
    raise LawVerifyError(
        f"no layout on {source.location} serves publication {publication_root}. Tried:\n  "
        + "\n  ".join(attempts))


def _materialize(base: str, dest: str, verified: Sequence[Mapping[str, Any]],
                 receipt: Mapping[str, Any],
                 files: Sequence[Mapping[str, Any]] = ()) -> None:
    """Write the trees and single files to a private directory, then move it into place ATOMICALLY."""
    import shutil
    import tempfile

    os.makedirs(base, exist_ok=True)
    staging = tempfile.mkdtemp(prefix=".incomplete-", dir=base)
    try:
        for item in verified:
            tree_dir = os.path.join(staging, *item["extract_to"].split("/"))
            for relpath, data in sorted(item["files"].items()):
                path = os.path.join(tree_dir, *relpath.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fh:
                    fh.write(data)
        for item in files:
            path = os.path.join(staging, *item["install_to"].split("/"))
            os.makedirs(os.path.dirname(path) or staging, exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(item["data"])
        _write_receipt(staging, receipt)
        if os.path.exists(dest):
            # `os.replace` onto a non-empty directory fails, so an existing cache is moved aside
            # first and only removed once the new one is in place.
            retired = dest + ".retired-%d" % os.getpid()
            os.replace(dest, retired)
            try:
                os.replace(staging, dest)
            finally:
                shutil.rmtree(retired, ignore_errors=True)
        else:
            os.replace(staging, dest)
        staging = None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


# --------------------------------------------------------------------------- #
# activation
# --------------------------------------------------------------------------- #
class LawActivationError(LawError):
    """The pins were set too late to be read. See :func:`activate`."""


def activate(cache: LawCache, *, modules=None) -> Dict[str, str]:
    """Apply the pins, refusing if the modules that read them have ALREADY been imported.

    ``replay.py`` reads the three env vars at IMPORT time — they become the default arguments of
    the sandbox and the oracle screen — so setting them afterwards is a no-op that LOOKS like it
    worked. That is the worst possible failure mode for this feature: the run would BACKLOG at
    step 5 with a law cache sitting right there, and the report would say the trees were not
    configured. So it is refused with the reason, rather than silently ignored.
    """
    import sys

    modules = sys.modules if modules is None else modules
    already = modules.get(__package__ + ".replay")
    pins = cache.env()
    if already is not None and getattr(already, "_BENCH_V2_TREE", "") != pins[ENV_BENCHMARK_V2]:
        raise LawActivationError(
            "the admission trees were pinned AFTER coretex_validator.replay was imported, so the "
            "sandbox and oracle screen are still bound to "
            f"{getattr(already, '_BENCH_V2_TREE', '') or '(nothing)'}. Those defaults are read at "
            "import time; set the pins first (the CLI does this before importing anything that "
            "reads them) or pass the directories explicitly")
    return cache.apply()
