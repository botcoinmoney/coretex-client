# SPDX-License-Identifier: Apache-2.0
"""``sync-law`` end to end, against a REAL local mirror (spec §9.3).

Three mirror shapes, one code path: a threaded ``http.server``, a ``file://`` url and a bare local
directory. Every honest case must produce a cache whose three env pins point at trees that hash to
the roots the publication manifest names; every dishonest case must fail CLOSED with an error that
says which check refused and why.

The publication set is BUILT here, deterministically, in the exact shape the real one has (a
manifest whose ``files[]`` names each object by its code root, and objects that are ustar tars of
the tree they extract to). That is what makes the negative controls meaningful: each one is the
honest set with exactly one thing changed.
"""
from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import tarfile
import threading

import pytest

from coretex_validator import law


# --------------------------------------------------------------------------- #
# a synthetic publication set
# --------------------------------------------------------------------------- #
def tree_files(name):
    """A small but non-trivial tree for each of the six required destinations."""
    return {
        "__init__.py": f"# {name}\n".encode("utf-8"),
        "core.py": f"VALUE = {len(name)}\n".encode("utf-8"),
        "sub/helper.py": f"def helper():\n    return {name!r}\n".encode("utf-8"),
    }


def make_tar(extract_to, files):
    """A deterministic ustar tar, packed under ``extract_to`` — the published container shape."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for rel, data in sorted(files.items()):
            info = tarfile.TarInfo(f"{extract_to}/{rel}")
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build_publication(trees=None, *, trailing_newline=True):
    """``(publication_root, manifest_bytes, {relpath: bytes})`` for a complete honest set."""
    trees = trees or {name: tree_files(name) for name in law.REQUIRED_TREES}
    objects = {}
    entries = []
    for extract_to, files in sorted(trees.items()):
        root = law.tree_hash_from_files(files, law.key_material_exclusions(extract_to))
        blob = make_tar(extract_to, files)
        objects[root] = blob
        entries.append({"file": f"artifacts/{root}", "bytes": len(blob),
                        "sha256": hashlib.sha256(blob).hexdigest()})
    entries.append({"file": "README.md", "bytes": 3,
                    "sha256": hashlib.sha256(b"hi\n").hexdigest()})
    manifest = {"format": "coretex.rig-state.admission-closure-manifest/v1",
                "classification": "TEST", "epoch": 180, "files": entries,
                "production_authority": False}
    data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if trailing_newline:
        data += b"\n"
    root = law.manifest_root_candidates(data)[-1][1]
    return root, data, objects


def write_set(base, publication_root, manifest_bytes, objects, *, layout="publication-set"):
    """Lay a publication set out on disk in one of the layouts a mirror may use."""
    os.makedirs(base, exist_ok=True)
    if layout == "publication-set":
        with open(os.path.join(base, "MANIFEST.json"), "wb") as fh:
            fh.write(manifest_bytes)
        artifacts = os.path.join(base, "artifacts")
        os.makedirs(artifacts, exist_ok=True)
        for root, blob in objects.items():
            with open(os.path.join(artifacts, root), "wb") as fh:
                fh.write(blob)
    elif layout == "flat-cas":
        with open(os.path.join(base, publication_root), "wb") as fh:
            fh.write(manifest_bytes)
        for root, blob in objects.items():
            with open(os.path.join(base, root), "wb") as fh:
                fh.write(blob)
    else:                                                      # pragma: no cover - test bug
        raise AssertionError(layout)
    return base


@pytest.fixture()
def honest(tmp_path):
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects)
    return {"root": publication_root, "manifest": manifest_bytes, "objects": objects,
            "dir": base, "cache": str(tmp_path / "cache")}


# --------------------------------------------------------------------------- #
# an http mirror
# --------------------------------------------------------------------------- #
class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


@pytest.fixture()
def http_mirror(honest):
    directory = honest["dir"]

    def factory(*args, **kwargs):
        return _Handler(*args, directory=directory, **kwargs)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), factory)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# the honest path
# --------------------------------------------------------------------------- #
def test_sync_law_over_http_materializes_a_verified_cache(honest, http_mirror):
    cache = law.sync_law(honest["root"], mirror=http_mirror, cache_dir=honest["cache"])
    assert cache.publication_root == honest["root"]
    assert os.path.isfile(os.path.join(cache.root_dir, law.CACHE_RECEIPT))
    # every required tree is on disk and hashes to the root the publication named
    for extract_to in law.REQUIRED_TREES:
        path = os.path.join(cache.root_dir, *extract_to.split("/"))
        assert os.path.isdir(path)
        assert law.tree_hash(path, law.key_material_exclusions(extract_to)) \
            == cache.receipt["trees"][extract_to]
    # ...and the pins are the three F4 documents
    env = cache.env()
    assert set(env) == set(law.ENV_PINS)
    assert env[law.ENV_REPO_ROOT] == cache.root_dir
    assert env[law.ENV_BENCHMARK_V2] == os.path.join(cache.root_dir, "benchmark-v2")
    assert env[law.ENV_MEMORY_RUNTIME] == os.path.join(cache.root_dir, "coretex-memory")


def test_the_supported_layouts_are_exactly_the_two_a_real_mirror_can_serve():
    """A layout that can never verify is worse than no layout: it spends a fetch and a retry on
    every sync and then reports "not found" for a mirror that is serving perfectly.

    ``coretex-v5-object`` was one. It fetched ``{base}/coretex/v5/object/{root}`` raw, but the
    coordinator route it named refuses a request that carries no ``?hashRule``, envelopes its
    answer by default — and does not hold law tars in the first place, which live in the KIT, not
    in the object CAS. Removed rather than fixed, because there is nothing there to fix.
    """
    assert {entry["name"] for entry in law.LAYOUTS} == {"flat-cas", "publication-set"}


@pytest.mark.parametrize("layout", ["publication-set", "flat-cas"])
def test_every_supported_mirror_layout_produces_the_same_cache(tmp_path, layout):
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / layout), publication_root, manifest_bytes, objects,
                     layout=layout)
    cache = law.sync_law(publication_root, mirror=base,
                         cache_dir=str(tmp_path / f"cache-{layout}"))
    assert cache.receipt["mirror_layout"] == layout
    assert sorted(cache.receipt["trees"]) == sorted(law.REQUIRED_TREES)


def test_a_file_url_mirror_works(honest, tmp_path):
    cache = law.sync_law(honest["root"], mirror="file://" + honest["dir"],
                         cache_dir=honest["cache"])
    assert cache.verify()


def test_a_manifest_without_a_trailing_newline_is_addressed_by_its_plain_sha256(tmp_path):
    publication_root, manifest_bytes, objects = build_publication(trailing_newline=False)
    assert publication_root == hashlib.sha256(manifest_bytes).hexdigest()
    base = write_set(str(tmp_path / "m"), publication_root, manifest_bytes, objects)
    cache = law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "c"))
    assert cache.receipt["manifest_hash_rule"] == "sha256-bytes"


def test_a_published_manifest_ending_in_a_newline_uses_the_documented_rule(honest):
    """The real epoch-180 set records ``sha256(MANIFEST.json minus trailing newline)``."""
    cache = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    assert cache.receipt["manifest_hash_rule"] == "sha256-bytes-without-trailing-newline"
    assert hashlib.sha256(honest["manifest"][:-1]).hexdigest() == honest["root"]


def test_a_second_sync_reuses_the_verified_cache_without_refetching(honest, http_mirror):
    law.sync_law(honest["root"], mirror=http_mirror, cache_dir=honest["cache"])
    # A mirror that is now GONE must not matter: the cache is complete and re-verifies locally.
    cache = law.sync_law(honest["root"], mirror="http://127.0.0.1:1",
                         cache_dir=honest["cache"])
    assert cache.verify()


def test_force_rematerializes_over_an_existing_cache(honest):
    first = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    marker = os.path.join(first.root_dir, "benchmark-v2", "frontier", "core.py")
    assert os.path.isfile(marker)
    second = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"],
                          force=True)
    assert second.root_dir == first.root_dir
    assert second.verify()


def test_find_cache_locates_what_sync_law_wrote(honest):
    law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    found = law.find_cache(cache_dir=honest["cache"])
    assert found is not None and found.publication_root == honest["root"]
    assert law.find_cache(cache_dir=honest["cache"], publication_root=honest["root"]) is not None
    assert law.find_cache(cache_dir=honest["cache"], publication_root="f" * 64) is None


# --------------------------------------------------------------------------- #
# there is no default publication
# --------------------------------------------------------------------------- #
def test_there_is_no_baked_in_publication_root(honest):
    """A default root is a trust anchor wearing a convenience costume.

    The one that used to be here was a 2026-08-04 REHEARSAL, so ``sync-law`` with no ``--root``
    silently installed trees no live chain head had ever bound, and every later command picked
    them up. The publication a validator wants is the one the deployment it is verifying names —
    which it discovers, from the coordinator kit or the release. So absence is now the only
    behaviour: the root is a required argument, everywhere.
    """
    assert not hasattr(law, "DEFAULT_PUBLICATION_ROOT")
    with pytest.raises(TypeError):
        law.sync_law(mirror=honest["dir"], cache_dir=honest["cache"])       # noqa: B015


def test_two_caches_and_no_named_root_is_ambiguous_rather_than_arbitrary(honest, tmp_path):
    """Without a default to break the tie, a second cache makes the pin genuinely ambiguous —
    and picking one would make the active law a function of directory listing order."""
    law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    other_root, other_manifest, other_objects = build_publication(
        {name: {**tree_files(name), "extra.py": b"X = 2\n"} for name in law.REQUIRED_TREES})
    other_dir = write_set(str(tmp_path / "mirror2"), other_root, other_manifest, other_objects)
    law.sync_law(other_root, mirror=other_dir, cache_dir=honest["cache"])
    assert law.find_cache(cache_dir=honest["cache"]) is None
    # naming one is still unambiguous
    named = law.find_cache(cache_dir=honest["cache"], publication_root=other_root)
    assert named is not None and named.publication_root == other_root


def test_export_lines_are_shell_ready(honest):
    cache = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    lines = cache.export_lines()
    assert len(lines) == 3
    assert all(line.startswith("export CORETEX_") and "=" in line for line in lines)


# --------------------------------------------------------------------------- #
# negative controls — every one of these is the honest set with ONE thing changed
# --------------------------------------------------------------------------- #
def test_a_manifest_that_does_not_hash_to_the_named_root_is_refused(honest, tmp_path):
    with pytest.raises(law.LawVerifyError) as exc:
        law.sync_law("a" * 64, mirror=honest["dir"], cache_dir=honest["cache"])
    assert "no layout" in str(exc.value) and "Tried" in str(exc.value)


def test_a_substituted_object_is_refused(honest):
    """Same address, different bytes: caught by the manifest's tar digest."""
    root = sorted(honest["objects"])[0]
    with open(os.path.join(honest["dir"], "artifacts", root), "wb") as fh:
        fh.write(make_tar("benchmark-v2/frontier", {"evil.py": b"import os\n"}))
    with pytest.raises(law.LawVerifyError) as exc:
        law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    assert "sha256" in str(exc.value)


def test_an_object_whose_TREE_does_not_hash_to_its_address_is_refused(tmp_path):
    """The deeper check: the container digest agrees, the TREE hash does not."""
    trees = {name: tree_files(name) for name in law.REQUIRED_TREES}
    publication_root, manifest_bytes, objects = build_publication(trees)
    # Repack ONE object with different content and re-point the manifest's digest at it, so only
    # the tree-hash rule can catch the substitution.
    victim = "benchmark-v2/scoring"
    victim_root = law.tree_hash_from_files(trees[victim], ())
    forged = make_tar(victim, {"__init__.py": b"# tampered\n"})
    objects[victim_root] = forged
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    for entry in manifest["files"]:
        if entry["file"].endswith(victim_root):
            entry["bytes"] = len(forged)
            entry["sha256"] = hashlib.sha256(forged).hexdigest()
    manifest_bytes = json.dumps(manifest, sort_keys=True,
                                separators=(",", ":")).encode("utf-8") + b"\n"
    publication_root = law.manifest_root_candidates(manifest_bytes)[-1][1]
    base = write_set(str(tmp_path / "m"), publication_root, manifest_bytes, objects)
    with pytest.raises(law.LawVerifyError) as exc:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "c"))
    assert "tree hash" in str(exc.value)


def test_an_unhashed_payload_smuggled_into_a_tar_is_refused(tmp_path):
    """A ``__pycache__`` member is invisible to the address and would still be extracted."""
    trees = {name: tree_files(name) for name in law.REQUIRED_TREES}
    publication_root, manifest_bytes, objects = build_publication(trees)
    victim = "benchmark-v2/miner_abi"
    victim_root = law.tree_hash_from_files(trees[victim], ())
    smuggled = dict(trees[victim])
    smuggled["__pycache__/backdoor.pyc"] = b"payload"           # not hashed by the rule
    blob = make_tar(victim, smuggled)
    objects[victim_root] = blob
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    for entry in manifest["files"]:
        if entry["file"].endswith(victim_root):
            entry["bytes"] = len(blob)
            entry["sha256"] = hashlib.sha256(blob).hexdigest()
    manifest_bytes = json.dumps(manifest, sort_keys=True,
                                separators=(",", ":")).encode("utf-8") + b"\n"
    publication_root = law.manifest_root_candidates(manifest_bytes)[-1][1]
    base = write_set(str(tmp_path / "m"), publication_root, manifest_bytes, objects)
    with pytest.raises(law.LawVerifyError) as exc:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "c"))
    assert "does NOT hash" in str(exc.value)


def _object_with(members, *, extract_to="benchmark-v2/frontier"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for info, data in members:
            tf.addfile(info, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def test_a_symlink_member_is_refused():
    link = tarfile.TarInfo("benchmark-v2/frontier/evil")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    blob = _object_with([(link, None)])
    with pytest.raises(law.LawVerifyError) as exc:
        law.read_tree_object(blob, root="0" * 64)
    assert "symlink" in str(exc.value)


def test_an_absolute_or_traversing_member_is_refused():
    for name in ("/etc/passwd", "../../escape.py", "benchmark-v2/../../escape.py"):
        info = tarfile.TarInfo(name)
        info.size = 1
        blob = _object_with([(info, b"x")])
        with pytest.raises(law.LawVerifyError) as exc:
            law.read_tree_object(blob, root="0" * 64)
        assert "escaping" in str(exc.value) or "archive root" in str(exc.value)


def test_a_tar_spanning_two_destinations_is_refused():
    members = []
    for name in ("benchmark-v2/frontier/a.py", "coretex-memory/coretex_memory/b.py"):
        info = tarfile.TarInfo(name)
        info.size = 1
        members.append((info, b"x"))
    with pytest.raises(law.LawVerifyError) as exc:
        law.read_tree_object(_object_with(members), root="0" * 64)
    assert "more than one destination" in str(exc.value)


def test_a_duplicate_member_name_is_refused():
    members = []
    for _ in range(2):
        info = tarfile.TarInfo("benchmark-v2/frontier/a.py")
        info.size = 1
        members.append((info, b"x"))
    with pytest.raises(law.LawVerifyError) as exc:
        law.read_tree_object(_object_with(members), root="0" * 64)
    assert "more than once" in str(exc.value)


def test_something_that_is_not_a_tar_is_refused():
    with pytest.raises(law.LawVerifyError) as exc:
        law.read_tree_object(b"not a tar at all, just some bytes", root="0" * 64)
    assert "readable tar" in str(exc.value)


def test_a_publication_missing_a_required_tree_is_refused(tmp_path):
    trees = {name: tree_files(name) for name in law.REQUIRED_TREES[:-1]}
    publication_root, manifest_bytes, objects = build_publication(trees)
    base = write_set(str(tmp_path / "m"), publication_root, manifest_bytes, objects)
    with pytest.raises(law.LawVerifyError) as exc:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "c"))
    assert "coretex-memory/coretex_memory" in str(exc.value)
    # and nothing was left half-installed
    cache_dir = tmp_path / "c" / publication_root
    assert not cache_dir.exists()


def test_a_truncated_object_is_refused(honest):
    root = sorted(honest["objects"])[0]
    path = os.path.join(honest["dir"], "artifacts", root)
    with open(path, "rb") as fh:
        blob = fh.read()
    with open(path, "wb") as fh:
        fh.write(blob[:-1024])
    with pytest.raises(law.LawVerifyError) as exc:
        law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    assert "bytes" in str(exc.value)


def test_an_oversize_object_is_never_read(honest):
    with pytest.raises(law.LawTransportError) as exc:
        law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"],
                     max_object_bytes=64)
    assert "ceiling" in str(exc.value)


def test_a_duplicate_json_key_in_the_manifest_is_refused():
    with pytest.raises(law.LawVerifyError) as exc:
        law.parse_manifest(b'{"format": "x", "format": "y"}')
    assert "duplicate object key" in str(exc.value)


def test_an_unknown_manifest_format_is_refused():
    with pytest.raises(law.LawVerifyError):
        law.parse_manifest(json.dumps({"format": "something/else", "files": []}).encode("utf-8"))


def test_a_mirror_url_carrying_credentials_is_refused():
    with pytest.raises(law.LawTransportError) as exc:
        law.Mirror("https://user:secret@mirror.example/law")
    assert "credentials" in str(exc.value)


def test_a_malformed_publication_root_never_reaches_a_mirror(honest):
    for bad in ("../../etc", "0x" + "a" * 62, "A" * 64, ""):
        with pytest.raises(law.LawVerifyError):
            law.sync_law(bad, mirror=honest["dir"], cache_dir=honest["cache"])


# --------------------------------------------------------------------------- #
# the cache is verified in the PRESENT TENSE
# --------------------------------------------------------------------------- #
def test_a_tampered_cache_is_refused_at_load_not_silently_refreshed(honest):
    cache = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    victim = os.path.join(cache.root_dir, "benchmark-v2", "scoring", "core.py")
    with open(victim, "ab") as fh:
        fh.write(b"# edited after verification\n")
    with pytest.raises(law.LawCacheError) as exc:
        law.load_cache(honest["root"], cache_dir=honest["cache"])
    assert "no longer verifies" in str(exc.value)
    # sync_law does NOT paper over it either: the operator is told, not quietly re-synced.
    with pytest.raises(law.LawCacheError):
        law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    assert law.find_cache(cache_dir=honest["cache"]) is None


def test_a_deleted_tree_makes_the_cache_incomplete_not_partially_usable(honest):
    import shutil

    cache = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    shutil.rmtree(os.path.join(cache.root_dir, "coretex-memory"))
    with pytest.raises(law.LawCacheError) as exc:
        law.load_cache(honest["root"], cache_dir=honest["cache"])
    assert "incomplete" in str(exc.value)


def test_loading_a_cache_that_was_never_written_says_what_to_run(tmp_path):
    with pytest.raises(law.LawCacheError) as exc:
        law.load_cache("c" * 64, cache_dir=str(tmp_path))
    assert "sync-law" in str(exc.value)


# --------------------------------------------------------------------------- #
# activation ordering — the failure mode that would look like success
# --------------------------------------------------------------------------- #
def test_activating_after_replay_was_imported_is_refused(honest):
    import types

    cache = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    stale = types.ModuleType("coretex_validator.replay")
    stale._BENCH_V2_TREE = ""                                  # imported with no trees configured
    with pytest.raises(law.LawActivationError) as exc:
        law.activate(cache, modules={"coretex_validator.replay": stale})
    assert "import time" in str(exc.value)


def test_activating_before_anything_read_the_pins_sets_them(honest):
    cache = law.sync_law(honest["root"], mirror=honest["dir"], cache_dir=honest["cache"])
    environ = {}
    pins = cache.apply(environ)
    assert environ == pins == cache.env()
