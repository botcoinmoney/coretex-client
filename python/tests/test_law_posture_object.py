# SPDX-License-Identifier: Apache-2.0
"""D-3 (client half): the SEVENTH sealed root is a FILE, and it has to be installable law.

WHAT WAS BROKEN. ``verify-receipt`` on a real production receipt refused at ``code_roots`` with
``candidate isolation posture is unavailable at
<LAW-CACHE>/v5/production/CANDIDATE-ISOLATION.production.json: [Errno 2] No such file or
directory``. ``benchmark-v2/validator/receipt.py::code_roots`` reads that path relative to the
repo root — which, for a validator running on the law cache, IS the cache — and hashes its bytes
to produce ``code_roots.candidate_isolation_posture``, the seventh root every receipt binds. The
publication shipped six tars and no way to obtain the seventh, and ``LAW-PUBLICATION.json``'s own
``code_roots_note`` says why: it is the sha256 of a single FILE, not a tree hash, so it was gated
at build time and simply not packed.

WHAT THIS ADDS. ``law.py`` learns SINGLE-FILE manifest entries: verified by raw sha256 against the
address they were fetched under, installed at their canonical relative path inside the cache,
recorded in the cache receipt, re-verified on every load, and REQUIRED. Required rather than
optional because a cache without it cannot satisfy ``code_roots()`` at all — the same reasoning
that already refuses a publication missing one of the six trees ("a partially-installed law is
worse than none").

The fixture posture file is the REAL one: sha256
``77e581c35758e0e1bef0b58e07322b7d3f4a7e8c5f120ea7067a48f41cbf0e69``, the exact value the
epoch-184 receipt's ``code_roots`` block binds.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from coretex_validator import law

from test_law_sync import build_publication, write_set


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
POSTURE_FILE = os.path.join(FIXTURES, "law-posture", "CANDIDATE-ISOLATION.production.json")
POSTURE_ROOT = "77e581c35758e0e1bef0b58e07322b7d3f4a7e8c5f120ea7067a48f41cbf0e69"


def posture_bytes():
    with open(POSTURE_FILE, "rb") as handle:
        return handle.read()


def test_the_fixture_is_the_real_sealed_root():
    """A synthesised posture file would prove nothing: the value under test IS this sha256."""
    assert hashlib.sha256(posture_bytes()).hexdigest() == POSTURE_ROOT
    assert law.POSTURE_RELPATH == "v5/production/CANDIDATE-ISOLATION.production.json"
    assert law.SINGLE_FILE_CODE_ROOTS["candidate_isolation_posture"] == law.POSTURE_RELPATH


# --------------------------------------------------------------------------- #
# 1. a publication carrying the file installs it
# --------------------------------------------------------------------------- #
def test_a_single_file_entry_is_verified_by_raw_sha_and_installed_at_its_canonical_path(
        tmp_path):
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    cache = law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))

    installed = os.path.join(cache.root_dir, *law.POSTURE_RELPATH.split("/"))
    assert os.path.isfile(installed)
    with open(installed, "rb") as handle:
        assert hashlib.sha256(handle.read()).hexdigest() == POSTURE_ROOT
    # RECORDED, not merely written: a cache receipt that did not name it could not re-verify it
    assert cache.receipt["files"] == {law.POSTURE_RELPATH: POSTURE_ROOT}
    assert cache.posture_path == installed
    assert law.POSTURE_RELPATH in cache.receipt["required_files"]


def test_the_installed_file_sits_where_benchmark_v2_receipt_code_roots_looks_for_it(tmp_path):
    """``receipt.py::code_roots`` opens ``<repo_root>/v5/production/CANDIDATE-ISOLATION...`` and
    the activated cache IS ``repo_root`` (``CORETEX_ADMISSION_REPO_ROOT``). The two have to be the
    same path or the seventh root is unobtainable however carefully it was published."""
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    cache = law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))

    repo_root = cache.env()[law.ENV_REPO_ROOT]
    assert repo_root == cache.root_dir
    from_repo_root = os.path.join(repo_root, "v5", "production",
                                  "CANDIDATE-ISOLATION.production.json")
    with open(from_repo_root, "rb") as handle:
        assert hashlib.sha256(handle.read()).hexdigest() == POSTURE_ROOT


def test_loading_the_cache_re_verifies_the_file_not_only_the_trees(tmp_path):
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    cache = law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))

    installed = os.path.join(cache.root_dir, *law.POSTURE_RELPATH.split("/"))
    with open(installed, "ab") as handle:
        handle.write(b" ")
    with pytest.raises(law.LawCacheError) as excinfo:
        law.load_cache(publication_root, cache_dir=str(tmp_path / "cache"))
    assert law.POSTURE_RELPATH in str(excinfo.value)

    os.remove(installed)
    with pytest.raises(law.LawCacheError):
        law.load_cache(publication_root, cache_dir=str(tmp_path / "cache"))


# --------------------------------------------------------------------------- #
# 2. fail closed
# --------------------------------------------------------------------------- #
def test_bytes_that_do_not_hash_to_the_address_are_refused(tmp_path):
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    # tamper the served file, leaving the address it is served under alone
    with open(os.path.join(base, POSTURE_ROOT), "wb") as handle:
        handle.write(posture_bytes().replace(b'"uid": 65534', b'"uid": 00000'))
    with pytest.raises(law.LawVerifyError) as excinfo:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))
    assert POSTURE_ROOT in str(excinfo.value)
    assert not os.path.isdir(os.path.join(str(tmp_path / "cache"), publication_root))


def test_a_publication_that_lists_the_file_but_does_not_serve_it_is_refused(tmp_path):
    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    os.remove(os.path.join(base, POSTURE_ROOT))
    with pytest.raises(law.LawError):
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))


def test_a_publication_that_omits_the_file_entirely_is_refused_with_the_reason(tmp_path):
    """This is the shipped publication, and it is the one that produced D-3. It installs six
    verified trees and leaves the validator unable to compute the seventh root — so it is refused
    up front rather than at the first receipt replay, weeks later."""
    publication_root, manifest_bytes, objects = build_publication(posture=None)
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    with pytest.raises(law.LawVerifyError) as excinfo:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))
    message = str(excinfo.value)
    assert law.POSTURE_RELPATH in message
    assert "candidate_isolation_posture" in message


def test_a_single_file_entry_may_not_escape_the_cache(tmp_path):
    publication_root, manifest_bytes, objects = build_publication(
        posture_install_to="../../../etc/evil.json")
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    with pytest.raises(law.LawVerifyError) as excinfo:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))
    assert "escap" in str(excinfo.value) or ".." in str(excinfo.value)


def test_a_declared_single_file_object_with_no_install_path_is_refused_not_untarred(tmp_path):
    """A publication that says "this one is a file" without saying WHERE it installs has not told
    the client what to do with it, and guessing would put unaddressed content in the cache."""
    publication_root, manifest_bytes, objects = build_publication(posture_field=None,
                                                                 posture_install_to=None,
                                                                 posture_object_kind="file")
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    with pytest.raises(law.LawVerifyError) as excinfo:
        law.sync_law(publication_root, mirror=base, cache_dir=str(tmp_path / "cache"))
    assert "install" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# 3. the report says what was installed
# --------------------------------------------------------------------------- #
def test_setup_and_sync_law_report_the_file_alongside_the_trees(tmp_path, capsys):
    from coretex_validator import cli

    publication_root, manifest_bytes, objects = build_publication()
    base = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                     layout="flat-cas")
    code = cli.main(["sync-law", "--mirror", base, "--root", publication_root,
                     "--cache-dir", str(tmp_path / "cache")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["law"]["receipt"]["files"] == {law.POSTURE_RELPATH: POSTURE_ROOT}
