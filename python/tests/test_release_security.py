from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import zipfile
from typing import Optional

import pytest

from coretex_validator import frontier
from coretex_validator import release
from coretex_validator import publication
from coretex_validator import release_schema as schema
from coretex_validator.keccak256 import keccak256


def _lock():
    locks = {
        name: {"hash_rule": rule, "kind": "root", "root": f"{index:02x}" * 32}
        for index, (name, rule) in enumerate(release._LOCK_ROOT_RULES.items(), 1)
    }
    locks.update(copy.deepcopy(release._LOCK_LITERALS))
    document = {"format": "coretex.compatibility-lock/v1", "locks": locks}
    document["lock_root"] = keccak256(
        release.LOCK_DOMAIN + frontier.canonical_bytes(document)).hex()
    return document


def test_compatibility_lock_rule_set_is_closed_before_its_root_is_trusted():
    document = _lock()
    assert release._lock_root(document) == document["lock_root"]
    document["locks"]["counter_root"]["hash_rule"] = "sha256-bytes"
    body = {key: value for key, value in document.items() if key != "lock_root"}
    document["lock_root"] = keccak256(
        release.LOCK_DOMAIN + frontier.canonical_bytes(body)).hex()
    with pytest.raises(release.ReleaseError, match="counter_root"):
        release._lock_root(document)


def test_packaged_publication_rule_verifies_canonical_compatibility_lock_bytes():
    document = _lock()
    raw = publication.encode(document, publication.HASH_RULE_COMPATIBILITY_LOCK)
    assert publication.root_of(raw, publication.HASH_RULE_COMPATIBILITY_LOCK) \
        == document["lock_root"]


#: The fixture wheel names the version the PACKAGE declares, read rather than typed.
#: `release._wheel_payload` checks the archive's metadata against the release's own product
#: version, so a fixture frozen at an old version stops being a fixture for this package the
#: first time the release is retargeted.
_FIXTURE_VERSION = schema.PRODUCT_VERSION
_FIXTURE_STEM = f"coretex_validator-{_FIXTURE_VERSION}"


def _wheel(*, unsafe_member: Optional[str] = None) -> bytes:
    prefix = f"{_FIXTURE_STEM}.dist-info/"
    files = {
        "coretex_validator/__init__.py":
            f"__version__ = '{_FIXTURE_VERSION}'\n".encode(),
        prefix + "METADATA":
            ("Metadata-Version: 2.1\nName: coretex-validator\n"
             f"Version: {_FIXTURE_VERSION}\n").encode(),
        prefix + "WHEEL":
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        prefix + "entry_points.txt":
            b"[console_scripts]\ncoretex-validator = coretex_validator.cli:main\n",
        prefix + "top_level.txt": b"coretex_validator\n",
    }
    if unsafe_member is not None:
        files[unsafe_member] = b"bad\n"
    rows = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rows.append((name, "sha256=" + digest, str(len(data))))
    record = prefix + "RECORD"
    rows.append((record, "", ""))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        record_bytes = io.StringIO()
        csv.writer(record_bytes, lineterminator="\n").writerows(rows)
        archive.writestr(record, record_bytes.getvalue().encode())
    return output.getvalue()


def test_wheel_payload_verifies_record_and_exact_pure_metadata():
    payload = release._wheel_payload(
        _wheel(), package="coretex_validator",
        distribution_stem=_FIXTURE_STEM, where="fixture")
    assert payload == {
        "__init__.py": hashlib.sha256(
            f"__version__ = '{_FIXTURE_VERSION}'\n".encode()).hexdigest()}


def test_wheel_payload_rejects_archive_traversal_before_extracting():
    with pytest.raises(release.ReleaseError, match="member path"):
        release._wheel_payload(
            _wheel(unsafe_member="../escape"), package="coretex_validator",
            distribution_stem=_FIXTURE_STEM, where="fixture")


def test_wheel_payload_rejects_unrecorded_directory_members():
    raw = _wheel()
    source = zipfile.ZipFile(io.BytesIO(raw))
    output = io.BytesIO()
    with source, zipfile.ZipFile(output, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info))
        # RECORD remains otherwise closed.  A loader which silently skips directory entries
        # would accept these different archive bytes as the same package payload.
        target.writestr("coretex_validator/ignored/", b"")
    with pytest.raises(release.ReleaseError, match="directory member"):
        release._wheel_payload(
            output.getvalue(), package="coretex_validator",
            distribution_stem=_FIXTURE_STEM, where="fixture")
