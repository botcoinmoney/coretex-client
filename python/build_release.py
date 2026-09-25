#!/usr/bin/env python3
"""Build and verify the deterministic public validator wheel and source archive.

This is the only package builder. It uses only the Python standard library, consumes one exact
source inventory, emits byte-stable archives, and then re-opens every decompressed member before
publishing either output. The externally supplied CoreTex RELEASE.json binds the wheel hash; the
wheel intentionally does not embed RELEASE.json or its own hash.

The build target is an INPUT, never a literal: the version is whatever ``pyproject.toml``
declares under ``[project]``, and the wheel/sdist filenames are derived from it.  ``--version``
lets a caller assert the version it expects (it can only agree, never override), and
``--print-target`` lets a caller discover the target before spending a build.

Five package data members are not this repository's own text: they are the coordinator's law
sources, copied in.  ``--coordinator-repo`` plus ``--verify-law-inputs`` proves the embedded
bytes still equal that coordinator tree's own bytes (and that RELEASE-CONTRACT.v1.json still
names that tree's product and law), so a release cut can invoke this builder as a sub-build and
fail closed on drift.  ``--sync-law-inputs`` is the only path that rewrites those members, and it
never runs implicitly.
"""
from __future__ import annotations

import argparse
import base64
import configparser
import csv
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import tarfile
import tempfile
import unicodedata
import zipfile
from pathlib import Path
from typing import Iterable, Mapping

class BuildError(RuntimeError):
    """The source tree or an emitted archive is not the one public package."""


DIST = "coretex_validator"
PACKAGE = "coretex_validator"
PYPROJECT = "pyproject.toml"
#: A release version is MAJOR.MINOR.PATCH — the same shape the coordinator's
#: RELEASE-MANIFEST.<version>.json filename is built from, so one can address the other.
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4_096
#: A pyproject.toml large enough to hide a second [project] table in is not this one.
MAX_PYPROJECT_BYTES = 256 * 1024


def declared_version(root: Path) -> str:
    """Return the one version ``pyproject.toml`` declares under its ``[project]`` table.

    This is the single source of the build target.  The builder never restates a version, so a
    product version bump is one edit in one file and every derived name follows it.  The scan is
    table-aware on purpose: ``[project.urls]`` and ``[build-system]`` may not contribute a
    version, and two declarations under ``[project]`` are a drift, not a preference.
    """
    path = root / PYPROJECT
    try:
        if path.stat().st_size > MAX_PYPROJECT_BYTES:
            raise BuildError(f"{PYPROJECT} exceeds the {MAX_PYPROJECT_BYTES} byte bound")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise BuildError(f"{PYPROJECT} is not UTF-8: {exc}") from exc
    table = None
    found: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            table = stripped[1:-1].strip()
            continue
        if table != "project":
            continue
        match = re.fullmatch(r'version\s*=\s*"([^"]*)"', stripped)
        if match is not None:
            found.append(match.group(1))
    if len(found) != 1:
        raise BuildError(
            f"{PYPROJECT} must declare exactly one [project] version, found {len(found)}: "
            f"{found}")
    version = found[0]
    if not VERSION_RE.fullmatch(version):
        raise BuildError(
            f"{PYPROJECT} [project] version {version!r} is not a MAJOR.MINOR.PATCH release "
            f"version")
    return version


VERSION = declared_version(Path(__file__).resolve().parent)
WHEEL_NAME = f"{DIST}-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"{DIST}-{VERSION}.tar.gz"
DIST_INFO = f"{DIST}-{VERSION}.dist-info"
SDIST_ROOT = f"{DIST}-{VERSION}"

PYTHON_MEMBERS = frozenset({
    "__init__.py", "abi.py", "activation.py", "baseline_composition.py", "benchmark_replay.py", "canonical_suite.py",
    "cli.py", "compat_lock.py",
    "discovery.py", "dispatch.py", "epoch_law.py", "eval_artifact.py", "frontier.py",
    "join.py", "keccak256.py", "parent_execution.py", "publication.py",
    "receipt_chain.py", "release.py", "release_schema.py", "replay.py", "rig_events.py",
    "rig_receipt_binding.py", "rpc.py", "secp256k1.py", "snapshot.py",
})
DATA_MEMBERS = frozenset({
    "CANONICAL-SUITE.v1.json", "COUNTER_RESOURCE_LAW.v1.json", "LAW.md",
    "RELEASE-CONTRACT.v1.json", "RIG-CONTRACT-AUTHORITY.base-mainnet.json",
    "RIG-WIRE-BINDING.v1.json",
})
PACKAGE_MEMBERS = PYTHON_MEMBERS | DATA_MEMBERS
SDIST_TOP_LEVEL = frozenset({"README.md", "build_release.py", "pyproject.toml", "reproduce.sh"})

#: Package data members that are NOT this repository's own text: each one is a verbatim copy of a
#: file in the coordinator tree the release is cut from.  A stale copy here would ship a validator
#: that replays a law the coordinator no longer publishes, which is why the coordinator's own
#: release build refuses a wheel whose member hashes differ from its sources.
LAW_INPUT_MEMBERS = (
    "CANONICAL-SUITE.v1.json", "COUNTER_RESOURCE_LAW.v1.json", "LAW.md",
    "RIG-CONTRACT-AUTHORITY.base-mainnet.json", "RIG-WIRE-BINDING.v1.json",
)
#: The one law input the coordinator manifest does not name a path for; the coordinator's
#: build_current_release.py carries the same constant.
RIG_WIRE_BINDING_SOURCE = "v5/contract-authority/base-mainnet/rig-wire-binding.json"
#: Self-described, not copied: it names the release graph rather than carrying law text, and it
#: is checked field-by-field against the manifest instead of byte-by-byte against a source.
RELEASE_CONTRACT_MEMBER = "RELEASE-CONTRACT.v1.json"
MANIFEST_DIR = "v5"

#: The one test subdirectory the sdist admits (JSON parity fixtures only).
TEST_FIXTURES_DIR = "fixtures"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _private_markers() -> tuple[bytes, ...]:
    # Split the spellings so the scanner can inspect this builder when it is inside the sdist.
    return tuple(value.encode("ascii") for value in (
        "86deac65e365619c3601655b6768b6ef" + "1738943ab620f67d62368089d727919b",
        "4e81744ee61fd58602c04b23210b8ac7" + "dad66cc126986ac82db2af66200dbe9c",
        "c85857242b434cec35ae2cb0b67bd33f" + "96d1f0f425bc6265fec3758321e98ce5",
        "operator-g6-" + "champions-test",
        "benchmark-v2/g8-" + "deployment-signed/v1",
        "baseline-" + "default",
        '"roll' + 'back_id"',
        "coretex-runtime-cef-20260731-" + "r",
        "dominance-fixed-suite-" + "2026-08-25",
        "runtime-integration/" + "history",
        "coretex.law-cut-" + "packet/v1",
        "CORETEX_LAW_" + "CUT",
    ))


PRIVATE_MARKERS = _private_markers()
PRIVATE_TEXT = re.compile(
    (r"(?i)(?:pre[-_]" + r"rig|genesis[-_]" + r"rehearsal|mainnet[-_]" +
     r"rehearsal|coretex-runtime-cef-20260731-" + r"r[0-9]+)").encode("ascii"))
PRIVATE_KEY = re.compile(
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE " + r"KEY-----|"
     r"-----BEGIN ENCRYPTED PRIVATE " + r"KEY-----").encode("ascii"))
PRIVATE_BASENAMES = frozenset({
    ".env", "id_dsa", "id_ed25519", "id_rsa", "operator.key", "secrets.json",
    "signer.key", "wallet.json",
})


def _scan(data: bytes, where: str) -> None:
    hits = [marker.decode("ascii") for marker in PRIVATE_MARKERS if marker in data]
    for pattern in (PRIVATE_TEXT, PRIVATE_KEY):
        match = pattern.search(data)
        if match is not None:
            hits.append(match.group(0).decode("ascii", "replace"))
    if hits:
        raise BuildError(f"{where} contains private pre-public marker(s): {sorted(set(hits))}")


def _safe_name(name: str, where: str, *, directory: bool = False) -> str:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise BuildError(f"{where} has an unsafe member name {name!r}")
    if unicodedata.normalize("NFC", name) != name:
        raise BuildError(f"{where} member is not NFC-normalized: {name!r}")
    raw = name[:-1] if directory and name.endswith("/") else name
    if not raw or raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
        raise BuildError(f"{where} has an absolute member name {name!r}")
    parts = raw.split("/")
    if any(part in ("", ".", "..") for part in parts) or posixpath.normpath(raw) != raw:
        raise BuildError(f"{where} has a non-canonical member name {name!r}")
    if any(part.lower() in PRIVATE_BASENAMES for part in parts):
        raise BuildError(f"{where} contains a private key/config path {name!r}")
    _scan(name.encode("utf-8"), where)
    return raw


def _read_regular(path: Path, where: str, *, scan: bool = True) -> bytes:
    """Read one stable regular file.

    ``scan=False`` is for bytes that are only ever HASHED AND COMPARED, never published: a
    coordinator source being verified must be allowed to report "these two differ" rather than
    "this file mentions a private marker", or drift detection would fail for the wrong reason.
    Every path that WRITES coordinator bytes into the package keeps the scan on.
    """
    try:
        before = path.lstat()
    except OSError as exc:
        raise BuildError(f"cannot stat {where}: {exc}") from exc
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise BuildError(f"{where} must be one regular non-symlink file")
    if before.st_nlink != 1:
        raise BuildError(f"{where} must not be hard-linked")
    if not 0 < before.st_size <= MAX_MEMBER_BYTES:
        raise BuildError(f"{where} is outside the 1..{MAX_MEMBER_BYTES} byte bound")
    try:
        data = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise BuildError(f"cannot read {where}: {exc}") from exc
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                              value.st_ctime_ns)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise BuildError(f"{where} changed while it was read")
    if scan:
        _scan(data, where)
    return data


def _source_files(root: Path) -> dict[str, bytes]:
    # The archive names were derived from THIS file's pyproject.toml. A root whose pyproject
    # declares something else would be packaged under the wrong filename and the wrong METADATA,
    # so it is a refusal rather than a silent relabel.
    observed_version = declared_version(root)
    if observed_version != VERSION:
        raise BuildError(
            f"{root}/{PYPROJECT} declares version {observed_version!r}, but this builder targets "
            f"{VERSION!r}")
    package_dir = root / PACKAGE
    observed = {path.name for path in package_dir.iterdir() if path.is_file()}
    if observed != PACKAGE_MEMBERS:
        raise BuildError(
            f"package inventory drift (missing={sorted(PACKAGE_MEMBERS-observed)}, "
            f"unexpected={sorted(observed-PACKAGE_MEMBERS)})")
    unexpected = sorted(path.name for path in package_dir.iterdir()
                        if path.name != "__pycache__" and not path.is_file())
    if unexpected:
        raise BuildError(f"package contains non-file members: {unexpected}")
    files = {
        f"{PACKAGE}/{name}": _read_regular(package_dir / name, f"package member {name}")
        for name in sorted(PACKAGE_MEMBERS)
    }
    for name in sorted(SDIST_TOP_LEVEL):
        files[name] = _read_regular(root / name, f"source member {name}")
    tests_dir = root / "tests"
    tests = sorted(path for path in tests_dir.iterdir()
                   if path.is_file() and path.suffix == ".py")
    unexpected_tests = sorted(path.name for path in tests_dir.iterdir()
                              if path.name not in {"__pycache__", TEST_FIXTURES_DIR}
                              and not (path.is_file() and path.suffix == ".py"))
    if not tests or unexpected_tests:
        raise BuildError(
            f"tests must be one flat non-empty Python inventory plus an optional "
            f"{TEST_FIXTURES_DIR}/ of JSON; unexpected={unexpected_tests}")
    for path in tests:
        files[f"tests/{path.name}"] = _read_regular(path, f"test member {path.name}")
    fixtures_dir = tests_dir / TEST_FIXTURES_DIR
    if fixtures_dir.exists():
        # The law parity corpus and its materialized artifacts: flat, JSON-only, regular files, so
        # the sdist's source tests replay the same vectors the coordinator and evaluator do.
        fixtures = sorted(fixtures_dir.iterdir())
        unexpected_fixtures = sorted(
            path.name for path in fixtures
            if not (path.is_file() and path.suffix == ".json"))
        if not fixtures or unexpected_fixtures:
            raise BuildError(
                f"tests/{TEST_FIXTURES_DIR} must be a flat non-empty JSON inventory; "
                f"unexpected={unexpected_fixtures}")
        for path in fixtures:
            files[f"tests/{TEST_FIXTURES_DIR}/{path.name}"] = _read_regular(
                path, f"test fixture {path.name}")
    return dict(sorted(files.items()))


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: coretex-validator\n"
        f"Version: {VERSION}\n"
        "Summary: Public CoreTex validator: genesis fixed-suite admission replay.\n"
        "License: Apache-2.0\n"
        "Requires-Python: >=3.9\n"
        "Project-URL: Homepage, https://github.com/botcoinmoney/coretex-client\n"
        "Project-URL: Source, https://github.com/botcoinmoney/coretex-client\n"
        "Keywords: coretex,botcoin,base,validator,replay\n"
        "Classifier: Intended Audience :: Developers\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Classifier: Topic :: Security :: Cryptography\n"
        "\n"
        "# CoreTex validator\n\n"
        f"Independent validation for the prospective CoreTex {VERSION} fixed-suite release.\n"
    ).encode("utf-8")


def _record(files: Mapping[str, bytes]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow((name, "sha256=" + digest, str(len(data))))
    writer.writerow((f"{DIST_INFO}/RECORD", "", ""))
    return output.getvalue().encode("utf-8")


def build_wheel(source: Mapping[str, bytes]) -> bytes:
    files = {name: data for name, data in source.items() if name.startswith(PACKAGE + "/")}
    files.update({
        f"{DIST_INFO}/METADATA": _metadata(),
        f"{DIST_INFO}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: coretex-validator-build-release\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n").encode("ascii"),
        f"{DIST_INFO}/entry_points.txt": (
            "[console_scripts]\ncoretex-validator = coretex_validator.cli:main\n").encode("ascii"),
        f"{DIST_INFO}/top_level.txt": b"coretex_validator\n",
    })
    files[f"{DIST_INFO}/RECORD"] = _record(files)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return output.getvalue()


def _tar_info(name: str, data: bytes | None, *, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    info.mode = mode
    if data is None:
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.size = len(data)
    return info


def build_sdist(source: Mapping[str, bytes]) -> bytes:
    files = {f"{SDIST_ROOT}/{name}": data for name, data in source.items()}
    files[f"{SDIST_ROOT}/PKG-INFO"] = _metadata()
    directories = {SDIST_ROOT}
    for name in files:
        parent = posixpath.dirname(name)
        while parent:
            directories.add(parent)
            if parent == SDIST_ROOT:
                break
            parent = posixpath.dirname(parent)
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for directory in sorted(directories):
            archive.addfile(_tar_info(directory, None, mode=0o755))
        for name, data in sorted(files.items()):
            mode = 0o755 if name.endswith(("/reproduce.sh", "/build_release.py")) else 0o644
            archive.addfile(_tar_info(name, data, mode=mode), io.BytesIO(data))
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0) as stream:
        stream.write(tar_bytes.getvalue())
    return output.getvalue()


def _bounded_scan(files: Mapping[str, bytes], where: str) -> None:
    total = 0
    for name, data in files.items():
        _safe_name(name, where)
        if len(data) > MAX_MEMBER_BYTES:
            raise BuildError(f"{where}!/{name} exceeds the member bound")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise BuildError(f"{where} exceeds the decompressed aggregate bound")
        _scan(data, f"{where}!/{name}")


def verify_wheel(raw: bytes) -> dict[str, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not 0 < len(infos) <= MAX_ARCHIVE_MEMBERS:
                raise BuildError(
                    f"wheel member count is outside 1..{MAX_ARCHIVE_MEMBERS}")
            names = [_safe_name(info.filename, "wheel") for info in infos]
            if len(names) != len(set(names)) or any(info.is_dir() for info in infos):
                raise BuildError("wheel contains duplicate or directory members")
            files = {}
            for name, info in zip(names, infos):
                kind = stat.S_IFMT((info.external_attr >> 16) & 0xffff)
                if kind not in (0, stat.S_IFREG) or info.flag_bits & 0x1:
                    raise BuildError(f"wheel has non-regular or encrypted member {name}")
                if not 0 < info.file_size <= MAX_MEMBER_BYTES:
                    raise BuildError(f"wheel member {name} is outside the byte bound")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise BuildError(f"wheel member {name} changed while read")
                files[name] = data
    except (OSError, zipfile.BadZipFile) as exc:
        raise BuildError(f"wheel is not a readable zip: {exc}") from exc
    _bounded_scan(files, "wheel")
    expected_package = {f"{PACKAGE}/{name}" for name in PACKAGE_MEMBERS}
    package_members = {name for name in files if name.startswith(PACKAGE + "/")}
    expected_dist = {
        f"{DIST_INFO}/METADATA", f"{DIST_INFO}/WHEEL", f"{DIST_INFO}/entry_points.txt",
        f"{DIST_INFO}/top_level.txt", f"{DIST_INFO}/RECORD",
    }
    if package_members != expected_package or set(files) != expected_package | expected_dist:
        raise BuildError("wheel member inventory is not the exact current package/dist-info set")
    expected_metadata = {
        f"{DIST_INFO}/METADATA": _metadata(),
        f"{DIST_INFO}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: coretex-validator-build-release\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n").encode("ascii"),
        f"{DIST_INFO}/entry_points.txt": (
            "[console_scripts]\ncoretex-validator = coretex_validator.cli:main\n").encode("ascii"),
        f"{DIST_INFO}/top_level.txt": b"coretex_validator\n",
    }
    for name, expected in expected_metadata.items():
        if files[name] != expected:
            raise BuildError(f"wheel metadata member {name} is not the exact GA value")
    try:
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read_string(files[f"{DIST_INFO}/entry_points.txt"].decode("ascii"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise BuildError(f"wheel entry-point metadata is invalid: {exc}") from exc
    if parser.sections() != ["console_scripts"] or list(parser["console_scripts"].items()) != [
            ("coretex-validator", "coretex_validator.cli:main")]:
        raise BuildError("wheel does not expose only the public validator command")
    record_name = f"{DIST_INFO}/RECORD"
    rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"))))
    if any(len(row) != 3 for row in rows):
        raise BuildError("wheel RECORD contains a non-three-column row")
    records = {row[0]: row[1:] for row in rows}
    if len(rows) != len(records) or set(records) != set(files):
        raise BuildError("wheel RECORD is not unique and closed")
    for name, data in files.items():
        encoded_hash, encoded_size = records[name]
        if name == record_name:
            if encoded_hash or encoded_size:
                raise BuildError("wheel RECORD binds itself")
            continue
        expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if encoded_hash != "sha256=" + expected or encoded_size != str(len(data)):
            raise BuildError(f"wheel RECORD disagrees with {name}")
    return {name.removeprefix(PACKAGE + "/"): sha256(data)
            for name, data in sorted(files.items()) if name.startswith(PACKAGE + "/")}


def verify_sdist(raw: bytes, source: Mapping[str, bytes]) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            if not 0 < len(members) <= MAX_ARCHIVE_MEMBERS:
                raise BuildError(
                    f"sdist member count is outside 1..{MAX_ARCHIVE_MEMBERS}")
            names = [_safe_name(member.name, "sdist", directory=member.isdir())
                     for member in members]
            if len(names) != len(set(names)):
                raise BuildError("sdist contains duplicate members")
            files = {}
            directories = set()
            for name, member in zip(names, members):
                if member.isdir():
                    directories.add(name)
                    continue
                if not member.isfile():
                    raise BuildError(f"sdist has non-regular member {name}")
                if not 0 < member.size <= MAX_MEMBER_BYTES:
                    raise BuildError(f"sdist member {name} is outside the byte bound")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BuildError(f"sdist member {name} cannot be read")
                data = stream.read(MAX_MEMBER_BYTES + 1)
                if len(data) != member.size:
                    raise BuildError(f"sdist member {name} changed while read")
                files[name] = data
    except (OSError, tarfile.TarError) as exc:
        raise BuildError(f"sdist is not a readable tar.gz: {exc}") from exc
    _bounded_scan(files, "sdist")
    expected = {f"{SDIST_ROOT}/{name}" for name in source} | {f"{SDIST_ROOT}/PKG-INFO"}
    if set(files) != expected:
        raise BuildError("sdist member inventory is not the exact current source set")
    expected_directories = {SDIST_ROOT}
    for name in expected:
        parent = posixpath.dirname(name)
        while parent:
            expected_directories.add(parent)
            if parent == SDIST_ROOT:
                break
            parent = posixpath.dirname(parent)
    if directories != expected_directories:
        raise BuildError("sdist directory inventory is not the exact current source tree")
    if files[f"{SDIST_ROOT}/PKG-INFO"] != _metadata():
        raise BuildError("sdist PKG-INFO is not the exact GA metadata")
    for name, data in source.items():
        if files[f"{SDIST_ROOT}/{name}"] != data:
            raise BuildError(f"sdist changed source member {name}")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def manifest_relative_path(version: str = VERSION) -> str:
    """The coordinator-relative path of the release manifest for one product version."""
    if not VERSION_RE.fullmatch(version):
        raise BuildError(f"{version!r} is not a MAJOR.MINOR.PATCH release version")
    return f"{MANIFEST_DIR}/RELEASE-MANIFEST.{version}.json"


def _coordinator_path(coordinator_repo: Path, relative: str) -> Path:
    """Resolve one repository-relative coordinator path, refusing anything that escapes."""
    _safe_name(relative, f"coordinator source {relative!r}")
    return coordinator_repo / relative


def load_coordinator_manifest(coordinator_repo: Path, version: str = VERSION) -> dict:
    """Load the coordinator's release manifest for this build's product version."""
    relative = manifest_relative_path(version)
    raw = _read_regular(
        _coordinator_path(coordinator_repo, relative), f"coordinator {relative}", scan=False)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BuildError(f"coordinator {relative} is not readable JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BuildError(f"coordinator {relative} is not a JSON object")
    return manifest


def coordinator_law_sources(manifest: Mapping[str, object]) -> dict[str, str]:
    """Map each embedded law member to the coordinator path it must equal.

    Four of the five paths are READ OUT OF the manifest rather than hardcoded, so a coordinator
    that relocates its law text stays verifiable without a matching edit here.
    """
    law = manifest.get("law")
    authority = manifest.get("rig_contract_authority")
    if not isinstance(law, dict) or not isinstance(authority, dict):
        raise BuildError(
            "coordinator manifest has no law / rig_contract_authority table to resolve law "
            "inputs from")
    sources = {
        "CANONICAL-SUITE.v1.json": law.get("canonical_suite_path"),
        "COUNTER_RESOURCE_LAW.v1.json": law.get("counter_resource_law_path"),
        "LAW.md": law.get("law_md_path"),
        "RIG-CONTRACT-AUTHORITY.base-mainnet.json": authority.get("path"),
        "RIG-WIRE-BINDING.v1.json": RIG_WIRE_BINDING_SOURCE,
    }
    unresolved = sorted(name for name, value in sources.items()
                        if not isinstance(value, str) or not value)
    if unresolved:
        raise BuildError(f"coordinator manifest does not name a source for {unresolved}")
    if sorted(sources) != sorted(LAW_INPUT_MEMBERS):
        raise BuildError("law input source map is not the exact embedded law member set")
    return {name: str(value) for name, value in sources.items()}


def contract_identity(manifest: Mapping[str, object]) -> dict[str, dict]:
    """The exact ``product`` and ``law`` blocks RELEASE-CONTRACT.v1.json must carry.

    This mirrors the coordinator's own release build, which rejects a validator wheel whose
    contract does not name that build's product and law identity verbatim.
    """
    product = manifest.get("product")
    law = manifest.get("law")
    release = manifest.get("release")
    if not isinstance(product, dict) or not isinstance(law, dict) or not isinstance(release, dict):
        raise BuildError("coordinator manifest has no product / law / release identity to bind")
    for table, keys in (("product", ("name", "version")),
                        ("law", ("family", "revision", "decision_engine_id")),
                        ("release", ("sequence", "predecessor"))):
        missing = [key for key in keys if key not in manifest[table]]
        if missing:
            raise BuildError(f"coordinator manifest {table} is missing {missing}")
    return {
        "product": {
            "name": product["name"],
            "predecessor": release["predecessor"],
            "sequence": release["sequence"],
            "version": product["version"],
        },
        "law": {
            "decision_engine_id": law["decision_engine_id"],
            "family": law["family"],
            "id": f"{law['family']}.{law['revision']}",
            "revision": law["revision"],
        },
    }


def _load_release_contract(root: Path) -> tuple[bytes, dict]:
    path = root / PACKAGE / RELEASE_CONTRACT_MEMBER
    raw = _read_regular(path, f"package member {RELEASE_CONTRACT_MEMBER}", scan=False)
    try:
        contract = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BuildError(f"{RELEASE_CONTRACT_MEMBER} is not readable JSON: {exc}") from exc
    if not isinstance(contract, dict):
        raise BuildError(f"{RELEASE_CONTRACT_MEMBER} is not a JSON object")
    return raw, contract


def _serialize_contract(contract: Mapping[str, object]) -> bytes:
    """The file's own convention: two-space indent, sorted keys, one trailing newline."""
    return (json.dumps(contract, indent=2, sort_keys=True) + "\n").encode("utf-8")


def verify_law_inputs(root: Path, coordinator_repo: Path, *, version: str = VERSION) -> dict:
    """Compare every embedded law input, and the release contract's identity, to a coordinator.

    Writes nothing.  A member the coordinator cannot supply is reported as a failure with a null
    coordinator hash rather than raised, so one run names EVERY drifted member instead of
    stopping at the first.
    """
    manifest = load_coordinator_manifest(coordinator_repo, version)
    sources = coordinator_law_sources(manifest)
    entries = []
    for member in LAW_INPUT_MEMBERS:
        relative = sources[member]
        package_sha = sha256(_read_regular(
            root / PACKAGE / member, f"package member {member}", scan=False))
        detail = None
        try:
            coordinator_sha = sha256(_read_regular(
                _coordinator_path(coordinator_repo, relative),
                f"coordinator {relative}", scan=False))
        except BuildError as exc:
            coordinator_sha, detail = None, str(exc)
        entries.append({
            "coordinator_sha256": coordinator_sha,
            "detail": detail,
            "kind": "bytes",
            "member": member,
            "ok": coordinator_sha is not None and coordinator_sha == package_sha,
            "package_sha256": package_sha,
            "source": relative,
        })
    _, contract = _load_release_contract(root)
    identity = contract_identity(manifest)
    for field in ("product", "law"):
        observed = contract.get(field)
        entries.append({
            "coordinator_sha256": None,
            "detail": None if observed == identity[field] else
                      f"expected {json.dumps(identity[field], sort_keys=True)}, "
                      f"found {json.dumps(observed, sort_keys=True)}",
            "expected": identity[field],
            "kind": "identity",
            "member": f"{RELEASE_CONTRACT_MEMBER}:{field}",
            "observed": observed,
            "ok": observed == identity[field],
            "package_sha256": None,
            "source": manifest_relative_path(version),
        })
    failures = [entry["member"] for entry in entries if not entry["ok"]]
    return {
        "coordinator_repo": str(coordinator_repo),
        "entries": entries,
        "failures": failures,
        "manifest": manifest_relative_path(version),
        "ok": not failures,
        "version": version,
    }


def render_law_inputs(result: Mapping[str, object]) -> str:
    """One fixed-width line per checked member, in the builder's stable member order."""
    lines = [
        f"law inputs vs {result['coordinator_repo']} ({result['manifest']})",
    ]
    width = max(len(str(entry["member"])) for entry in result["entries"])
    for entry in result["entries"]:
        status = "OK  " if entry["ok"] else "DIFF"
        lines.append(f"  {status}  {str(entry['member']).ljust(width)}  {entry['source']}")
        if entry["kind"] == "bytes":
            lines.append(f"        package     {entry['package_sha256']}")
            lines.append(f"        coordinator {entry['coordinator_sha256'] or '<unreadable>'}")
            if entry["detail"] is not None:
                lines.append(f"        {entry['detail']}")
        elif not entry["ok"]:
            lines.append(f"        {entry['detail']}")
    lines.append("law inputs: OK" if result["ok"]
                 else "law inputs DRIFTED: " + ", ".join(result["failures"]))
    return "\n".join(lines)


def sync_law_inputs(root: Path, coordinator_repo: Path, *, version: str = VERSION) -> list[dict]:
    """Copy the coordinator's law bytes over the embedded members. The only writing path.

    The incoming bytes go through the ordinary private-marker scan: a coordinator file that still
    carries a pre-public marker must not become a published package member.
    """
    manifest = load_coordinator_manifest(coordinator_repo, version)
    sources = coordinator_law_sources(manifest)
    changed = []
    for member in LAW_INPUT_MEMBERS:
        relative = sources[member]
        incoming = _read_regular(
            _coordinator_path(coordinator_repo, relative), f"coordinator {relative}")
        target = root / PACKAGE / member
        current = _read_regular(target, f"package member {member}", scan=False)
        if current == incoming:
            continue
        _atomic_write(target, incoming)
        changed.append({
            "after": sha256(incoming),
            "before": sha256(current),
            "member": member,
            "source": relative,
        })
    return changed


def sync_release_contract(root: Path, coordinator_repo: Path, *,
                          version: str = VERSION) -> dict | None:
    """Rewrite ONLY the contract's ``product`` and ``law`` blocks from the coordinator manifest.

    Every other key is carried through untouched, and the rewrite refuses unless the file already
    round-trips through its own serialization convention — so a file someone reformatted by hand
    is reported rather than silently reformatted.  RELEASE-CONTRACT.v1.json is not
    self-addressed: it carries no hash of its own bytes (the coordinator hashes the wheel member
    externally), so there is nothing to recompute here.
    """
    manifest = load_coordinator_manifest(coordinator_repo, version)
    identity = contract_identity(manifest)
    raw, contract = _load_release_contract(root)
    if _serialize_contract(contract) != raw:
        raise BuildError(
            f"{RELEASE_CONTRACT_MEMBER} is not serialized as its own convention (two-space "
            f"indent, sorted keys, trailing newline); refusing to rewrite it")
    updated = dict(contract)
    updated["product"] = identity["product"]
    updated["law"] = identity["law"]
    data = _serialize_contract(updated)
    if data == raw:
        return None
    _atomic_write(root / PACKAGE / RELEASE_CONTRACT_MEMBER, data)
    return {
        "after": {"law": identity["law"], "product": identity["product"]},
        "before": {"law": contract.get("law"), "product": contract.get("product")},
        "member": RELEASE_CONTRACT_MEMBER,
        "source": manifest_relative_path(version),
    }


def target(out_dir: Path) -> dict:
    """The build target a caller can discover without spending a build."""
    return {
        "distribution": DIST,
        "out_dir": str(out_dir),
        "sdist_name": SDIST_NAME,
        "version": VERSION,
        "wheel_name": WHEEL_NAME,
    }


def build(root: Path, out_dir: Path, *, check: bool = False) -> dict:
    source = _source_files(root)
    wheel = build_wheel(source)
    sdist = build_sdist(source)
    payload = verify_wheel(wheel)
    verify_sdist(sdist, source)
    outputs = {WHEEL_NAME: wheel, SDIST_NAME: sdist}
    drift = []
    for name, data in outputs.items():
        path = out_dir / name
        if check:
            try:
                current = _read_regular(path, f"release output {name}")
            except BuildError:
                current = b""
            if current != data:
                drift.append(name)
        else:
            _atomic_write(path, data)
    result = {
        "drift": drift,
        "ok": not drift,
        "package_members": payload,
        "sdist": {"filename": SDIST_NAME, "sha256": sha256(sdist), "size": len(sdist)},
        "wheel": {"filename": WHEEL_NAME, "sha256": sha256(wheel), "size": len(wheel)},
    }
    if check and drift:
        raise BuildError(f"release outputs drift: {drift}")
    return result


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out-dir", default="dist",
                        help="where the wheel and sdist are written (default: dist)")
    parser.add_argument("--check", action="store_true",
                        help="rebuild and compare against existing outputs; refuse on drift")
    parser.add_argument("--version", dest="expect_version", metavar="VERSION",
                        help="assert the version this build targets; refused unless it equals "
                             f"the version {PYPROJECT} declares")
    parser.add_argument("--print-target", action="store_true",
                        help="print the target as one line of JSON and exit without building")
    parser.add_argument("--coordinator-repo", metavar="PATH",
                        help="the coordinator worktree this release is being cut from")
    parser.add_argument("--verify-law-inputs", action="store_true",
                        help="compare every embedded law input and the release contract identity "
                             "against --coordinator-repo; writes nothing, exits non-zero on drift")
    parser.add_argument("--sync-law-inputs", action="store_true",
                        help="copy --coordinator-repo's law bytes over the embedded members "
                             "(the only path that rewrites them; never implicit)")
    parser.add_argument("--sync-release-contract", action="store_true",
                        help="rewrite only RELEASE-CONTRACT.v1.json's product and law blocks from "
                             "--coordinator-repo's release manifest")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    out_dir = (root / args.out_dir).resolve()

    if args.expect_version is not None and args.expect_version != VERSION:
        raise BuildError(
            f"--version {args.expect_version!r} is not the version this tree declares: "
            f"{PYPROJECT} [project] version is {VERSION!r}")
    if args.print_target:
        print(json.dumps(target(out_dir), sort_keys=True))
        return 0

    wants_coordinator = (args.verify_law_inputs or args.sync_law_inputs
                         or args.sync_release_contract)
    if wants_coordinator and args.coordinator_repo is None:
        raise BuildError(
            "--verify-law-inputs/--sync-law-inputs/--sync-release-contract require "
            "--coordinator-repo")
    coordinator_repo = None
    if args.coordinator_repo is not None:
        if not wants_coordinator:
            # Naming a coordinator must never be enough to pull its bytes in.
            raise BuildError(
                "--coordinator-repo does nothing on its own; add --verify-law-inputs, "
                "--sync-law-inputs or --sync-release-contract. Law inputs are never synced "
                "implicitly")
        coordinator_repo = Path(args.coordinator_repo).resolve()
        if not coordinator_repo.is_dir():
            raise BuildError(f"--coordinator-repo {coordinator_repo} is not a directory")

    if args.sync_law_inputs:
        changed = sync_law_inputs(root, coordinator_repo)
        print(f"synced law inputs from {coordinator_repo}: "
              f"{len(changed)} of {len(LAW_INPUT_MEMBERS)} member(s) rewritten")
        for entry in changed:
            print(f"  {entry['member']}  {entry['before']} -> {entry['after']}  "
                  f"({entry['source']})")
    if args.sync_release_contract:
        rewritten = sync_release_contract(root, coordinator_repo)
        if rewritten is None:
            print(f"{RELEASE_CONTRACT_MEMBER} already names this release; unchanged")
        else:
            print(f"rewrote {RELEASE_CONTRACT_MEMBER} product/law from {rewritten['source']}")
            print(f"  product {json.dumps(rewritten['after']['product'], sort_keys=True)}")
            print(f"  law     {json.dumps(rewritten['after']['law'], sort_keys=True)}")
    if args.verify_law_inputs:
        result = verify_law_inputs(root, coordinator_repo)
        print(render_law_inputs(result))
        return 0 if result["ok"] else 1

    result = build(root, out_dir, check=args.check)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as exc:
        raise SystemExit(f"VALIDATOR RELEASE BUILD REFUSED: {exc}") from exc
