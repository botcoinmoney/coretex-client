#!/usr/bin/env python3
"""Build and verify the deterministic first-public validator wheel and source archive.

This is the only package builder. It uses only the Python standard library, consumes one exact
source inventory, emits byte-stable archives, and then re-opens every decompressed member before
publishing either output. The externally supplied CoreTex RELEASE.json binds the wheel hash; the
wheel intentionally does not embed RELEASE.json or its own hash.
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

VERSION = "1.0.0"
DIST = "coretex_validator"
PACKAGE = "coretex_validator"
WHEEL_NAME = f"{DIST}-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"{DIST}-{VERSION}.tar.gz"
DIST_INFO = f"{DIST}-{VERSION}.dist-info"
SDIST_ROOT = f"{DIST}-{VERSION}"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4_096

PYTHON_MEMBERS = frozenset({
    "__init__.py", "abi.py", "activation.py", "benchmark_replay.py", "canonical_suite.py",
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


class BuildError(RuntimeError):
    """The source tree or an emitted archive is not the one public package."""


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


def _read_regular(path: Path, where: str) -> bytes:
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
    _scan(data, where)
    return data


def _source_files(root: Path) -> dict[str, bytes]:
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
        "Independent validation for the first-public CoreTex 1.0.0 release.\n"
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="dist")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    result = build(root, (root / args.out_dir).resolve(), check=args.check)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as exc:
        raise SystemExit(f"VALIDATOR RELEASE BUILD REFUSED: {exc}") from exc
