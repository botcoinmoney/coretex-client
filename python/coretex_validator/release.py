# SPDX-License-Identifier: Apache-2.0
"""Load and verify the closed first-public release directory.

The release binds this validator wheel; the validator independently verifies the supplied release
and all of its reachable bytes. No package tag, branch, signer list, or prior packet participates
in this authority.
"""
from __future__ import annotations

import hashlib
import base64
import configparser
import csv
import io
import json
import os
import re
import stat
import unicodedata
import zipfile
from email.parser import Parser
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from . import frontier as fr
from . import release_schema as schema
from .activation import PublicActivation
from .keccak256 import keccak256
from .rig_receipt_binding import RIG_BINDING_AUTHORITY_SHA256

MAX_FILE_BYTES = 64 * 1024 * 1024
LOCK_DOMAIN = b"\x19coretex.compatibility-lock/v1\n"
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_EMBEDDED_RELEASE_INPUTS = {
    "benchmark_law_root": "LAW.md",
    "canonical_suite_root": "CANONICAL-SUITE.v1.json",
    "counter_resource_law_root": "COUNTER_RESOURCE_LAW.v1.json",
    "rig_contract_authority_root": "RIG-CONTRACT-AUTHORITY.base-mainnet.json",
}
_LOCK_ROOT_RULES = {
    "benchmark_law_root": "sha256-bytes",
    "counter_resource_law_root": "sha256-frontier-canonical-json",
    "counter_root": "sha256-benchmark-canonical-json",
    "evaluation_law_root": "sha256-benchmark-canonical-json",
    "evaluation_law_scorer_root": "sha256-benchmark-canonical-json",
    "miner_module_abi_root": "sha256-frontier-canonical-json",
    "renderer_root": "sha256-benchmark-canonical-json",
    "rig_contract_authority_root": "sha256-bytes",
    "runtime_artifact_root": "sha256-file-tree",
    "runtime_protocol_abi_root": "sha256-frontier-canonical-json",
    "runtime_wheel_root": "sha256-bytes",
}
_LOCK_LITERALS = {
    "input_envelope_schema": {"kind": "literal", "schema": "envelope.v1", "version": 1},
    "module_manifest_schema": {
        "kind": "literal", "schema": "coretex-memory/release-manifest", "version": 4},
    "store_schema": {"kind": "literal", "schema": "coretex-memory/store", "version": 1},
    "transition_descriptor_schema": {
        "kind": "literal", "schema": "coretex-transition-descriptor-v3", "version": 33},
}
_LOCK_ROOT_RULES.update({
    "wasmtime_aarch64_wheel_root": "sha256-bytes",
    "wasmtime_amd64_wheel_root": "sha256-bytes",
})
_VALIDATOR_MEMBERS = frozenset({
    "CANONICAL-SUITE.v1.json", "COUNTER_RESOURCE_LAW.v1.json", "LAW.md",
    "RELEASE-CONTRACT.v1.json", "RIG-CONTRACT-AUTHORITY.base-mainnet.json",
    "RIG-WIRE-BINDING.v1.json", "__init__.py", "abi.py", "activation.py",
    "benchmark_replay.py", "compat_lock.py", "canonical_suite.py", "cli.py", "discovery.py",
    "dispatch.py", "epoch_law.py",
    "eval_artifact.py", "frontier.py", "join.py", "keccak256.py", "parent_execution.py",
    "publication.py", "receipt_chain.py", "release.py", "release_schema.py", "replay.py",
    "rig_events.py", "rig_receipt_binding.py", "rpc.py", "secp256k1.py", "snapshot.py",
})
_MAX_ARCHIVE_MEMBER_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024


class ReleaseError(ValueError):
    """The supplied directory is not one closed release graph."""


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json(raw: bytes, where: str) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseError(f"non-finite JSON value {value!r}")))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReleaseError(f"{where} is not duplicate-free UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"{where} must contain a JSON object")
    return value


def _safe_relative(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")) \
            or "\\" in value:
        raise ReleaseError(f"{where} is not a repository-relative path")
    if "\x00" in value or unicodedata.normalize("NFC", value) != value:
        raise ReleaseError(f"{where} is not a canonical Unicode path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ReleaseError(f"{where} is not a canonical relative path")
    return value


def _directory_chain(root: str, path: str) -> tuple[tuple[Any, ...], ...]:
    relative = os.path.relpath(os.path.dirname(path), root)
    if relative == os.pardir or relative.startswith(os.pardir + os.sep) \
            or os.path.isabs(relative):
        raise ReleaseError("release path escapes its root")
    directories = [root]
    current = root
    for part in (() if relative == "." else relative.split(os.sep)):
        current = os.path.join(current, part)
        directories.append(current)
    result = []
    for directory in directories:
        try:
            observed = os.lstat(directory)
        except OSError as exc:
            raise ReleaseError(f"cannot resolve release directory {directory}: {exc}") from exc
        if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise ReleaseError(f"release directory {directory} must not be a symlink")
        result.append((directory, observed.st_dev, observed.st_ino,
                       observed.st_mtime_ns, observed.st_ctime_ns))
    return tuple(result)


def _read(root: str, relative: str, *, expected_size: Optional[int] = None) -> bytes:
    relative = _safe_relative(relative, "release file path")
    root = os.path.realpath(root)
    if not os.path.isdir(root):
        raise ReleaseError("release root is unavailable or is not a directory")
    path = os.path.abspath(os.path.join(root, *relative.split("/")))
    if os.path.commonpath((root, path)) != root or path == root:
        raise ReleaseError(f"{relative} escapes the release root")
    directories = _directory_chain(root, path)
    try:
        first = os.lstat(path)
        if not stat.S_ISREG(first.st_mode) or stat.S_ISLNK(first.st_mode) or first.st_nlink != 1:
            raise ReleaseError(f"{relative} must be one regular non-linked file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ReleaseError(f"cannot safely open {relative}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (first.st_dev, first.st_ino) \
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseError(f"{relative} changed while it was opened")
        if before.st_size < 1 or before.st_size > MAX_FILE_BYTES:
            raise ReleaseError(f"{relative} is outside the 1..{MAX_FILE_BYTES} byte bound")
        if expected_size is not None and before.st_size != expected_size:
            raise ReleaseError(
                f"{relative} has {before.st_size} bytes, release declares {expected_size}")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1 << 20, remaining))
            if not chunk:
                raise ReleaseError(f"{relative} ended during its bounded read")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ReleaseError(f"{relative} changed during read")
        final = os.lstat(path)
        if any(getattr(first, field) != getattr(final, field) for field in fields):
            raise ReleaseError(f"{relative} changed while its path was resolved")
        if _directory_chain(root, path) != directories:
            raise ReleaseError(f"{relative} changed while its release directories were resolved")
        if os.path.realpath(path) != path:
            raise ReleaseError(f"{relative} resolves through a symlink")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _embedded(name: str) -> bytes:
    """Read one immutable wheel input without accepting an external search path."""
    return _read(_PACKAGE_DIR, name)


def _canonical_benchmark(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode()


def _object_root(raw: bytes, rule: str, where: str) -> str:
    if rule == "sha256-bytes":
        return _sha(raw)
    document = _json(raw, where)
    if rule == "sha256-frontier-canonical-json":
        return _sha(fr.canonical_bytes(document))
    if rule == "sha256-benchmark-canonical-json":
        return _sha(_canonical_benchmark(document))
    raise ReleaseError(f"{where} uses unsupported hash rule {rule!r}")


def _frontier_body_root(document: Mapping[str, Any], self_field: str) -> str:
    return _sha(fr.canonical_bytes(
        {key: value for key, value in document.items() if key != self_field}))


def _lock_root(document: Mapping[str, Any]) -> str:
    if set(document) != {"format", "lock_root", "locks"} \
            or document.get("format") != "coretex.compatibility-lock/v1":
        raise ReleaseError("COMPATIBILITY-LOCK.json has another or open schema")
    locks = document.get("locks")
    expected_names = set(_LOCK_ROOT_RULES) | set(_LOCK_LITERALS)
    if not isinstance(locks, Mapping) or set(locks) != expected_names:
        raise ReleaseError("COMPATIBILITY-LOCK.json does not carry the exact current lock set")
    for name, rule in _LOCK_ROOT_RULES.items():
        entry = locks[name]
        if not isinstance(entry, Mapping) \
                or set(entry) != {"hash_rule", "kind", "root"} \
                or entry.get("hash_rule") != rule or entry.get("kind") != "root":
            raise ReleaseError(f"COMPATIBILITY-LOCK.json locks.{name} has another shape or rule")
        value = entry.get("root")
        if not isinstance(value, str) or len(value) != 64 \
                or any(character not in "0123456789abcdef" for character in value) \
                or value == "0" * 64:
            raise ReleaseError(f"COMPATIBILITY-LOCK.json locks.{name}.root is invalid")
    for name, expected in _LOCK_LITERALS.items():
        if locks[name] != expected:
            raise ReleaseError(f"COMPATIBILITY-LOCK.json locks.{name} has another literal")
    body = {key: value for key, value in document.items() if key != "lock_root"}
    observed = keccak256(LOCK_DOMAIN + fr.canonical_bytes(body)).hex()
    if document["lock_root"] != observed or observed == "0" * 64:
        raise ReleaseError("COMPATIBILITY-LOCK.json does not reproduce lock_root")
    return observed


def _archive_name(value: str, where: str) -> str:
    if not value or value.startswith(("/", "\\")) or "\\" in value or "\x00" in value \
            or unicodedata.normalize("NFC", value) != value:
        raise ReleaseError(f"{where} has unsafe member path {value!r}")
    raw = value[:-1] if value.endswith("/") else value
    if not raw or any(part in ("", ".", "..") for part in raw.split("/")):
        raise ReleaseError(f"{where} has non-canonical member path {value!r}")
    return raw


def _wheel_payload(raw: bytes, *, package: str, distribution_stem: str,
                   where: str, version: str = "1.0.0",
                   tag: str = "py3-none-any") -> Dict[str, str]:
    """Verify one pure wheel's safe closed archive and return package member hashes."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        infos = archive.infolist()
    except zipfile.BadZipFile as exc:
        raise ReleaseError(f"{where} is not a wheel: {exc}") from exc
    try:
        if not infos or len(infos) > 20_000:
            raise ReleaseError(f"{where} has an invalid member count")
        files: Dict[str, bytes] = {}
        seen: set[str] = set()
        total = 0
        for info in infos:
            name = _archive_name(info.filename, where)
            if name in seen:
                raise ReleaseError(f"{where} repeats archive member {name!r}")
            seen.add(name)
            mode = (info.external_attr >> 16) & 0xffff
            kind = stat.S_IFMT(mode)
            if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or info.flag_bits & 1:
                raise ReleaseError(f"{where} contains unsafe archive member {name!r}")
            if info.is_dir():
                # A wheel has a RECORD-closed regular-file inventory.  Silently dropping an
                # explicit directory entry would let two different zip inventories validate as
                # the same wheel payload and would leave that member outside the deep read below.
                raise ReleaseError(
                    f"{where} contains directory member {info.filename!r}; "
                    "the wheel inventory must contain regular files only")
            if info.file_size > _MAX_ARCHIVE_MEMBER_BYTES:
                raise ReleaseError(f"{where} member {name!r} exceeds the byte bound")
            data = archive.read(info)
            if len(data) != info.file_size:
                raise ReleaseError(f"{where} member {name!r} changed size during read")
            total += len(data)
            if total > _MAX_ARCHIVE_TOTAL_BYTES:
                raise ReleaseError(f"{where} expands beyond the total byte bound")
            files[name] = data
    finally:
        archive.close()

    dist_prefix = distribution_stem + ".dist-info/"
    required_dist = {"METADATA", "WHEEL", "top_level.txt", "RECORD"}
    if package != "wasmtime":
        required_dist.add("entry_points.txt")
    dist_members = {name[len(dist_prefix):]: data for name, data in files.items()
                    if name.startswith(dist_prefix)}
    missing = required_dist - set(dist_members)
    unknown = {name for name in dist_members
               if name not in required_dist and not name.startswith("licenses/")}
    outside = {name for name in files
               if not name.startswith((package + "/", dist_prefix))}
    if missing or unknown or outside:
        raise ReleaseError(
            f"{where} is not a closed {package} wheel "
            f"(missing={sorted(missing)}, unknown={sorted(unknown)}, outside={sorted(outside)})")
    try:
        metadata = Parser().parsestr(dist_members["METADATA"].decode("utf-8"))
        wheel = Parser().parsestr(dist_members["WHEEL"].decode("utf-8"))
        top_level = dist_members["top_level.txt"].decode("utf-8")
        entry_points = None
        if package != "wasmtime":
            entry_points = configparser.ConfigParser(interpolation=None, strict=True)
            entry_points.optionxform = str
            entry_points.read_string(dist_members["entry_points.txt"].decode("utf-8"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise ReleaseError(f"{where} has invalid distribution metadata: {exc}") from exc
    distribution = {
        "coretex_memory": ("coretex-memory", "coretex-memory", "coretex_memory.cli:main"),
        "coretex_validator": (
            "coretex-validator", "coretex-validator", "coretex_validator.cli:main"),
        "coretex_memory_agent": (
            "coretex-memory-agent", "coretex", "coretex_memory_agent.cli:main"),
        "wasmtime": ("wasmtime", None, None),
    }[package]
    expected_name, command, target = distribution
    normalize = lambda value: "-".join(  # noqa: E731 - local metadata normalization
        part for part in re.split(r"[-_.]+", str(value).lower()) if part)
    if metadata.get_all("Name", []) != [expected_name] \
            or metadata.get_all("Version", []) != [version] \
            or wheel.get_all("Wheel-Version", []) != ["1.0"] \
            or wheel.get_all("Root-Is-Purelib", []) != ["true"] \
            or wheel.get_all("Tag", []) != [tag] \
            or normalize(metadata.get("Name", "")) != normalize(expected_name) \
            or top_level != package + "\n" \
            or (command is not None and (
                entry_points is None or entry_points.sections() != ["console_scripts"]
                or list(entry_points["console_scripts"].items()) != [(command, target)])):
        raise ReleaseError(f"{where} does not carry the exact declared wheel identity")
    record_name = dist_prefix + "RECORD"
    try:
        rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ReleaseError(f"{where} RECORD is invalid: {exc}") from exc
    recorded: Dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            raise ReleaseError(f"{where} RECORD has a non-three-column row")
        name = _archive_name(row[0], f"{where} RECORD")
        if name in recorded:
            raise ReleaseError(f"{where} RECORD repeats {name!r}")
        recorded[name] = (row[1], row[2])
    if set(recorded) != set(files):
        raise ReleaseError(f"{where} RECORD is not closed over the wheel")
    for name, data in files.items():
        digest, size = recorded[name]
        if name == record_name:
            if digest or size:
                raise ReleaseError(f"{where} RECORD binds itself")
            continue
        expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if digest != "sha256=" + expected or size != str(len(data)):
            raise ReleaseError(f"{where} RECORD binding for {name!r} is invalid")
    prefix = package + "/"
    payload = {name[len(prefix):]: _sha(data) for name, data in files.items()
               if name.startswith(prefix)}
    if "__init__.py" not in payload:
        raise ReleaseError(f"{where} has no {package} package")
    return dict(sorted(payload.items()))


def _file_tree_root(entries: Mapping[str, str]) -> str:
    body = "".join(f"{name}\0{digest}\n" for name, digest in sorted(entries.items()))
    return _sha(body.encode("utf-8"))


def _installed_validator_payload() -> Dict[str, str]:
    actual = {name for name in os.listdir(_PACKAGE_DIR)
              if os.path.isfile(os.path.join(_PACKAGE_DIR, name))}
    if actual != _VALIDATOR_MEMBERS:
        raise ReleaseError(
            "installed validator package is not the exact current surface "
            f"(missing={sorted(_VALIDATOR_MEMBERS-actual)}, "
            f"unexpected={sorted(actual-_VALIDATOR_MEMBERS)})")
    return {name: _sha(_embedded(name)) for name in sorted(_VALIDATOR_MEMBERS)}


@dataclass(frozen=True)
class ReleaseDirectory:
    path: str
    release: schema.RuntimeRelease
    integration: Mapping[str, Any]
    objects: Mapping[str, bytes]
    artifacts: Mapping[str, bytes]
    authority: Mapping[str, Any]

    @property
    def release_root(self) -> str:
        return self.release.release_root

    @property
    def genesis_frontier_root(self) -> str:
        return self.release.genesis_frontier_root

    def activation(self, path: str) -> PublicActivation:
        return PublicActivation.load(path)


def load(path: str) -> ReleaseDirectory:
    """Verify every file reachable from ``RELEASE.json`` and return its exact bytes."""
    root = os.path.abspath(os.path.expanduser(path))
    release_document = _json(_read(root, "RELEASE.json"), "RELEASE.json")
    try:
        parsed = schema.parse_release(release_document)
    except schema.ReleaseSchemaError as exc:
        raise ReleaseError(str(exc)) from exc
    integration_document = _json(
        _read(root, "RUNTIME-INTEGRATION.json"), "RUNTIME-INTEGRATION.json")
    try:
        integration = schema.parse_integration(integration_document, parsed)
    except schema.ReleaseSchemaError as exc:
        raise ReleaseError(str(exc)) from exc

    object_bytes: Dict[str, bytes] = {}
    for name, descriptor in parsed.raw["objects"].items():
        raw = _read(root, descriptor["path"], expected_size=descriptor["size"])
        if _sha(raw) != descriptor["raw_sha256"]:
            raise ReleaseError(f"objects.{name} does not match raw_sha256")
        observed = _object_root(raw, descriptor["hash_rule"], f"objects.{name}")
        if observed != descriptor["root"]:
            raise ReleaseError(
                f"objects.{name} resolves to {observed}, not {descriptor['root']}")
        object_bytes[name] = raw

    # The release binds this wheel, while these four one-way inputs let the wheel independently
    # refuse a release built from another law, suite, counter law, or deployed rig authority.  A
    # canonical-JSON object is compared by its declared rule; byte-addressed inputs compare byte
    # for byte.  RELEASE.json itself is intentionally not embedded (that would be self-reference).
    for object_name, member_name in _EMBEDDED_RELEASE_INPUTS.items():
        descriptor = parsed.raw["objects"][object_name]
        packaged = _embedded(member_name)
        packaged_root = _object_root(
            packaged, descriptor["hash_rule"], f"embedded {member_name}")
        if packaged_root != descriptor["root"]:
            raise ReleaseError(
                f"release {object_name} differs from the validator's embedded {member_name}")
        if descriptor["hash_rule"] == "sha256-bytes" \
                and packaged != object_bytes[object_name]:
            raise ReleaseError(
                f"release {object_name} bytes differ from embedded {member_name}")

    artifact_bytes: Dict[str, bytes] = {}
    for name, descriptor in parsed.raw["artifacts"].items():
        raw = _read(root, descriptor["path"], expected_size=descriptor["size"])
        if _sha(raw) != descriptor["sha256"]:
            raise ReleaseError(f"artifacts.{name} does not match sha256")
        artifact_bytes[name] = raw

    runtime_payload = _wheel_payload(
        artifact_bytes["runtime_wheel"], package="coretex_memory",
        distribution_stem="coretex_memory-1.0.0", where="artifacts.runtime_wheel")
    validator_payload = _wheel_payload(
        artifact_bytes["validator_wheel"], package="coretex_validator",
        distribution_stem="coretex_validator-1.0.0", where="artifacts.validator_wheel")
    _wheel_payload(
        artifact_bytes["adapter_wheel"], package="coretex_memory_agent",
        distribution_stem="coretex_memory_agent-1.0.0", where="artifacts.adapter_wheel")
    _wheel_payload(
        artifact_bytes["wasmtime_amd64_wheel"], package="wasmtime",
        distribution_stem="wasmtime-46.0.1", where="artifacts.wasmtime_amd64_wheel",
        version="46.0.1", tag="py3-none-manylinux1_x86_64")
    _wheel_payload(
        artifact_bytes["wasmtime_aarch64_wheel"], package="wasmtime",
        distribution_stem="wasmtime-46.0.1", where="artifacts.wasmtime_aarch64_wheel",
        version="46.0.1", tag="py3-none-manylinux2014_aarch64")

    payload_document = _json(
        object_bytes["validator_wheel_payload_root"], "validator wheel payload manifest")
    if set(payload_document) != {
            "distribution", "format", "members", "package", "version", "wheel_sha256"} \
            or payload_document.get("format") != "coretex.validator-wheel-payload/v1" \
            or payload_document.get("distribution") != "coretex-validator" \
            or payload_document.get("package") != "coretex_validator" \
            or payload_document.get("version") != "1.0.0" \
            or payload_document.get("wheel_sha256") \
            != parsed.raw["artifacts"]["validator_wheel"]["sha256"] \
            or payload_document.get("members") != validator_payload \
            or set(validator_payload) != _VALIDATOR_MEMBERS:
        raise ReleaseError("validator wheel payload manifest does not describe the exact wheel")
    if validator_payload != _installed_validator_payload():
        raise ReleaseError(
            "the release validator wheel differs from this installed validator package")

    portability = _json(
        artifact_bytes["portability_evidence"], "artifacts.portability_evidence")
    runtime_identity = portability.get("runtime_identity")
    if not isinstance(runtime_identity, Mapping) \
            or runtime_identity.get("runtime_artifact_root") != _file_tree_root(runtime_payload):
        raise ReleaseError(
            "portability evidence does not bind the exact runtime wheel package payload")

    lock_document = _json(_read(root, "COMPATIBILITY-LOCK.json"), "COMPATIBILITY-LOCK.json")
    if _lock_root(lock_document) != parsed.raw["compatibility_lock_root"]:
        raise ReleaseError("release names another compatibility lock")
    locks = lock_document.get("locks")
    if not isinstance(locks, Mapping):
        raise ReleaseError("compatibility lock has no locks object")
    expected_lock_roots = {
        name: parsed.raw["objects"][name]["root"]
        for name in _LOCK_ROOT_RULES if name in parsed.raw["objects"]
    }
    expected_lock_roots.update({
        "runtime_artifact_root": _file_tree_root(runtime_payload),
        "runtime_wheel_root": parsed.raw["artifacts"]["runtime_wheel"]["sha256"],
        "wasmtime_aarch64_wheel_root":
            parsed.raw["artifacts"]["wasmtime_aarch64_wheel"]["sha256"],
        "wasmtime_amd64_wheel_root":
            parsed.raw["artifacts"]["wasmtime_amd64_wheel"]["sha256"],
    })
    for name, expected_root in expected_lock_roots.items():
        entry = locks.get(name)
        if not isinstance(entry, Mapping) or entry.get("kind") != "root" \
                or entry.get("root") != expected_root \
                or entry.get("hash_rule") != _LOCK_ROOT_RULES[name]:
            raise ReleaseError(f"compatibility lock and release disagree on {name}")

    runtime_config = integration.get("runtime_config")
    if not isinstance(runtime_config, Mapping) or set(runtime_config) == {"config_root"}:
        raise ReleaseError("runtime integration has no closed runtime config body")
    runtime_config_body = {
        key: value for key, value in runtime_config.items() if key != "config_root"}
    if runtime_config.get("config_root") != parsed.raw["runtime_config_root"] \
            or _canonical_benchmark(runtime_config_body) \
            != _canonical_benchmark(_json(
                object_bytes["runtime_config_root"], "objects.runtime_config_root")):
        raise ReleaseError("runtime integration runtime config is not its release object")
    evaluation_law = integration.get("evaluation_law")
    if not isinstance(evaluation_law, Mapping) or set(evaluation_law) == {"law_root"}:
        raise ReleaseError("runtime integration has no closed evaluation law body")
    evaluation_law_body = {
        key: value for key, value in evaluation_law.items() if key != "law_root"}
    if evaluation_law.get("law_root") != parsed.raw["law"]["evaluation_law_root"] \
            or _canonical_benchmark(evaluation_law_body) \
            != _canonical_benchmark(_json(
                object_bytes["evaluation_law_root"], "objects.evaluation_law_root")):
        raise ReleaseError("runtime integration evaluation law is not its release object")
    code_roots = integration.get("code_roots")
    expected_code_names = {
        "candidate_isolation_posture", "frontier", "generators", "miner_abi",
        "runtime_coretex_memory", "scoring", "validator"}
    if not isinstance(code_roots, Mapping) or set(code_roots) != expected_code_names \
            or any(not isinstance(value, str) or len(value) != 64
                   or any(character not in "0123456789abcdef" for character in value)
                   or value == "0" * 64 for value in code_roots.values()):
        raise ReleaseError("runtime integration has another or malformed code-root set")

    composition = _json(_read(root, "GENESIS-COMPOSITION.json"), "GENESIS-COMPOSITION.json")
    baseline = _json(_read(root, "GENESIS-BASELINE.json"), "GENESIS-BASELINE.json")
    frontier_record = _json(_read(root, "GENESIS-FRONTIER.json"), "GENESIS-FRONTIER.json")
    if _frontier_body_root(composition, "composition_root") \
            != parsed.raw["genesis"]["composition_root"]:
        raise ReleaseError("genesis composition does not reproduce the release root")
    if _frontier_body_root(baseline, "baseline_root") != parsed.raw["genesis"]["baseline_root"]:
        raise ReleaseError("genesis baseline does not reproduce the release root")
    if set(frontier_record) != {"format", "frontier_root", "manifest"} \
            or fr.frontier_root(frontier_record["manifest"]) != frontier_record["frontier_root"] \
            or frontier_record["frontier_root"] != parsed.genesis_frontier_root:
        raise ReleaseError("genesis frontier does not reproduce the release root")

    if set(composition) != {"composition_root", "format", "profiles"} \
            or composition.get("format") != "coretex.genesis-composition/v1" \
            or set(baseline) != {"baseline_root", "format", "law_id", "profiles", "suite_root"} \
            or baseline.get("format") != "coretex.genesis-baseline/v1" \
            or baseline.get("law_id") != parsed.raw["law"]["id"] \
            or baseline.get("suite_root") != parsed.raw["law"]["canonical_suite_root"]:
        raise ReleaseError("genesis composition or baseline has another closed product shape")
    frontier_manifest = frontier_record["manifest"]
    if not isinstance(frontier_manifest, Mapping) or set(frontier_manifest) != {
            "benchmark_law_root", "default_composition_root", "epoch", "format",
            "parent_frontier_root", "profiles", "runtime_abi_root"} \
            or frontier_manifest.get("format") != "coretex.memory-frontier.v1" \
            or frontier_manifest.get("epoch") != 0 \
            or frontier_manifest.get("parent_frontier_root") != "0" * 64 \
            or frontier_manifest.get("benchmark_law_root") \
            != parsed.raw["law"]["benchmark_law_root"] \
            or frontier_manifest.get("default_composition_root") \
            != parsed.raw["genesis"]["composition_root"] \
            or frontier_manifest.get("runtime_abi_root") \
            != parsed.raw["objects"]["miner_module_abi_root"]["root"]:
        raise ReleaseError("genesis frontier has another product identity")

    composition_profiles = composition.get("profiles")
    baseline_profiles = baseline.get("profiles")
    frontier_profiles = frontier_manifest.get("profiles")
    profile_ids = set(parsed.raw["genesis"]["profile_releases"])
    if not isinstance(composition_profiles, Mapping) \
            or not isinstance(baseline_profiles, Mapping) \
            or not isinstance(frontier_profiles, Mapping) \
            or set(composition_profiles) != profile_ids \
            or set(baseline_profiles) != profile_ids or set(frontier_profiles) != profile_ids:
        raise ReleaseError("genesis documents carry different profile sets")

    miner_abi = _json(object_bytes["miner_module_abi_root"], "objects.miner_module_abi_root")
    expected_miner_abi_fields = {
        "admission_report_schema", "admission_ruleset_root", "bundle_files", "capability_ids",
        "format", "hook_names", "input_schema_versions", "manifest_schema",
        "module_abi_version", "module_manifest_schema_version", "policy_abi_version",
        "source_provenance_base_modules", "store_schema_version", "wrapper_format",
    }
    if set(miner_abi) != expected_miner_abi_fields \
            or miner_abi.get("format") != "coretex.memory-frontier.v1/runtime-abi-pin" \
            or not isinstance(miner_abi.get("hook_names"), list) \
            or not isinstance(miner_abi.get("capability_ids"), list):
        raise ReleaseError("miner-module ABI object has another or open shape")
    expected_reference_abi = {
        "capabilities": miner_abi["capability_ids"],
        "hooks": miner_abi["hook_names"],
        "id": "coretex-memory/miner-module/v1",
        "module_version": miner_abi["module_abi_version"],
        "policy_version": miner_abi["policy_abi_version"],
    }

    for profile, binding in parsed.raw["genesis"]["profile_releases"].items():
        document = _json(_read(root, binding["path"]), f"reference release {profile}")
        if fr.sha256_hex(fr.canonical_bytes(document)) != binding["root"]:
            raise ReleaseError(f"reference release {profile} does not reproduce its root")
        if set(document) != {"abi", "exec", "format", "profile_id", "reference_runtime"} \
                or document.get("format") != "coretex.genesis-reference-release/v1" \
                or document.get("profile_id") != profile or document.get("exec") != "reference" \
                or document.get("reference_runtime") != {
                    "id": "reference-runtime", "protocol": "rrm1"} \
                or document.get("abi") != expected_reference_abi:
            raise ReleaseError(
                f"reference release {profile} is not the release-bound builtin runtime")
        if composition_profiles[profile] != {"exec": "reference", "release_root": binding["root"]} \
                or frontier_profiles[profile] != binding["root"]:
            raise ReleaseError(f"genesis composition/frontier disagrees on {profile}")
        baseline_entry = baseline_profiles[profile]
        if not isinstance(baseline_entry, Mapping) or set(baseline_entry) != {
                "law_id", "partitions", "profile_id", "release_root", "stored_vector_root",
                "suite_root"}:
            raise ReleaseError(f"genesis baseline {profile} has another shape")
        baseline_body = {
            key: value for key, value in baseline_entry.items() if key != "stored_vector_root"}
        if baseline_entry.get("law_id") != parsed.raw["law"]["id"] \
                or baseline_entry.get("profile_id") != profile \
                or baseline_entry.get("release_root") != binding["root"] \
                or baseline_entry.get("suite_root") != parsed.raw["law"]["canonical_suite_root"] \
                or baseline_entry.get("stored_vector_root") \
                != _sha(fr.canonical_bytes(baseline_body)):
            raise ReleaseError(f"genesis baseline {profile} does not reproduce its vector")

    authority = _json(object_bytes["rig_contract_authority_root"], "rig contract authority")
    if _sha(object_bytes["rig_contract_authority_root"]) != RIG_BINDING_AUTHORITY_SHA256:
        raise ReleaseError("release contract authority differs from this validator's wire binding")
    if authority.get("format") != "coretex.rig-contract-authority/v1" \
            or authority.get("chain_id") != 8453:
        raise ReleaseError("rig contract authority is not the Base mainnet authority")
    abi_objects = authority.get("abi_objects")
    if not isinstance(abi_objects, Mapping) or set(abi_objects) != {"mining", "registry", "verifier"}:
        raise ReleaseError("rig contract authority has another ABI object set")
    for role in ("mining", "registry", "verifier"):
        declaration = abi_objects[role]
        release_object = parsed.raw["objects"][f"rig_{role}_abi_root"]
        if not isinstance(declaration, Mapping) \
                or declaration.get("sha256") != release_object["root"] \
                or declaration.get("path") != release_object.get("authority_path"):
            raise ReleaseError(f"rig authority and release object disagree on {role} ABI")
    return ReleaseDirectory(root, parsed, integration, object_bytes, artifact_bytes, authority)


__all__ = ["MAX_FILE_BYTES", "ReleaseDirectory", "ReleaseError", "load"]
