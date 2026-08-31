# SPDX-License-Identifier: Apache-2.0
"""Execute the release-bound fixed benchmark instead of trusting reported scores.

The standalone validator deliberately does not carry a second hand-copied scorer.  The one public
release binds an offline miner kit containing the exact Benchmark-v2 support trees, runtime wheel,
and platform Wasmtime wheels.  This module verifies that closed kit, materializes it in a private
temporary checkout, installs no ambient dependency, and invokes Benchmark-v2's own unsigned-report
replayer in a network-denied child.  A report is accepted only when that child rebuilds its content
address byte-for-byte from the canonical suite, candidate, and exact public parent.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Mapping, Optional

from . import eval_artifact as evaluation
from . import release as release_module

_MANIFEST = "MINER-KIT.json"
_KIT_FORMAT = "coretex.miner-validator-kit/v1"
_SUPPORT_TREES = (
    "benchmark-v2/frontier",
    "benchmark-v2/generators",
    "benchmark-v2/kit",
    "benchmark-v2/miner_abi",
    "benchmark-v2/scoring",
    "benchmark-v2/validator",
)
_EXECUTION_TREES = tuple(tree for tree in _SUPPORT_TREES if tree != "benchmark-v2/kit")
_ISOLATION_BOOTSTRAP = "docker/coretex-candidate-sitecustomize.py"
_ISOLATION_MODULE = "v5/worker/candidate_isolation.py"
_ISOLATION_SOURCES = (_ISOLATION_BOOTSTRAP, _ISOLATION_MODULE)
_ROOT_FILES = ("benchmark-v2/LAW.md", "v5/COUNTER_RESOURCE_LAW.v1.json")
_MAX_MEMBERS = 20_000
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
_ROOT = re.compile(r"^[0-9a-f]{64}$")


class BenchmarkReplayError(RuntimeError):
    """The release cannot independently reproduce one reported benchmark result."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes, where: str) -> dict[str, Any]:
    def reject(pairs):
        value = {}
        for key, member in pairs:
            if key in value:
                raise BenchmarkReplayError(f"{where} repeats JSON key {key!r}")
            value[key] = member
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=reject,
            parse_constant=lambda token: (_ for _ in ()).throw(
                BenchmarkReplayError(f"{where} contains non-finite {token}")))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BenchmarkReplayError(f"{where} is not canonical-input JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise BenchmarkReplayError(f"{where} must contain an object")
    return value


def _closed(value: Any, fields: set[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BenchmarkReplayError(f"{where} has another or open schema")
    return value


def _tree_root(prefix: str, records: list[Mapping[str, Any]]) -> str:
    marker = prefix.rstrip("/") + "/"
    lines = []
    for record in records:
        path = record["path"]
        if not isinstance(path, str) or not path.startswith(marker):
            raise BenchmarkReplayError(f"kit support record escapes {prefix}")
        lines.append(f"{path[len(marker):]}\0{record['sha256']}\n")
    return _sha("".join(sorted(lines)).encode("utf-8"))


def _kit_files(release: release_module.ReleaseDirectory) -> dict[str, bytes]:
    """Return a fully inventoried kit; never call ``extractall`` on public bytes."""
    raw = release.artifacts["miner_validator_kit"]
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_MEMBERS:
                raise BenchmarkReplayError("miner kit member count is outside its bound")
            seen: set[str] = set()
            for member in members:
                name = release_module._archive_name(  # noqa: SLF001 - one package security rule
                    member.name, "miner kit")
                if name in seen:
                    raise BenchmarkReplayError(f"miner kit repeats member {name!r}")
                seen.add(name)
                if not member.isfile() or member.size < 1 or member.size > _MAX_MEMBER_BYTES:
                    raise BenchmarkReplayError(
                        f"miner kit {name!r} is not one bounded regular file")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BenchmarkReplayError(f"miner kit cannot read {name!r}")
                data = stream.read(_MAX_MEMBER_BYTES + 1)
                if len(data) != member.size:
                    raise BenchmarkReplayError(f"miner kit {name!r} changed during read")
                total += len(data)
                if total > _MAX_TOTAL_BYTES:
                    raise BenchmarkReplayError("miner kit decompressed size exceeds its bound")
                files[name] = data
    except (OSError, tarfile.TarError) as exc:
        raise BenchmarkReplayError(f"cannot inspect miner kit: {exc}") from exc

    document = _json(files.get(_MANIFEST, b""), _MANIFEST)
    _closed(document, {
        "closure", "format", "law", "members", "packages", "product", "support_trees",
    }, _MANIFEST)
    if document["format"] != _KIT_FORMAT \
            or document["product"] != {"name": "coretex", "version": "1.0.0"}:
        raise BenchmarkReplayError("miner kit has another public product identity")
    if document["closure"] != {
            "manifest_member": _MANIFEST,
            "release_binding": "RELEASE.json#/artifacts/miner_validator_kit",
            "self_hash_embedded": False}:
        raise BenchmarkReplayError("miner kit has another closure rule")

    member_rows = document["members"]
    if not isinstance(member_rows, list) or not member_rows:
        raise BenchmarkReplayError("miner kit has no member inventory")
    records: dict[str, Mapping[str, Any]] = {}
    for index, candidate in enumerate(member_rows):
        record = _closed(candidate, {"path", "role", "sha256", "size"},
                         f"miner kit members[{index}]")
        path = release_module._archive_name(record["path"], "miner kit inventory")  # noqa: SLF001
        if path == _MANIFEST or path in records or not isinstance(record["role"], str) \
                or not _ROOT.fullmatch(str(record["sha256"])) \
                or type(record["size"]) is not int or not 0 < record["size"] <= _MAX_MEMBER_BYTES:
            raise BenchmarkReplayError(f"miner kit has invalid member record {path!r}")
        data = files.get(path)
        if data is None or len(data) != record["size"] or _sha(data) != record["sha256"]:
            raise BenchmarkReplayError(f"miner kit member {path!r} differs from its inventory")
        records[path] = record
    if list(records) != sorted(records) or set(records) != set(files) - {_MANIFEST}:
        raise BenchmarkReplayError("miner kit inventory is not sorted and closed")

    packages = document["packages"]
    expected_roles = {
        "runtime_wheel", "validator_wheel", "adapter_wheel",
        "wasmtime_amd64_wheel", "wasmtime_aarch64_wheel",
    }
    if not isinstance(packages, list) or len(packages) != len(expected_roles):
        raise BenchmarkReplayError("miner kit has another package set")
    found_roles = set()
    for index, candidate in enumerate(packages):
        package = _closed(candidate, {
            "distribution", "filename", "role", "sha256", "size", "version",
        }, f"miner kit packages[{index}]")
        role = package["role"]
        if role not in expected_roles or role in found_roles:
            raise BenchmarkReplayError(f"miner kit repeats or invents package role {role!r}")
        found_roles.add(role)
        expected = release.release.raw["artifacts"][role]
        if package != {
                "distribution": expected["distribution"],
                "filename": expected["filename"],
                "role": role,
                "sha256": expected["sha256"],
                "size": expected["size"],
                "version": expected["version"]}:
            raise BenchmarkReplayError(f"miner kit package {role} differs from RELEASE.json")
        member = "artifacts/" + expected["filename"]
        if files.get(member) != release.artifacts[role] \
                or records.get(member, {}).get("role") != "package:" + role:
            raise BenchmarkReplayError(f"miner kit does not carry exact release bytes for {role}")
    if found_roles != expected_roles:
        raise BenchmarkReplayError("miner kit omits a release package role")

    support = document["support_trees"]
    if not isinstance(support, list) or [row.get("path") for row in support
                                        if isinstance(row, Mapping)] != list(_SUPPORT_TREES):
        raise BenchmarkReplayError("miner kit has another or non-canonical support-tree set")
    code_roots = release.integration["code_roots"]
    for index, candidate in enumerate(support):
        row = _closed(candidate, {"files", "path", "tree_sha256"},
                      f"miner kit support_trees[{index}]")
        tree = row["path"]
        tree_records = [record for path, record in records.items()
                        if path.startswith(tree + "/")]
        role = "support:" + tree.rsplit("/", 1)[-1]
        expected_root = code_roots.get(tree.rsplit("/", 1)[-1])
        observed = _tree_root(tree, tree_records)
        if type(row["files"]) is not int or row["files"] != len(tree_records) \
                or not tree_records or any(record["role"] != role for record in tree_records) \
                or row["tree_sha256"] != observed \
                or (tree != "benchmark-v2/kit" and expected_root != observed):
            raise BenchmarkReplayError(f"miner kit support tree {tree} does not close")
    for member in _ROOT_FILES:
        if records.get(member, {}).get("role") != "law":
            raise BenchmarkReplayError(f"miner kit omits current law input {member}")
    for member in _ISOLATION_SOURCES:
        if records.get(member, {}).get("role") != "candidate-isolation":
            raise BenchmarkReplayError(
                f"miner kit omits release-bound candidate isolation member {member}")
    allowed = {
        "artifacts/" + package["filename"] for package in packages
    } | set(_ROOT_FILES) | set(_ISOLATION_SOURCES)
    allowed.update(
        path for path in records
        if any(path.startswith(tree + "/") for tree in _SUPPORT_TREES))
    if set(records) != allowed:
        raise BenchmarkReplayError("miner kit carries a member outside its current surface")
    return files


def _wheel_files(raw: bytes, where: str) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > _MAX_MEMBERS:
                raise BenchmarkReplayError(f"{where} member count is outside its bound")
            for info in infos:
                name = release_module._archive_name(info.filename, where)  # noqa: SLF001
                # Empty regular members (notably Wasmtime's ``py.typed`` marker) are valid wheel
                # payload.  Directory entries remain forbidden and the aggregate/member ceilings
                # still bound extraction.
                if name in files or info.is_dir() or info.file_size < 0 \
                        or info.file_size > _MAX_MEMBER_BYTES:
                    raise BenchmarkReplayError(f"{where} contains invalid member {name!r}")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise BenchmarkReplayError(f"{where} member {name!r} changed during read")
                total += len(data)
                if total > _MAX_TOTAL_BYTES:
                    raise BenchmarkReplayError(f"{where} decompressed size exceeds its bound")
                files[name] = data
    except (OSError, zipfile.BadZipFile) as exc:
        raise BenchmarkReplayError(f"cannot inspect {where}: {exc}") from exc
    return files


def _write_files(root: Path, files: Mapping[str, bytes], *, prefixes: tuple[str, ...] = ()) -> None:
    for relative, data in sorted(files.items()):
        if prefixes and not any(relative.startswith(prefix) for prefix in prefixes):
            continue
        target = root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _seal_public_tree(temporary: Path, repo: Path) -> None:
    """Make the release tree traversable by uid 65534 but immutable to an unprivileged replay.

    ``mkdtemp`` is intentionally 0700.  The coordinator normally starts the trusted launcher as
    root and the candidate runs as uid 65534, so leaving that default in place makes the sandbox
    fail before it can read its own release-bound code.  Only the public, content-addressed repo is
    opened; the sibling control directory stays private and writable by the validator process.
    """
    os.chmod(temporary, 0o711)
    for directory, names, filenames in os.walk(repo, topdown=True, followlinks=False):
        os.chmod(directory, 0o555)
        for name in names:
            candidate = Path(directory) / name
            if not candidate.is_symlink():
                os.chmod(candidate, 0o555)
        for name in filenames:
            candidate = Path(directory) / name
            if not candidate.is_symlink():
                os.chmod(candidate, 0o444)


def _remove_temporary(root: Path) -> None:
    """Undo local read-only modes before removing the private materialization."""
    if not root.exists():
        return
    for directory, names, _filenames in os.walk(root, topdown=False, followlinks=False):
        for name in names:
            candidate = Path(directory) / name
            if not candidate.is_symlink():
                try:
                    os.chmod(candidate, 0o755)
                except OSError:
                    pass
        try:
            os.chmod(directory, 0o755)
        except OSError:
            pass
    shutil.rmtree(root, ignore_errors=True)


_CHILD = r'''
import ctypes, ctypes.util, errno, json, os, platform, socket, struct, sys, tempfile
payload = json.loads(sys.stdin.read())
site, bench = payload["site"], payload["bench"]
sys.path[:] = [site, bench] + [p for p in sys.path if p and "site-packages" not in p]

class F(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
class P(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
def stmt(code, k): return struct.pack("HBBI", code, 0, 0, k)
def jump(code, k, jt, jf): return struct.pack("HBBI", code, jt, jf, k)
machine = platform.machine().lower()
profiles = {"x86_64": (0xC000003E, 41), "amd64": (0xC000003E, 41),
            "aarch64": (0xC00000B7, 198), "arm64": (0xC00000B7, 198)}
if os.name != "posix" or platform.system() != "Linux" or machine not in profiles:
    raise SystemExit("networkless fixed-suite replay requires Linux x86-64 or aarch64")
audit_arch, socket_syscall = profiles[machine]
program = stmt(0x20, 4) + jump(0x15, audit_arch, 1, 0) + stmt(0x06, 0x00050001)
program += stmt(0x20, 0) + jump(0x15, socket_syscall, 1, 0) + stmt(0x06, 0x7fff0000)
program += stmt(0x20, 16)
families = (socket.AF_INET, socket.AF_INET6, socket.AF_PACKET)
for i, family in enumerate(families):
    program += jump(0x15, family, len(families) - i, 0)
program += stmt(0x06, 0x7fff0000) + stmt(0x06, 0x00050001)
libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
buf = ctypes.create_string_buffer(program, len(program))
prog = P(len(program) // ctypes.sizeof(F), ctypes.cast(buf, ctypes.c_void_p))
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(prog), 0, 0) != 0:
    raise SystemExit("cannot install seccomp network denial")
proof = {}
for name in ("AF_INET", "AF_INET6"):
    try:
        sock = socket.socket(getattr(socket, name), socket.SOCK_STREAM)
    except OSError as exc:
        proof[name] = {"created": False, "errno": exc.errno,
                       "errno_name": errno.errorcode.get(exc.errno)}
    else:
        sock.close(); proof[name] = {"created": True, "errno": None, "errno_name": None}
if any(row["created"] for row in proof.values()):
    raise SystemExit("seccomp network denial did not hold")

if payload["mode"] == "runtime":
    from coretex_memory import release as runtime_release
    manifest = payload["execution"]["release_manifest"]
    module = payload["execution"]["module"]["source"].encode("utf-8")
    root = payload["execution"]["release_root"]
    runtime_release.load_content_addressed_release(
        manifest, expected_manifest_root=root, runtime_checks=True)
    runtime_release.recompute_admission(module, manifest)
    result = {"ok": True, "networkless_proof": proof}
else:
    from validator.replay import replay_report
    result = replay_report(
        payload["report"], expected_root=payload["expected_root"],
        repo_root=payload["repo"], incumbent_execution=payload["incumbent"],
        parent_stored_vector=payload["parent_stored_vector"])
    result["networkless_proof"] = proof
print("<<<JSON>>>" + json.dumps(result, sort_keys=True, default=str))
'''


class ReleaseBenchmarkRunner:
    """One verified, reusable fixed-suite execution environment for a snapshot build."""

    def __init__(self, release: release_module.ReleaseDirectory, *, timeout: int = 7200) -> None:
        self.release = release
        self.timeout = timeout
        self._temporary: Optional[Path] = None
        self._validated_releases: set[str] = set()

    def __enter__(self) -> "ReleaseBenchmarkRunner":
        if self._temporary is not None:
            raise BenchmarkReplayError("benchmark environment is already open")
        root = Path(tempfile.mkdtemp(prefix="coretex-validator-replay-"))
        self._temporary = root
        self._validated_releases.clear()
        try:
            control = root / "control"
            control.mkdir(mode=0o700)
            kit = _kit_files(self.release)
            repo = root / "repo"
            _write_files(repo, kit, prefixes=(
                *(tree + "/" for tree in _EXECUTION_TREES), *_ISOLATION_SOURCES))
            isolation = self.release.objects["public_candidate_isolation"]
            expected_isolation = self.release.integration["code_roots"][
                "candidate_isolation_posture"]
            if _sha(isolation) != expected_isolation:
                raise BenchmarkReplayError(
                    "release candidate-isolation object is not the scorer-bound posture")
            posture = _json(isolation, "public candidate-isolation posture")
            for label, member in (
                    ("bootstrap", _ISOLATION_BOOTSTRAP), ("module", _ISOLATION_MODULE)):
                declaration = posture.get(label)
                if not isinstance(declaration, Mapping) \
                        or declaration.get("repository_path") != member \
                        or not _ROOT.fullmatch(str(declaration.get("sha256", ""))):
                    raise BenchmarkReplayError(
                        f"candidate-isolation posture has another {label} declaration")
                source = kit.get(member)
                if source is None or _sha(source) != declaration["sha256"]:
                    raise BenchmarkReplayError(
                        f"miner kit does not carry the exact release-bound isolation {label}")
            target = repo / "v5" / "CANDIDATE-ISOLATION.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(isolation)

            site = repo / "coretex-memory"
            frontier_source = repo / "benchmark-v2" / "frontier"
            frontier_target = site / "frontier"
            if not frontier_source.is_dir() or frontier_target.exists():
                raise BenchmarkReplayError("miner kit has another benchmark frontier layout")
            frontier_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(frontier_source), str(frontier_target))
            frontier_source.symlink_to(Path("..") / "coretex-memory" / "frontier",
                                       target_is_directory=True)
            runtime_files = _wheel_files(
                self.release.artifacts["runtime_wheel"], "runtime wheel")
            machine = platform.machine().lower()
            if machine in ("x86_64", "amd64"):
                wasmtime_role = "wasmtime_amd64_wheel"
            elif machine in ("aarch64", "arm64"):
                wasmtime_role = "wasmtime_aarch64_wheel"
            else:
                raise BenchmarkReplayError(
                    f"no release-bound Wasmtime wheel exists for architecture {machine!r}")
            wasmtime_files = _wheel_files(
                self.release.artifacts[wasmtime_role], wasmtime_role)
            _write_files(site, runtime_files)
            _write_files(site, wasmtime_files)
            (site / "sitecustomize.py").write_bytes(kit[_ISOLATION_BOOTSTRAP])
            if not any(name.startswith("coretex_memory/") for name in runtime_files):
                raise BenchmarkReplayError("release runtime wheel has no coretex_memory package")
            _seal_public_tree(root, repo)
            self.probe_isolation()
        except Exception:
            _remove_temporary(root)
            self._temporary = None
            raise
        return self

    def __exit__(self, _kind, _value, _traceback) -> None:
        if self._temporary is not None:
            _remove_temporary(self._temporary)
            self._temporary = None

    @property
    def _paths(self) -> tuple[Path, Path, Path]:
        if self._temporary is None:
            raise BenchmarkReplayError("benchmark environment is not open")
        repo = self._temporary / "repo"
        return repo, repo / "benchmark-v2", repo / "coretex-memory"

    def _new_status_path(self) -> Path:
        if self._temporary is None:
            raise BenchmarkReplayError("benchmark environment is not open")
        descriptor, raw = tempfile.mkstemp(
            prefix="candidate-isolation-status-", suffix=".json",
            dir=self._temporary / "control")
        os.close(descriptor)
        path = Path(raw)
        path.unlink()
        return path

    def _base_env(self, status: Path) -> dict[str, str]:
        repo, bench, site = self._paths
        return {
            "PATH": os.environ.get("PATH", ""),
            "NO_PROXY": "*",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": os.pathsep.join((str(site), str(bench))),
            "CORETEX_ADMISSION_REPO_ROOT": str(repo),
            "CORETEX_CANDIDATE_ISOLATION_REQUIRED": "1",
            "CORETEX_CANDIDATE_RUNTIME_ROOT": str(site),
            "CORETEX_CANDIDATE_ISOLATION_STATUS": str(status),
            "CORETEX_V5_REPO_ROOT": str(repo),
            "CORETEX_RESOLVER_QUIET": "1",
        }

    @staticmethod
    def _finish_process(process: subprocess.Popen[str], *, input_text: str,
                        timeout: int, label: str) -> tuple[str, str]:
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, 9)
            except OSError:
                process.kill()
            process.wait()
            raise BenchmarkReplayError(f"{label} exceeded its bounded process-group timeout") \
                from exc
        return stdout, stderr

    @staticmethod
    def _require_isolation_status(status: Path) -> None:
        try:
            value = _json(status.read_bytes(), "candidate isolation status")
        except (OSError, BenchmarkReplayError) as exc:
            raise BenchmarkReplayError(
                "candidate pack worker produced no enforced isolation observation") from exc
        detail = value.get("detail")
        match = re.fullmatch(r"landlock_abi=([0-9]+),path_rules=([0-9]+)",
                             detail if isinstance(detail, str) else "")
        if set(value) != {"detail", "inner_returncode", "observed_at", "state"} \
                or value.get("state") != "enforced" \
                or value.get("inner_returncode") != 0 \
                or type(value.get("observed_at")) is not int or value["observed_at"] <= 0 \
                or match is None or int(match.group(1)) < 3 or int(match.group(2)) < 1:
            raise BenchmarkReplayError(
                "candidate pack worker did not install the release-bound OS confinement")

    def probe_isolation(self) -> None:
        """Fast real kernel proof through the exact sitecustomize → outer → inner path."""
        repo, bench, _site = self._paths
        assert self._temporary is not None
        probe = self._temporary / "control" / "isolation-probe"
        probe.mkdir(exist_ok=True)
        view = probe / "view.json"
        store = probe / "store"
        spec = probe / "spec.json"
        view.write_text("{}\n", encoding="utf-8")
        source = "def make_hooks(context): return None\n"
        spec.write_text(json.dumps({
            "store_dir": str(store), "view_path": str(view), "module_source": source,
            "module_sha256": _sha(source.encode("utf-8")),
        }, sort_keys=True), encoding="utf-8")
        status = self._new_status_path()
        env = self._base_env(status)
        env["CORETEX_CANDIDATE_ISOLATION_PROBE"] = "1"
        try:
            process = subprocess.Popen(
                [os.sys.executable, str(bench / "miner_abi" / "pack_worker.py"), str(spec)],
                cwd=repo, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True)
            stdout, stderr = self._finish_process(
                process, input_text="", timeout=min(self.timeout, 120),
                label="candidate isolation probe")
        except OSError as exc:
            raise BenchmarkReplayError(f"candidate isolation probe could not start: {exc}") from exc
        if process.returncode != 0 or "PACK_RESULT " not in stdout:
            raise BenchmarkReplayError(
                f"candidate isolation probe refused ({process.returncode}): "
                f"{(stderr or stdout)[-2000:]}")
        try:
            self._require_isolation_status(status)
        finally:
            status.unlink(missing_ok=True)

    def _run(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        repo, bench, site = self._paths
        body = dict(payload, repo=str(repo), bench=str(bench), site=str(site))
        status = self._new_status_path()
        env = self._base_env(status)
        try:
            process = subprocess.Popen(
                [os.sys.executable, "-c", _CHILD],
                cwd=repo, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True)
            stdout, stderr = self._finish_process(
                process, input_text=json.dumps(body), timeout=self.timeout,
                label="fixed-suite child")
        except OSError as exc:
            raise BenchmarkReplayError(f"fixed-suite child could not run: {exc}") from exc
        if process.returncode != 0 or "<<<JSON>>>" not in stdout:
            diagnostic = (stderr or stdout)[-4000:]
            raise BenchmarkReplayError(
                f"fixed-suite child refused or failed ({process.returncode}): {diagnostic}")
        try:
            result = json.loads(stdout.split("<<<JSON>>>", 1)[1])
        except ValueError as exc:
            raise BenchmarkReplayError("fixed-suite child returned malformed JSON") from exc
        if not isinstance(result, dict):
            raise BenchmarkReplayError("fixed-suite child returned a non-object")
        proof = result.get("networkless_proof")
        if not isinstance(proof, Mapping) or any(
                not isinstance(row, Mapping) or row.get("created") is not False
                for row in proof.values()):
            raise BenchmarkReplayError("fixed-suite child did not prove network denial")
        if payload.get("mode") == "replay":
            try:
                self._require_isolation_status(status)
            finally:
                status.unlink(missing_ok=True)
        else:
            status.unlink(missing_ok=True)
        return result

    def replay_report(self, report: Mapping[str, Any], *, expected_root: str,
                      incumbent_execution: Mapping[str, Any],
                      parent_stored_vector: Mapping[str, Any]) -> Mapping[str, Any]:
        profile_id = report.get("profile_id") if isinstance(report, Mapping) else None
        release_root = incumbent_execution.get("release_root") \
            if isinstance(incumbent_execution, Mapping) else None
        try:
            parent_stored_vector = evaluation.validate_parent_stored_vector(
                parent_stored_vector, expected_profile_id=profile_id,
                expected_release_root=release_root)
        except evaluation.EvalArtifactError as exc:
            raise BenchmarkReplayError(
                f"replay requires a complete exact-parent stored vector: {exc}") from exc
        result = self._run({
            "mode": "replay", "report": dict(report), "expected_root": expected_root,
            "incumbent": dict(incumbent_execution),
            "parent_stored_vector": dict(parent_stored_vector),
        })
        if result.get("reproduced") is not True or result.get("report_root", expected_root) \
                != expected_root:
            raise BenchmarkReplayError(
                f"fixed-suite report did not reproduce: {result.get('code')}: "
                f"{result.get('reason')}")
        return result

    def validate_execution(self, execution: Mapping[str, Any]) -> None:
        if execution.get("exec") == "reference":
            return
        release_root = execution.get("release_root")
        if isinstance(release_root, str) and release_root in self._validated_releases:
            return
        result = self._run({"mode": "runtime", "execution": dict(execution)})
        if result.get("ok") is not True:
            raise BenchmarkReplayError("candidate release failed runtime validation")
        if isinstance(release_root, str):
            self._validated_releases.add(release_root)


__all__ = ["BenchmarkReplayError", "ReleaseBenchmarkRunner"]
