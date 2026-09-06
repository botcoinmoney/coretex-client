from __future__ import annotations

import io
import json
import os
from pathlib import Path
import stat
import zipfile

import pytest

from coretex_validator import benchmark_replay


def _wheel(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return output.getvalue()


def test_wheel_inspection_accepts_empty_regular_markers_but_not_directories():
    files = benchmark_replay._wheel_files(  # noqa: SLF001 - security-rule unit test
        _wheel({"package/__init__.py": b"pass\n", "package/py.typed": b""}), "wheel")
    assert files["package/py.typed"] == b""
    with pytest.raises(benchmark_replay.BenchmarkReplayError, match="invalid member"):
        benchmark_replay._wheel_files(  # noqa: SLF001
            _wheel({"package/": b"", "package/__init__.py": b"pass\n"}), "wheel")


def test_isolation_status_is_unique_closed_success_evidence(tmp_path: Path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({
        "detail": "landlock_abi=6,path_rules=9",
        "inner_returncode": 0,
        "observed_at": 1,
        "state": "enforced",
    }), encoding="utf-8")
    benchmark_replay.ReleaseBenchmarkRunner._require_isolation_status(good)  # noqa: SLF001

    for label, mutation in (
            ("extra", {"extra": True}),
            ("failed", {"inner_returncode": 70}),
            ("old-landlock", {"detail": "landlock_abi=2,path_rules=9"}),
            ("open-detail", {"detail": "landlock_abi=6,path_rules=9,forged=1"})):
        value = json.loads(good.read_text(encoding="utf-8"))
        value.update(mutation)
        path = tmp_path / f"{label}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(benchmark_replay.BenchmarkReplayError, match="did not install"):
            benchmark_replay.ReleaseBenchmarkRunner._require_isolation_status(path)  # noqa: SLF001


def test_public_replay_tree_is_traversable_but_read_only(tmp_path: Path):
    control = tmp_path / "control"
    repo = tmp_path / "repo"
    package = repo / "coretex-memory" / "package"
    package.mkdir(parents=True)
    control.mkdir(mode=0o700)
    member = package / "member.py"
    member.write_text("pass\n", encoding="utf-8")
    link = repo / "logical"
    link.symlink_to(Path("coretex-memory") / "package", target_is_directory=True)

    benchmark_replay._seal_public_tree(tmp_path, repo)  # noqa: SLF001

    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o711
    assert stat.S_IMODE(control.stat().st_mode) == 0o700
    assert stat.S_IMODE(repo.stat().st_mode) == 0o555
    assert stat.S_IMODE(member.stat().st_mode) == 0o444
    assert link.is_symlink()
    assert os.path.realpath(link) == os.path.realpath(package)

    benchmark_replay._remove_temporary(tmp_path)  # noqa: SLF001
    assert not tmp_path.exists()


def test_cpu_archive_omits_only_the_known_optional_logging_startup_hook(monkeypatch):
    import hashlib
    import sys
    import tarfile
    from types import SimpleNamespace
    monkeypatch.setattr(benchmark_replay.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(benchmark_replay.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(sys, 'version_info', (3, 10))
    known = b'import os; exec(\'try: __import__("coloredlogs").auto_install() if os.environ.get("COLOREDLOGS_AUTO_INSTALL") else None\\nexcept ImportError: pass\')\n'

    def archive_for(startup_name, startup):
        wheel = _wheel({'numeric/__init__.py': b'pass\n', startup_name: startup})
        name = 'numeric_fixture.whl'
        doc = {'format': 'coretex.cpu-dependency-bundle/v1', 'machine': 'x86_64',
            'python_abi': 'cp310', 'versions': {'onnxruntime':'1.19.2','numpy':'1.26.4','tokenizers':'0.20.3'},
            'wheels': {name: {'bytes':len(wheel),'sha256':hashlib.sha256(wheel).hexdigest()}}}
        out=io.BytesIO()
        with tarfile.open(fileobj=out,mode='w') as tar:
            for path, data in [('CPU-RUNTIME.json',json.dumps(doc).encode()),(name,wheel)]:
                info=tarfile.TarInfo(path);info.size=len(data);tar.addfile(info,io.BytesIO(data))
        return SimpleNamespace(artifacts={'numeric_runtime_amd64':out.getvalue()})

    files=benchmark_replay._numeric_files(archive_for('coloredlogs.pth',known))
    assert files=={'numeric/__init__.py':b'pass\n'}
    for name, content in [('coloredlogs.pth',b'import arbitrary_startup\n'),('other.pth',known)]:
        with pytest.raises(benchmark_replay.BenchmarkReplayError,match='path injection'):
            benchmark_replay._numeric_files(archive_for(name,content))
