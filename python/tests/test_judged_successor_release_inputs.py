"""What a JUDGED SUCCESSOR release looks like to this package, in the two places it refused one.

Both defects were found by the coordinator image's own build gate, which runs
`release.load(<release dir>)` and then opens the shipped miner kit through
`ReleaseBenchmarkRunner`. Neither had been exercised before: the release cut checks the wheel's
payload, and the public replay runs from the benchmark-v2 source tree.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile

import pytest

from coretex_validator import benchmark_replay


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _kit(members: dict[str, bytes]) -> bytes:
    """One closed kit tar, manifest first, in the shape `current_miner_kit` writes."""
    records = [{"path": path, "role": "support:validator", "sha256": _sha(data),
                "size": len(data)} for path, data in sorted(members.items())]
    manifest = (json.dumps({
        "closure": {"manifest_member": "MINER-KIT.json",
                    "release_binding": "RELEASE.json#/artifacts/miner_validator_kit",
                    "self_hash_embedded": False},
        "format": "coretex.miner-validator-kit/v1",
        "law": {"decision_engine_id": "dominance.componentwise.v2",
                "family": "benchmark-v2-law/dominance-fixed-suite",
                "id": "benchmark-v2-law/dominance-fixed-suite.v2", "revision": "v2"},
        "members": records,
        "packages": [],
        "product": {"name": "coretex", "version": "1.1.2"},
        "support_trees": [],
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in [("MINER-KIT.json", manifest)] + sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


class _Release:
    """The one attribute `_kit_files` reads. Nothing else in a release is involved here."""

    def __init__(self, raw: bytes) -> None:
        self.artifacts = {"miner_validator_kit": raw}


def _read(raw: bytes):
    return benchmark_replay._kit_files(_Release(raw))


def test_a_zero_byte_package_marker_is_a_legitimate_kit_member():
    """`benchmark-v2/validator/tools/__init__.py` is empty ON PURPOSE.

    It is the marker that makes the package importable, it is tracked, and the kit builder ships
    it. The byte bound exists to refuse a member too LARGE to ship; refusing a zero-byte file
    stopped the replay runner from opening the kit at all and reported it as a byte-bound
    violation, which reads like corruption.
    """
    raw = _kit({
        "benchmark-v2/validator/tools/__init__.py": b"",
        "benchmark-v2/validator/receipt.py": b"def code_roots(repo):\n    return {}\n",
    })
    # This fixture is a kit TAR and inventory, not a whole release, so the reader refuses it a few
    # checks later for the five release packages it deliberately does not carry. That refusal is
    # the assertion: reaching it means the zero-byte member passed BOTH bounds it used to fail --
    # the tar member bound and the inventory record bound. Naming the later refusal exactly is
    # what stops this test passing for the wrong reason.
    with pytest.raises(benchmark_replay.BenchmarkReplayError, match="another package set"):
        _read(raw)

    # And the same fixture without the empty member reaches the identical point, so nothing about
    # the empty file changed the path taken.
    with pytest.raises(benchmark_replay.BenchmarkReplayError, match="another package set"):
        _read(_kit({"benchmark-v2/validator/receipt.py": b"def code_roots(repo):\n    return {}\n"}))


def test_an_oversized_member_still_refuses():
    """The bound that matters is the upper one, and it is untouched."""
    oversized = b"x" * (benchmark_replay._MAX_MEMBER_BYTES + 1)
    with pytest.raises(benchmark_replay.BenchmarkReplayError,
                       match="bounded regular file|outside its bound|exceeds its bound"):
        _read(_kit({"benchmark-v2/validator/huge.py": oversized}))


def test_a_member_whose_bytes_do_not_match_its_record_still_refuses():
    raw = _kit({"benchmark-v2/validator/receipt.py": b"original\n"})
    tampered = raw.replace(b"original\n", b"tampered\n")
    assert tampered != raw
    with pytest.raises(benchmark_replay.BenchmarkReplayError,
                       match="differs from its inventory"):
        _read(tampered)
