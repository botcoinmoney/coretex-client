# SPDX-License-Identifier: Apache-2.0
"""``setup`` is the public install-time command. Package selection is the part that can
silently fetch the wrong era, so it is asserted from a fixture manifest rather than live kit.
"""
from __future__ import annotations

import io
import hashlib
import json
import tarfile

import pytest

from coretex_validator import cli
from coretex_validator import setup as su


def test_setup_is_on_the_parser_with_live_defaults():
    parser = cli.build_parser()
    args = parser.parse_args(["setup"])
    assert args.command == "setup"
    assert args.rpc == su.DEFAULT_RPC
    assert args.coordinator == su.DEFAULT_COORDINATOR
    assert args.skip_packages is False


def test_kit_package_files_take_the_miner_kit_not_the_validator_wheel():
    manifest = {
        "kit": {
            "components": [
                {
                    "id": "current_miner_kit", "present": True,
                    "files": [{
                        "path": ("v5/miner-kit/coretex-validator-miner-kit-" + "ee" * 32
                                 + ".tar"),
                        "sha256": "ee" * 32,
                        "download": "/coretex/v5/kit/file/" + "ee" * 32,
                    }],
                },
                {
                    "id": "frozen_runtime_packet",
                    "files": [
                        {
                            "path": "v5/miner-kit/coretex_validator-0.4.0-py3-none-any.whl",
                            "sha256": "aa" * 32,
                            "download": "/coretex/v5/kit/file/" + "aa" * 32,
                            "downloadEncoding": "raw-bytes",
                        },
                        {
                            "path": ("v5/runtime-packets/root/"
                                     "coretex-validator-miner-kit-bb.tar"),
                            "sha256": "bb" * 32,
                            "download": "/coretex/v5/kit/file/" + "bb" * 32,
                            "downloadEncoding": "raw-bytes",
                        },
                        {
                            "path": "v5/runtime-packets/root/FROZEN-RUNTIME-PACKET.json",
                            "sha256": "cc" * 32,
                            "download": "/coretex/v5/kit/file/" + "cc" * 32,
                            "downloadEncoding": "json-envelope-base64",
                        },
                        {
                            "path": "v5/adapter/coretex_memory_agent-0.1.10-py3-none-any.whl",
                            "sha256": "dd" * 32,
                            "download": "/coretex/v5/kit/file/" + "dd" * 32,
                            "downloadEncoding": "raw-bytes",
                        },
                    ],
                }
            ]
        }
    }
    files = su.kit_package_files(manifest)
    names = {item["name"] for item in files}
    assert names == {
        "coretex-validator-miner-kit-" + "ee" * 32 + ".tar",
        "FROZEN-RUNTIME-PACKET.json",
    }
    assert "coretex-validator-miner-kit-bb.tar" not in names
    assert all(item["sha256"] != "aa" * 32 for item in files)


def test_package_selection_ignores_the_law_publication_component():
    """The law's files are addressed by ROOT and are installed by the law sync, not unpacked as
    packages. A root-named tar landing in the packages directory would be extracted blind."""
    manifest = {
        "kit": {
            "components": [
                {
                    "id": "law_publication",
                    "publicationRoot": "1" * 64,
                    "note": "admission law publication root " + "1" * 64,
                    "files": [
                        {"path": "v5/law-publication/LAW-PUBLICATION.json",
                         "sha256": "11" * 32,
                         "download": "/coretex/v5/kit/file/" + "11" * 32},
                        {"path": "v5/law-publication/" + "2" * 64, "sha256": "22" * 32,
                         "download": "/coretex/v5/kit/file/" + "22" * 32},
                    ],
                },
                {
                    "id": "current_miner_kit", "present": True,
                    "files": [{
                        "path": "v5/miner-kit/coretex-validator-miner-kit-" + "bb" * 32 + ".tar",
                        "sha256": "bb" * 32,
                        "download": "/coretex/v5/kit/file/" + "bb" * 32,
                    }],
                },
                {
                    "id": "frozen_runtime_packet",
                    "files": [
                        {"path": "v5/runtime-packets/root/coretex-validator-miner-kit-" +
                         "cc" * 32 + ".tar", "sha256": "cc" * 32,
                         "download": "/coretex/v5/kit/file/" + "cc" * 32},
                    ],
                },
            ]
        }
    }
    assert [item["name"] for item in su.kit_package_files(manifest)] == [
        "coretex-validator-miner-kit-" + "bb" * 32 + ".tar"]
    component = su.law_publication_component(manifest)
    assert component is not None and su.law_publication_root(component) == "1" * 64


def test_extract_is_idempotent(tmp_path):
    archive = tmp_path / "coretex-validator-miner-kit-test.tar"
    with tarfile.open(archive, "w") as tar:
        payload = b"hello\n"
        info = tarfile.TarInfo(name="hello.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    item = {"local_path": str(archive), "sha256": digest}
    first = su.maybe_extract_tars([item], str(tmp_path))
    second = su.maybe_extract_tars([item], str(tmp_path))
    assert first == second
    dest = tmp_path / "coretex-validator-miner-kit-test"
    assert (dest / "hello.txt").read_bytes() == b"hello\n"
    marker = json.loads((dest / ".extracted").read_text(encoding="utf-8"))
    assert marker["archive_sha256"] == digest
    assert marker["tree_sha256"]


def test_extract_rejects_parent_traversal_even_without_stdlib_data_filter(tmp_path):
    archive = tmp_path / "coretex-validator-miner-kit-evil.tar"
    with tarfile.open(archive, "w") as tar:
        payload = b"owned\n"
        info = tarfile.TarInfo(name="../outside.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="unsafe tar member"):
        su.maybe_extract_tars([{"local_path": str(archive), "sha256": digest}], str(tmp_path))
    assert not (tmp_path.parent / "outside.txt").exists()


def test_extract_rejects_links_and_devices(tmp_path):
    archive = tmp_path / "coretex-validator-miner-kit-link.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="unsafe tar member"):
        su.maybe_extract_tars([{"local_path": str(archive), "sha256": digest}], str(tmp_path))


def test_current_miner_kit_tree_requires_both_unsealed_support_trees(tmp_path):
    root = tmp_path / "kit"
    for relpath in su.REQUIRED_CURRENT_KIT_FILES[:-1]:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# fixture\n")
    with pytest.raises(RuntimeError, match="integration/portability_matrix.py"):
        su.validate_current_miner_kit_tree(str(root))
    path = root / su.REQUIRED_CURRENT_KIT_FILES[-1]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# fixture\n")
    su.validate_current_miner_kit_tree(str(root))


def _manifest_envelope(components):
    kit = {"format": "coretex.memory-frontier.v1/kit-manifest", "components": components}
    body = {
        "format": kit["format"],
        "components": [{
            "id": c["id"], "present": c["present"],
            "files": [{"path": f["path"], "sha256": f.get("sha256") or "",
                       "bytes": f["bytes"]} for f in c["files"]],
            "missing": c["missing"],
        } for c in components],
    }
    from coretex_validator import frontier as fr
    manifest_hash = hashlib.sha256(fr.canonical_bytes(body)).hexdigest()
    kit["manifestHash"] = manifest_hash
    return {"ok": True, "productionRelease": {"kitManifestHash": manifest_hash}, "kit": kit}


def test_current_kit_envelope_recomputes_manifest_hash_and_requires_one_miner_tar():
    tar_sha = "ab" * 32
    components = [{
        "id": "current_miner_kit", "present": True, "missing": [],
        "files": [{"path": f"v5/runtime/coretex-validator-miner-kit-{tar_sha}.tar",
                   "sha256": tar_sha, "bytes": 12}],
    }, {
        "id": "law_publication", "present": True, "missing": [],
        "publicationRoot": "cd" * 32, "files": [],
    }]
    envelope = _manifest_envelope(components)
    verified = su.validate_kit_manifest_envelope(envelope)
    assert verified["manifestHash"] == envelope["kit"]["manifestHash"]
    assert su.current_miner_kit_file(envelope)["sha256"] == tar_sha


def test_current_kit_envelope_rejects_a_wrong_manifest_hash():
    tar_sha = "ab" * 32
    components = [{
        "id": "current_miner_kit", "present": True, "missing": [],
        "files": [{"path": f"v5/runtime/coretex-validator-miner-kit-{tar_sha}.tar",
                   "sha256": tar_sha, "bytes": 12}],
    }, {
        "id": "law_publication", "present": True, "missing": [],
        "publicationRoot": "cd" * 32, "files": [],
    }]
    envelope = _manifest_envelope(components)
    envelope["kit"]["manifestHash"] = "00" * 32
    with pytest.raises(RuntimeError, match="manifestHash"):
        su.validate_kit_manifest_envelope(envelope)


def test_current_kit_envelope_requires_the_production_release_binding():
    tar_sha = "ab" * 32
    envelope = _manifest_envelope([{
        "id": "current_miner_kit", "present": True, "missing": [],
        "files": [{"path": f"v5/runtime/coretex-validator-miner-kit-{tar_sha}.tar",
                   "sha256": tar_sha, "bytes": 12}],
    }, {
        "id": "law_publication", "present": True, "missing": [],
        "publicationRoot": "cd" * 32, "files": [],
    }])
    del envelope["productionRelease"]
    with pytest.raises(RuntimeError, match="productionRelease"):
        su.validate_kit_manifest_envelope(envelope)


def test_current_kit_envelope_rejects_two_miner_tars():
    tar_a, tar_b = "aa" * 32, "bb" * 32
    components = [{
        "id": "current_miner_kit", "present": True, "missing": [],
        "files": [
            {"path": f"v5/runtime/coretex-validator-miner-kit-{tar_a}.tar",
             "sha256": tar_a, "bytes": 12},
            {"path": f"v5/runtime/coretex-validator-miner-kit-{tar_b}.tar",
             "sha256": tar_b, "bytes": 13},
        ],
    }, {
        "id": "law_publication", "present": True, "missing": [],
        "publicationRoot": "cd" * 32, "files": [],
    }]
    envelope = _manifest_envelope(components)
    with pytest.raises(RuntimeError, match="exactly one addressed tar"):
        su.validate_kit_manifest_envelope(envelope)


def test_current_kit_envelope_rejects_absent_or_duplicate_current_components():
    tar_sha = "ab" * 32
    current = {
        "id": "current_miner_kit", "present": True, "missing": [],
        "files": [{"path": f"v5/runtime/coretex-validator-miner-kit-{tar_sha}.tar",
                   "sha256": tar_sha, "bytes": 12}],
    }
    law_component = {
        "id": "law_publication", "present": True, "missing": [],
        "publicationRoot": "cd" * 32, "files": [],
    }
    with pytest.raises(RuntimeError, match="current_miner_kit"):
        su.validate_kit_manifest_envelope(_manifest_envelope([law_component]))
    with pytest.raises(RuntimeError, match="duplicated|current_miner_kit"):
        su.validate_kit_manifest_envelope(_manifest_envelope([current, dict(current),
                                                               law_component]))
