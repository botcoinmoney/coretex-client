# SPDX-License-Identifier: Apache-2.0
"""``setup`` is the public install-time command. Package selection is the part that can
silently fetch the wrong era, so it is asserted from a fixture manifest rather than live kit.
"""
from __future__ import annotations

import io
import tarfile

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
        "coretex-validator-miner-kit-bb.tar",
        "FROZEN-RUNTIME-PACKET.json",
    }
    assert all(item["sha256"] != "aa" * 32 for item in files)


def test_extract_is_idempotent(tmp_path):
    archive = tmp_path / "coretex-validator-miner-kit-test.tar"
    with tarfile.open(archive, "w") as tar:
        payload = b"hello\n"
        info = tarfile.TarInfo(name="hello.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    item = {"local_path": str(archive), "sha256": "deadbeef"}
    first = su.maybe_extract_tars([item], str(tmp_path))
    second = su.maybe_extract_tars([item], str(tmp_path))
    assert first == second
    dest = tmp_path / "coretex-validator-miner-kit-test"
    assert (dest / "hello.txt").read_bytes() == b"hello\n"
    assert (dest / ".extracted").read_text(encoding="utf-8") == "deadbeef"
