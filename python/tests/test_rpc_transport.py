# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json

import pytest

from coretex_validator.rpc import JsonRpc, RpcError


class _Response:
    def __init__(self, body):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


def test_password_only_basic_auth_is_normalized_before_urllib(monkeypatch):
    observed = {}

    def open_request(request, *, timeout):
        observed["url"] = request.full_url
        observed["authorization"] = request.get_header("Authorization")
        observed["timeout"] = timeout
        return _Response({"jsonrpc": "2.0", "id": 1, "result": "0x2105"})

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    rpc = JsonRpc("https://:rpc-secret@example.invalid/v3/project", min_interval=0)

    assert rpc.chain_id() == 8453
    assert observed == {
        "url": "https://example.invalid/v3/project",
        "authorization": "Basic " + base64.b64encode(b":rpc-secret").decode("ascii"),
        "timeout": 30.0,
    }
    assert "rpc-secret" not in rpc.url


def test_percent_encoded_basic_auth_is_decoded_once(monkeypatch):
    observed = {}

    def open_request(request, *, timeout):
        observed["authorization"] = request.get_header("Authorization")
        return _Response({"jsonrpc": "2.0", "id": 1, "result": "0x1"})

    monkeypatch.setattr("urllib.request.urlopen", open_request)
    rpc = JsonRpc("https://user%40name:p%3Aword@example.invalid/rpc", min_interval=0)
    rpc.chain_id()

    expected = base64.b64encode(b"user@name:p:word").decode("ascii")
    assert observed["authorization"] == f"Basic {expected}"


def test_get_logs_walks_every_chunk_boundary_and_terminates_exactly_once():
    address = "0x" + "12" * 20
    rpc = JsonRpc("https://rpc.example", min_interval=0, chunk_blocks=2)
    calls = []

    def call(method, params):
        assert method == "eth_getLogs"
        criteria = params[0]
        calls.append((int(criteria["fromBlock"], 16), int(criteria["toBlock"], 16)))
        block = int(criteria["toBlock"], 16)
        return [{"address": address, "blockNumber": hex(block), "topics": [], "data": "0x"}]

    rpc.call = call
    logs = rpc.get_logs(addresses=[address], topics=[], from_block=10, to_block=14)
    assert calls == [(10, 11), (12, 13), (14, 14)]
    assert [int(log["blockNumber"], 16) for log in logs] == [11, 13, 14]


@pytest.mark.parametrize("defect", ["address", "before", "after"])
def test_get_logs_refuses_provider_rows_outside_the_requested_scope(defect):
    address = "0x" + "12" * 20
    rpc = JsonRpc("https://rpc.example", min_interval=0, chunk_blocks=5)

    def call(_method, _params):
        row = {"address": address, "blockNumber": "0xc", "topics": [], "data": "0x"}
        if defect == "address":
            row["address"] = "0x" + "34" * 20
        elif defect == "before":
            row["blockNumber"] = "0x9"
        else:
            row["blockNumber"] = "0x10"
        return [row]

    rpc.call = call
    with pytest.raises(RpcError, match="outside"):
        rpc.get_logs(addresses=[address], topics=[], from_block=10, to_block=14)
