# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json

from coretex_validator.rpc import JsonRpc


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
