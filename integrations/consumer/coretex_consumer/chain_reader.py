# SPDX-License-Identifier: Apache-2.0
"""Bounded public state reads for consumers. No log scanning or transaction submission."""
from __future__ import annotations

import ipaddress
import json
import re
import time
from urllib import error, parse, request

from coretex_memory_agent._keccak import keccak256
from coretex_memory_agent.authority import _parse_json_bytes

MAX_RESPONSE = 2 * 1024 * 1024


class SyncError(RuntimeError):
    """Current chain authority could not be established; retained stores are untouched."""


def validate_url(url):
    if not isinstance(url, str):
        raise SyncError("endpoint must be a URL string")
    try:
        parsed = parse.urlsplit(url)
        parsed.port
    except ValueError:
        raise SyncError("endpoint URL is malformed") from None
    try:
        loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback)) \
            or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise SyncError("endpoint must be HTTPS (or literal loopback HTTP), without URL userinfo")
    return url


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise SyncError("endpoint redirect refused")


class Transport:
    def __init__(self, *, timeout=20, interval=0.8):
        self.timeout, self.interval, self.last = timeout, interval, 0.0
        self.opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
        self.requests = 0

    def read(self, url, payload=None):
        validate_url(url)
        data = None if payload is None else json.dumps(payload).encode()
        for attempt in range(4):
            time.sleep(max(0, self.last + self.interval - time.monotonic()))
            self.last = time.monotonic()
            self.requests += 1
            req = request.Request(url, data=data, headers={
                "User-Agent": "coretex-memory-agent/current-state",
                "Content-Type": "application/json", "Accept-Encoding": "identity",
                "Accept": "application/octet-stream" if data is None else "application/json"})
            try:
                with self.opener.open(req, timeout=self.timeout) as response:
                    raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise SyncError("endpoint response exceeds 2 MiB")
                return raw
            except error.HTTPError as exc:
                if exc.code not in (429, 502, 503, 504) or attempt == 3:
                    raise SyncError(f"public endpoint returned HTTP {exc.code}") from None
                hint = exc.headers.get("Retry-After", "")
                time.sleep(min(30, int(hint)) if hint.isdigit() else 2 ** (attempt + 1))
            except (error.URLError, TimeoutError, OSError):
                # Do not include endpoint URLs: RPC paths/query strings can contain secrets.
                raise SyncError("public endpoint unavailable; check RPC access and retry sync") from None


def quantity(value):
    if not isinstance(value, str) or re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]*)", value) is None:
        raise SyncError("RPC returned a malformed hex quantity")
    return int(value, 16)


def hex_bytes(value):
    if not isinstance(value, str) or re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value) is None:
        raise SyncError("RPC returned malformed byte data")
    return bytes.fromhex(value[2:])


class ChainReader:
    def __init__(self, url, transport=None):
        self.url = validate_url(url)
        self.transport = transport or Transport()
        self.serial = 0

    def call(self, method, params):
        if method not in {"eth_chainId", "eth_blockNumber", "eth_getBlockByNumber",
                          "eth_call", "eth_getCode"}:
            raise SyncError("consumer sync only supports current-state RPC reads")
        self.serial += 1
        result = _parse_json_bytes(self.transport.read(self.url, {
            "jsonrpc": "2.0", "id": self.serial, "method": method, "params": params}), "RPC")
        if not isinstance(result, dict) or result.get("jsonrpc") != "2.0" \
                or type(result.get("id")) is not int or result["id"] != self.serial \
                or "error" in result or "result" not in result:
            raise SyncError(f"RPC refused or malformed {method}; check endpoint capability")
        return result["result"]

    def block(self, number):
        value = self.call("eth_getBlockByNumber", [hex(number), False])
        if not isinstance(value, dict) or quantity(value.get("number")) != number \
                or len(hex_bytes(value.get("hash"))) != 32:
            raise SyncError("RPC returned another or unavailable block")
        return {"number": number, "hash": value["hash"].lower(),
                "timestamp": quantity(value.get("timestamp"))}

    def head(self, confirmations):
        number = quantity(self.call("eth_blockNumber", [])) - confirmations
        if number < 1:
            raise SyncError("chain does not have enough confirmed blocks")
        block = self.block(number)
        if not -60 <= time.time() - block["timestamp"] <= 600:
            raise SyncError("confirmed RPC head is stale or clock is wrong; refusing stale sync")
        return block

    def view(self, address, signature, block, arg=None, *, words=1):
        data = "0x" + keccak256(signature.encode())[:4].hex()
        if arg is not None:
            data += f"{arg:064x}"
        result = hex_bytes(self.call("eth_call", [
            {"to": address, "data": data}, hex(block)]))
        if len(result) != words * 32:
            raise SyncError(f"{signature} returned an invalid ABI length")
        return [result[i:i+32] for i in range(0, len(result), 32)]

    def uint(self, address, signature, block, arg=None, *, bits=256):
        value = int.from_bytes(self.view(address, signature, block, arg)[0], "big")
        if value >= 2 ** bits:
            raise SyncError(f"{signature} returned an out-of-range integer")
        return value

    def deployment(self, authority, block):
        if quantity(self.call("eth_chainId", [])) != authority["chain_id"]:
            raise SyncError("RPC chain id differs from the release deployment")
        names = {"mining": "mining", "registry": "coretex_registry",
                 "verifier": "coretex_verifier"}
        addresses = {name: authority["contracts"][key] for name, key in names.items()}
        for name, key in names.items():
            code = hex_bytes(self.call("eth_getCode", [addresses[name], hex(block)]))
            if "0x" + keccak256(code).hex() != authority["code_hashes"][key]:
                raise SyncError(f"{name} deployed code differs from the sealed release authority")
        for owner, signature, target in (
            ("registry", "coreTexVerifier()", "verifier"),
            ("registry", "epochClock()", "mining"),
            ("verifier", "coreTexRegistry()", "registry"),
            ("verifier", "mining()", "mining"),
            ("mining", "coreTexVerifier()", "verifier"),
        ):
            raw = self.view(addresses[owner], signature, block)[0]
            if raw[:12] != bytes(12) or "0x" + raw[12:].hex() != addresses[target].lower():
                raise SyncError(f"{owner}.{signature} deployment binding differs")
        return addresses
