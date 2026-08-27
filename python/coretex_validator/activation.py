# SPDX-License-Identifier: Apache-2.0
"""The paired first-public chain scan floor.

The release fixes product identity; this separate two-coordinate record states where that product
was first activated on the reused contracts.  Every public epoch and log query must satisfy both
coordinates.  Neither value is optional and neither is inferred from contract deployment.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence
import urllib.error
import urllib.parse
import urllib.request

FORMAT = "coretex.public-activation/v1"
MAX_ACTIVATION_BYTES = 4096


class ActivationError(ValueError):
    """The activation record or an observed chain coordinate is unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _uint(value: Any, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < (1 if positive else 0):
        kind = "positive" if positive else "non-negative"
        raise ActivationError("ACTIVATION_INVALID", f"{field} must be a {kind} integer")
    return value


def quantity(value: Any, field: str) -> int:
    if isinstance(value, str) and value.startswith("0x"):
        try:
            return _uint(int(value, 16), field)
        except ValueError as exc:
            raise ActivationError(
                "ACTIVATION_INVALID", f"{field} is not a JSON-RPC quantity") from exc
    return _uint(value, field)


@dataclass(frozen=True)
class PublicActivation:
    epoch: int
    confirmed_block: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "epoch", _uint(self.epoch, "activation epoch", positive=True))
        object.__setattr__(
            self, "confirmed_block", _uint(
                self.confirmed_block, "activation confirmed block", positive=True))

    @classmethod
    def from_document(cls, value: Any) -> "PublicActivation":
        if not isinstance(value, Mapping) or set(value) != {"activation", "format"}:
            raise ActivationError(
                "ACTIVATION_INVALID", "record must contain exactly activation and format")
        if value["format"] != FORMAT:
            raise ActivationError("ACTIVATION_INVALID", f"format must be {FORMAT!r}")
        pair = value["activation"]
        if not isinstance(pair, Mapping) or set(pair) != {"confirmed_block", "epoch"}:
            raise ActivationError(
                "ACTIVATION_INVALID",
                "activation must contain exactly confirmed_block and epoch")
        return cls(
            _uint(pair["epoch"], "activation.epoch"),
            _uint(pair["confirmed_block"], "activation.confirmed_block", positive=True))

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PublicActivation":
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ActivationError("ACTIVATION_INVALID", f"record is not duplicate-free JSON: {exc}") \
                from exc
        result = cls.from_document(value)
        if raw != result.canonical_bytes():
            raise ActivationError("ACTIVATION_INVALID", "record bytes are not canonical")
        return result

    @classmethod
    def load(cls, source: str) -> "PublicActivation":
        """Load canonical bytes from one local file or the public coordinator route."""
        parsed = urllib.parse.urlparse(str(source))
        if parsed.scheme in ("http", "https"):
            request = urllib.request.Request(
                str(source), headers={
                    "Accept": "application/json",
                    "User-Agent": "coretex-validator/1.0.0",
                })
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    declared = response.headers.get("Content-Length")
                    if declared is not None and int(declared) > MAX_ACTIVATION_BYTES:
                        raise ActivationError(
                            "ACTIVATION_INVALID", "public activation response is oversized")
                    raw = response.read(MAX_ACTIVATION_BYTES + 1)
            except ActivationError:
                raise
            except (OSError, ValueError, urllib.error.URLError) as exc:
                raise ActivationError(
                    "ACTIVATION_UNAVAILABLE",
                    f"cannot fetch public activation record: {exc}") from exc
            if len(raw) > MAX_ACTIVATION_BYTES:
                raise ActivationError(
                    "ACTIVATION_INVALID", "public activation response is oversized")
            return cls.from_bytes(raw)
        if parsed.scheme:
            raise ActivationError(
                "ACTIVATION_INVALID", "activation source must be a local path or http(s) URL")
        try:
            with open(source, "rb") as handle:
                raw = handle.read(MAX_ACTIVATION_BYTES + 1)
        except OSError as exc:
            raise ActivationError(
                "ACTIVATION_UNAVAILABLE", f"cannot read public activation record: {exc}") from exc
        if len(raw) > MAX_ACTIVATION_BYTES:
            raise ActivationError("ACTIVATION_INVALID", "public activation file is oversized")
        return cls.from_bytes(raw)

    def as_document(self) -> dict[str, Any]:
        return {
            "activation": {"confirmed_block": self.confirmed_block, "epoch": self.epoch},
            "format": FORMAT,
        }

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.as_document(), indent=2, sort_keys=True) + "\n").encode("utf-8")

    def require_epoch(self, epoch: Any, *, what: str = "epoch") -> int:
        observed = quantity(epoch, what)
        if observed < self.epoch:
            raise ActivationError(
                "BELOW_PUBLIC_ACTIVATION_EPOCH",
                f"{what} {observed} is below activation epoch {self.epoch}")
        return observed

    def require_block(self, block: Any, *, what: str = "block") -> int:
        observed = quantity(block, what)
        if observed < self.confirmed_block:
            raise ActivationError(
                "BELOW_PUBLIC_ACTIVATION_BLOCK",
                f"{what} {observed} is below confirmed activation block {self.confirmed_block}")
        return observed

    def require_log(self, log: Mapping[str, Any], *, index: Optional[int] = None) -> None:
        where = f"log[{index}]" if index is not None else "log"
        if not isinstance(log, Mapping) or "blockNumber" not in log:
            raise ActivationError(
                "PUBLIC_LOG_BLOCK_REQUIRED", f"{where} must carry blockNumber")
        self.require_block(log["blockNumber"], what=f"{where}.blockNumber")

    def require_logs(self, logs: Sequence[Mapping[str, Any]]) -> None:
        for index, log in enumerate(logs):
            self.require_log(log, index=index)


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ActivationError("ACTIVATION_INVALID", f"duplicate JSON key {key!r}")
        result[key] = value
    return result
