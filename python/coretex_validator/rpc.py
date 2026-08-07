# SPDX-License-Identifier: Apache-2.0
"""A minimal Ethereum JSON-RPC client, on ``urllib``.

Deliberately not ``web3.py``. This package's whole claim is that a validator needs the standard
library and nothing else; the seven methods below are the entire chain surface the rig lane reads,
and they are a few hundred lines of HTTP and hex parsing.

TWO PROPERTIES THAT ARE NOT OPTIONAL:

* **Every read is pinned to a block.** ``eth_call`` and ``eth_getCode`` take an explicit block
  number, never ``"latest"`` by default. A snapshot assembled from reads at drifting heights is
  not a snapshot of anything — it is a blend of several chain states that never coexisted.
* **Reorg detection is the caller's, and it is cheap.** :meth:`block_hash_at` lets a caller
  re-read the pinned height at the end of a run and compare; :class:`PinnedBlock` carries the
  hash for exactly that. The client does not do it silently, because "the validator decided to
  retry" is a decision an operator should see.

``eth_getLogs`` is chunked, because every public endpoint has a range limit and hitting it
produces a partial answer that looks like an empty one.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

#: Public endpoints cap ``eth_getLogs`` ranges. 2000 is below every limit we have met.
DEFAULT_CHUNK_BLOCKS = 2000
#: Base finalizes in ~2 blocks; 15 is the confirmation depth the memory lane already uses and
#: there is no reason for the rig lane to be more optimistic than its predecessor.
DEFAULT_CONFIRMATION_DEPTH = 15


class RpcError(RuntimeError):
    """The endpoint refused, errored, or answered something that is not JSON-RPC."""


class TransportError(RpcError):
    """The request never got a usable answer: HTTP status, timeout, DNS, connection reset.

    SPLIT FROM :class:`ResponseError` BECAUSE REAL DATA PROVED IT MATTERS. A 429 rate-limit from a
    public endpoint arrived and was classified as ``CONTRACT_READ_REVERTED`` — a transport failure
    wearing a contract-revert label. The two demand opposite responses: a transport failure means
    "back off and retry", a revert means "the contract said no and retrying will say no again".
    Conflating them turns a rate limit into a fabricated claim about chain state.

    The over-correction is a bug too: a GENUINE revert must never be classified as transport, or a
    contract refusing an operation would look like a network blip and get retried forever.
    """

    def __init__(self, message: str, *, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class ResponseError(RpcError):
    """The endpoint answered, and the answer was an error — including a contract revert."""

    def __init__(self, message: str, *, returndata: bytes = b"") -> None:
        super().__init__(message)
        #: The raw revert returndata, when the endpoint supplied it. The FIRST FOUR BYTES are the
        #: custom-error selector, and that is the only reliable way to identify a revert: message
        #: text is endpoint-specific prose that changes between providers and versions.
        self.returndata = bytes(returndata)

    @property
    def selector(self) -> str:
        return "0x" + self.returndata[:4].hex() if len(self.returndata) >= 4 else ""


class ChainMismatchError(RpcError):
    """The endpoint is serving a different chain than the caller asked for. Never a warning."""


#: ``RigCoreTexStateRegistry.EpochContextNotSet()``. Matched by SELECTOR, never by message text.
#:
#: The registry delegates epoch reads to the verifier's context and reverts with this for an epoch
#: that was never armed. On the real chain this is not hypothetical: below epoch 180 — that
#: registry's genesis — ``liveStateRoot`` and ``epochParentStateRoot`` revert while
#: ``epochFinalized`` and ``transitionCount`` answer normally.
EPOCH_CONTEXT_NOT_SET_SELECTOR = "0xae3a262a"

#: A browser-ish User-Agent, because the default one is refused.
#:
#: ``https://mainnet.base.org`` answers urllib's default ``Python-urllib/3.x`` with a bare HTTP
#: 403 and no body — which reads exactly like an auth failure and sends you looking for an API key
#: that was never required. Setting a UA fixes it. Recorded here rather than in a comment on a
#: header dict because the next person to debug a 403 needs to find this.
DEFAULT_USER_AGENT = "coretex-validator/0.1 (+https://github.com/botcoinmoney/coretex-client)"


@dataclass(frozen=True)
class PinnedBlock:
    """A height AND the hash that was at it. Carrying only the height loses reorg detection."""

    number: int
    hash: str
    timestamp: int


def _hex_int(value: Any, field: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RpcError(f"{field}: expected a 0x quantity, got {value!r}")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise RpcError(f"{field}: {value!r} is not hex") from exc


class JsonRpc:
    """One endpoint. Not thread-safe, and not trying to be — a validator run is sequential."""

    def __init__(self, url: str, *, timeout: float = 30.0, retries: int = 8,
                 chunk_blocks: int = DEFAULT_CHUNK_BLOCKS,
                 user_agent: str = DEFAULT_USER_AGENT, backoff: float = 0.75,
                 min_interval: float = 0.7) -> None:
        if not isinstance(url, str) or not url:
            raise RpcError("an RPC url is required")
        self.url = url
        self.timeout = timeout
        self.retries = max(1, int(retries))
        self.chunk_blocks = max(1, int(chunk_blocks))
        self.user_agent = user_agent
        self.backoff = float(backoff)
        #: MINIMUM SPACING BETWEEN REQUESTS. Public endpoints rate-limit, and a validator's read
        #: pattern is a burst of small `eth_call`s — the worst possible shape for a token bucket.
        #: Retrying into a 429 storm is slower than not causing one, so requests are paced.
        #: `https://mainnet.base.org` refuses an unpaced burst within a few dozen calls.
        self.min_interval = float(min_interval)
        self._last_request = 0.0
        self.calls = 0
        #: Observed rate limits, surfaced in a report. A run that quietly absorbed fifty 429s took
        #: fifty times longer than it should have and nobody was told why.
        self.rate_limited = 0

    # -- transport --------------------------------------------------------- #
    def call(self, method: str, params: Sequence[Any]) -> Any:
        payload = json.dumps({"jsonrpc": "2.0", "id": self.calls + 1, "method": method,
                              "params": list(params)}).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=payload,
            headers={"content-type": "application/json", "accept": "application/json",
                     "user-agent": self.user_agent})
        last: Optional[Exception] = None
        for attempt in range(self.retries):
            gap = time.monotonic() - self._last_request
            if gap < self.min_interval:
                time.sleep(self.min_interval - gap)
            self._last_request = time.monotonic()
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 429:
                    self.rate_limited += 1
                # An HTTP status is TRANSPORT, always — including 429 and 403. The endpoint never
                # got as far as executing anything, so nothing it says is about the chain.
                last = TransportError(
                    f"{method}: HTTP {exc.code} from {self.url}"
                    + (" (rate limited — back off; this is NOT a contract revert)"
                       if exc.code == 429 else "")
                    + (" (403 with the default User-Agent usually means the endpoint refused the "
                       "agent string, not that a key is missing)"
                       if exc.code == 403 else ""),
                    status=exc.code)
                if attempt + 1 == self.retries:
                    raise last from exc
                time.sleep(self.backoff * (2 ** attempt) if exc.code == 429
                           else self.backoff * (attempt + 1))
            except (urllib.error.URLError, OSError) as exc:
                last = TransportError(f"{method}: {exc}")
                if attempt + 1 == self.retries:
                    raise last from exc
                time.sleep(self.backoff * (attempt + 1))
            except ValueError as exc:
                # A body that is not JSON came from something that is not a JSON-RPC endpoint.
                last = TransportError(f"{method}: response was not JSON ({exc})")
                if attempt + 1 == self.retries:
                    raise last from exc
                time.sleep(self.backoff * (attempt + 1))
        else:                                                # pragma: no cover - unreachable
            raise TransportError(f"{method}: {last}")
        self.calls += 1
        if not isinstance(body, Mapping):
            raise TransportError(f"{method}: response is not a JSON object")
        if "error" in body:
            error = body["error"] if isinstance(body["error"], Mapping) else {}
            raw = str(error.get("data") or "")
            returndata = b""
            if raw.startswith("0x"):
                try:
                    returndata = bytes.fromhex(raw[2:])
                except ValueError:                            # pragma: no cover - defensive
                    returndata = b""
            # A JSON-RPC error IS a response: the endpoint executed and said no. Classified here,
            # never as transport, so a genuine revert is not retried forever as a network blip.
            raise ResponseError(f"{method}: endpoint returned {body['error']}",
                                returndata=returndata)
        if "result" not in body:
            raise TransportError(f"{method}: response carries no result")
        return body["result"]

    # -- chain identity / heads -------------------------------------------- #
    def chain_id(self) -> int:
        return _hex_int(self.call("eth_chainId", []), "eth_chainId")

    def assert_chain(self, expected: int) -> int:
        observed = self.chain_id()
        if observed != int(expected):
            raise ChainMismatchError(
                f"this endpoint serves chain {observed}, the release names chain {expected}. "
                "Every address, root and receipt below is chain-scoped, so continuing would "
                "verify one chain's claims against another's state")
        return observed

    def block_number(self) -> int:
        return _hex_int(self.call("eth_blockNumber", []), "eth_blockNumber")

    def block(self, number: int) -> PinnedBlock:
        raw = self.call("eth_getBlockByNumber", [hex(int(number)), False])
        if not isinstance(raw, Mapping):
            raise RpcError(f"block {number} not found")
        return PinnedBlock(number=_hex_int(raw["number"], "block.number"),
                           hash=str(raw["hash"]).lower(),
                           timestamp=_hex_int(raw["timestamp"], "block.timestamp"))

    def block_hash_at(self, number: int) -> str:
        return self.block(number).hash

    def confirmed_head(self, depth: int = DEFAULT_CONFIRMATION_DEPTH) -> int:
        """The deepest block this run is willing to treat as settled."""
        return max(0, self.block_number() - int(depth))

    # -- state ------------------------------------------------------------- #
    def code(self, address: str, *, block: int) -> bytes:
        raw = self.call("eth_getCode", [address, hex(int(block))])
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RpcError(f"eth_getCode({address}) returned {raw!r}")
        return bytes.fromhex(raw[2:])

    def eth_call(self, *, to: str, data: str, block: int) -> bytes:
        raw = self.call("eth_call", [{"to": to, "data": data}, hex(int(block))])
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RpcError(f"eth_call({to}) returned {raw!r}")
        return bytes.fromhex(raw[2:])

    # -- logs -------------------------------------------------------------- #
    def get_logs(self, *, addresses: Sequence[str], topics: Sequence[str],
                 from_block: int, to_block: int) -> List[Dict[str, Any]]:
        """All matching logs in ``[from_block, to_block]``, chunked, in chain order.

        ``topics`` is the topic0 OR-set. Passing an EMPTY set means "every event from these
        addresses" — which is what a validator that must not miss an unknown administrative event
        actually wants, and is why this does not default to a filter.
        """
        out: List[Dict[str, Any]] = []
        start = int(from_block)
        end = int(to_block)
        while start <= end:
            stop = min(start + self.chunk_blocks - 1, end)
            criteria: Dict[str, Any] = {"fromBlock": hex(start), "toBlock": hex(stop),
                                        "address": [a for a in addresses]}
            if topics:
                criteria["topics"] = [["0x" + t if not t.startswith("0x") else t for t in topics]]
            raw = self.call("eth_getLogs", [criteria])
            if not isinstance(raw, list):
                raise RpcError("eth_getLogs did not return a list")
            out.extend(raw)
            start = stop + 1
        return out

    # -- transactions ------------------------------------------------------ #
    def transaction(self, tx_hash: str) -> Dict[str, Any]:
        raw = self.call("eth_getTransactionByHash", [tx_hash])
        if not isinstance(raw, Mapping):
            raise RpcError(
                f"transaction {tx_hash} is unavailable. Design §7.6: without calldata the signed "
                "receipt cannot be completed, so artifactHash/workPolicyHash/signature are "
                "unrecoverable for this advance. Use an archive node")
        return dict(raw)

    def transaction_receipt(self, tx_hash: str) -> Dict[str, Any]:
        raw = self.call("eth_getTransactionReceipt", [tx_hash])
        if not isinstance(raw, Mapping):
            raise RpcError(f"receipt for {tx_hash} is unavailable")
        return dict(raw)


# --------------------------------------------------------------------------- #
# Typed view calls
# --------------------------------------------------------------------------- #
def selector(signature: str) -> str:
    from .abi import selector as _sel                                          # local: cheap
    return "0x" + _sel(signature).hex()


def _encode_uint(value: int) -> str:
    return f"{int(value):064x}"


def _encode_address(value: str) -> str:
    return f"{int(str(value), 16):064x}"


class RigViews:
    """The registry / mining / verifier view calls the rig lane reads.

    Each one is here rather than inline at its call site so the ABI encoding is written once. The
    signatures are transcribed from the exact sources; a typo produces a revert or a zero, not a
    wrong-but-plausible number, because a wrong selector does not decode.
    """

    def __init__(self, rpc: JsonRpc, deployment, *, block: int) -> None:
        self.rpc = rpc
        self.deployment = deployment
        self.block = int(block)

    def _call(self, to: str, sig: str, args: str = "") -> bytes:
        return self.rpc.eth_call(to=to, data=selector(sig) + args, block=self.block)

    # -- registry ---------------------------------------------------------- #
    def live_state_root(self, epoch: int) -> str:
        return self._call(self.deployment.registry, "liveStateRoot(uint64)",
                          _encode_uint(epoch)).hex()

    def transition_count(self, epoch: int) -> int:
        return int.from_bytes(
            self._call(self.deployment.registry, "transitionCount(uint64)",
                       _encode_uint(epoch)), "big")

    def epoch_finalized(self, epoch: int) -> bool:
        return bool(int.from_bytes(
            self._call(self.deployment.registry, "epochFinalized(uint64)",
                       _encode_uint(epoch)), "big"))

    def epoch_has_context(self, epoch: int) -> bool:
        """Ask the VERIFIER whether epoch N was ever given a context, BEFORE reading the registry.

        This is not an optimisation, it is the precondition. The registry delegates every epoch
        read to the bound verifier's context and REVERTS with ``EpochContextNotSet()`` for an
        epoch that never had one — including ``liveStateRoot`` and ``epochParentStateRoot``.
        Design §7.5's fall-through rule is written about ``getHeader``, which returns a
        zero-filled struct rather than reverting; the other reads do NOT share that behaviour, so
        a backwards walk that only handled the ``getHeader`` case dies on the first epoch below
        the registry's first served one.

        Probing the flag turns that into a question with an answer instead of an exception to
        catch — and an exception-driven version would have to distinguish "no context" from "the
        endpoint is broken", which a revert selector alone does not reliably tell you.
        """
        raw = self._call(self.deployment.verifier, "coreTexEpochContextSet(uint64)",
                         _encode_uint(epoch))
        return bool(int.from_bytes(raw, "big"))

    def epoch_parent_state_root(self, epoch: int) -> str:
        return self._call(self.deployment.registry, "epochParentStateRoot(uint64)",
                          _encode_uint(epoch)).hex()

    def epoch_core_version_hash(self, epoch: int) -> str:
        return self._call(self.deployment.registry, "epochCoreVersionHash(uint64)",
                          _encode_uint(epoch)).hex()

    def epoch_context_root(self, epoch: int) -> str:
        return self._call(self.deployment.registry, "epochContextRoot(uint64)",
                          _encode_uint(epoch)).hex()

    def header(self, epoch: int) -> Dict[str, str]:
        """``getHeader(N)``. An UNSEALED epoch returns a ZERO-FILLED struct, not a revert.

        Design §7.5 is explicit that this is the normal case and not a fault: an epoch with no
        recorded transition can never be sealed, so it has no header, permanently. Callers must
        read :meth:`epoch_finalized` to tell "sealed" from "never sealed" — the zero root cannot
        do it, because D2 forbids a sealed epoch from having a zero live root, which makes an
        all-zero header unambiguous only once you have asked.
        """
        raw = self._call(self.deployment.registry, "getHeader(uint64)", _encode_uint(epoch))
        names = ("patch_set_root", "score_root")
        if len(raw) < 32 * len(names):
            raise RpcError(f"getHeader({epoch}) returned {len(raw)} bytes, expected "
                           f"{32 * len(names)}")
        return {name: raw[i * 32:(i + 1) * 32].hex() for i, name in enumerate(names)}

    def legacy_v2_header(self, epoch: int) -> Dict[str, str]:
        """Historical eight-word header decoder; never used for a live descriptor-v3 registry."""
        raw = self._call(self.deployment.registry, "getHeader(uint64)", _encode_uint(epoch))
        names = ("parent_state_root", "final_state_root", "core_version_hash", "corpus_root",
                 "active_frontier_root", "patch_set_root", "score_root",
                 "baseline_manifest_hash")
        if len(raw) < 32 * len(names):
            raise RpcError(f"legacy getHeader({epoch}) returned {len(raw)} bytes, expected "
                           f"{32 * len(names)}")
        return {name: raw[i * 32:(i + 1) * 32].hex() for i, name in enumerate(names)}

    def core_tex_verifier(self) -> str:
        raw = self._call(self.deployment.registry, "coreTexVerifier()")
        return "0x" + raw[-20:].hex()

    # -- verifier ---------------------------------------------------------- #
    def verifier_registry(self) -> str:
        raw = self._call(self.deployment.verifier, "coreTexRegistry()")
        return "0x" + raw[-20:].hex()

    def verifier_mining(self) -> str:
        raw = self._call(self.deployment.verifier, "mining()")
        return "0x" + raw[-20:].hex()

    def active_rules_version(self, epoch: int) -> int:
        """``activeCoreTexRulesVersion(epoch)`` — which scoring policy was IN FORCE at an epoch.

        THE AUTHORITATIVE ANSWER, and the reason this exists rather than scanning for a
        ``CoreTexPolicyScheduled`` event: a policy is scheduled ONCE and stays in force
        indefinitely, so the announcing event can sit arbitrarily far below any sensible log
        window. Reconstructing historical law from events alone therefore fails not because the
        law is unknowable but because the scan started too late — which is a property of the
        validator's configuration, not of the chain, and must never be reported as "this
        deployment scheduled no policy".
        """
        return int.from_bytes(
            self._call(self.deployment.verifier, "activeCoreTexRulesVersion(uint64)",
                       _encode_uint(epoch)), "big")

    def core_tex_policy(self, rules_version: int) -> Optional[Dict[str, Any]]:
        """``getCoreTexPolicy(version)``. ``None`` when the version was never scheduled."""
        raw = self._call(self.deployment.verifier, "getCoreTexPolicy(uint32)",
                         _encode_uint(rules_version))
        if len(raw) < 6 * 32:
            raise RpcError(f"getCoreTexPolicy({rules_version}) returned {len(raw)} bytes")
        exists = bool(int.from_bytes(raw[0:32], "big"))
        if not exists:
            return None
        return {
            "rules_version": int(rules_version),
            "effective_epoch": int.from_bytes(raw[32:64], "big"),
            "policy_hash": raw[64:96].hex(),
            "screener_work_bps": int.from_bytes(raw[96:128], "big"),
        }

    def difficulty_count(self, epoch: int) -> int:
        return int.from_bytes(
            self._call(self.deployment.verifier, "coreTexDifficultyCount(uint64)",
                       _encode_uint(epoch)), "big")

    # -- mining ------------------------------------------------------------ #
    def coordinator_signer(self) -> str:
        raw = self._call(self.deployment.mining, "coordinatorSigner()")
        return "0x" + raw[-20:].hex()

    def domain_separator(self) -> bytes:
        return self._call(self.deployment.mining, "DOMAIN_SEPARATOR()")[:32]

    def rig_next_index(self, rig_id: int) -> int:
        return int.from_bytes(
            self._call(self.deployment.mining, "rigNextIndex(uint256)",
                       _encode_uint(rig_id)), "big")

    def rig_last_receipt_hash(self, rig_id: int) -> str:
        return self._call(self.deployment.mining, "rigLastReceiptHash(uint256)",
                          _encode_uint(rig_id))[:32].hex()

    def current_epoch(self) -> int:
        return int.from_bytes(self._call(self.deployment.mining, "currentEpoch()"), "big")
