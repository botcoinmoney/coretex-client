# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the Cut V5-E validator tests.

A SCENARIO here is a complete, self-consistent slice of confirmed chain truth plus the
publication surface a public validator would read: the parent frontier manifest, the eval
artifact, the signed receipt, the counter-resource law, the encoded ``CoreTexMemoryFrontierAdvanced``
log, the matching ``CoreTexMemoryCreditAccepted`` log, and the context / commit / reveal logs a
validator turns into per-epoch pins.

The V5-C fixtures in ``conftest`` build the artifact; this module wraps them into logs and a
store. Nothing here talks to a chain, a network, or a runtime.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence

V5_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if V5_DIR not in sys.path:                                     # pragma: no cover - import guard
    sys.path.insert(0, V5_DIR)

import eval_artifact as ea                                                     # noqa: E402
import frontier as fr                                                          # noqa: E402
import publication as pub                                                      # noqa: E402
from validator import dispatch as dp                                           # noqa: E402
from validator import replay as rp                                             # noqa: E402

from conftest import (ROOT_B, SEASON_ROOT, TARGET_PROFILE, make_manifest,      # noqa: E402
                      make_receipt_wrapper, publish_required, selection_cases)

V5_REGISTRY = "0x00000000000000000000000000000000000000e5"
V4_REGISTRY = "0x00000000000000000000000000000000000000e4"
MINER = "0x000000000000000000000000000000000000abcd"

DEPLOYMENTS = dp.DeploymentSet([
    dp.Deployment(address=V4_REGISTRY, protocol=dp.PROTOCOL_V4, first_epoch=0, last_epoch=6,
                  label="CoreTexRegistry (V4, frozen)"),
    dp.Deployment(address=V5_REGISTRY, protocol=dp.PROTOCOL_V5, first_epoch=7,
                  label="CoreTexMemoryRegistry (V5)"),
])


# --------------------------------------------------------------------------- #
# Screens and sandboxes (declared test doubles — see replay.allow_test_doubles)
# --------------------------------------------------------------------------- #
class FixtureScreen:
    """A deterministic G6b screen stand-in with an explicit DIRTY set.

    ``consensus_grade`` is False and stays False: this proves the completeness ALGORITHM, never
    that a real walk was oracle-clean. ``replay_advance`` refuses it unless the caller opts in.
    """

    name = "fixture-screen(TEST DOUBLE)"
    consensus_grade = False

    def __init__(self, dirty: Sequence[tuple] = ()) -> None:
        self.dirty = {(p, int(s), sc) for p, s, sc in dirty}
        self.calls: List[tuple] = []

    def available(self) -> bool:
        return True

    def __call__(self, profile_id: str, seed: int, scale: str) -> bool:
        self.calls.append((profile_id, int(seed), scale))
        return (profile_id, int(seed), scale) not in self.dirty


class UnavailableScreen(FixtureScreen):
    name = "fixture-screen(unavailable)"

    def available(self) -> bool:
        return False


class RaisingScreen(FixtureScreen):
    name = "fixture-screen(raises)"

    def __call__(self, profile_id: str, seed: int, scale: str) -> bool:
        raise rp.OracleScreenUnavailable("the frozen runtime died mid-screen")


class StubSandbox(rp.CandidateSandbox):
    """A sandbox stand-in. Declares itself NOT consensus-grade, by construction."""

    name = "stub-sandbox(TEST DOUBLE)"
    consensus_grade = False

    def __init__(self, *, reproduced: bool = True, body: Optional[Mapping[str, Any]] = None,
                 receipt_hash: Optional[str] = None, networkless: bool = True,
                 available: bool = True, raises: Optional[Exception] = None,
                 malformed: bool = False,
                 networkless_evidence: Optional[Mapping[str, Any]] = None,
                 consensus_grade: Optional[bool] = None) -> None:
        self._reproduced = reproduced
        self._body = body
        self._receipt_hash = receipt_hash
        self._networkless = networkless
        self._available = available
        self._raises = raises
        self._malformed = malformed
        #: The W2 demonstration a real sandbox must supply. A test double may omit it (and is
        #: excluded from consensus by ``consensus_grade=False``); a stub that CLAIMS consensus
        #: grade without it is refused, which is what the unproven-sandbox test asserts.
        self._networkless_evidence = networkless_evidence
        if consensus_grade is not None:
            self.consensus_grade = bool(consensus_grade)
        self.calls = 0

    def available(self) -> bool:
        return self._available

    def execute(self, *, receipt_wrapper, artifact):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        if self._malformed:
            return {"sandbox": self.name}
        out = {"reproduced": self._reproduced, "code": None if self._reproduced else "divergence",
               "reason": "stub", "receipt_hash": self._receipt_hash,
               "body": dict(self._body) if self._body is not None else None,
               "sandbox": self.name, "networkless": self._networkless}
        if self._networkless_evidence is not None:
            out["networkless_evidence"] = dict(self._networkless_evidence)
        return out


# --------------------------------------------------------------------------- #
# Scenario
# --------------------------------------------------------------------------- #
class Scenario:
    """One confirmed advance plus everything a public validator would fetch to replay it."""

    def __init__(self, *, epoch: int = 7, indices=(0, 1, 2), admit: bool = True,
                 secret: str = "7" * 64, candidate_hash: str = "e" * 64,
                 canary: Optional[Mapping[str, Any]] = None, block_number: int = 100,
                 log_index: int = 0, transition_index: int = 0,
                 store: Optional[pub.ContentStore] = None, **receipt_kwargs) -> None:
        self.epoch = epoch
        self.store = store if store is not None else pub.InMemoryCAS()
        self.parent = make_manifest(epoch=epoch)
        self.parent_root = fr.frontier_root(self.parent)
        self.transition = fr.make_transition(
            target_profile=TARGET_PROFILE, expected_prior_release_root=ROOT_B,
            new_release_root="d" * 64, resulting_composition_root="4" * 64)
        self.new_root = fr.frontier_root(fr.apply_transition(self.parent, self.transition))
        self.secret = secret
        self.candidate_hash = candidate_hash

        self.gate_entropy = ea.derive_entropy_value(
            revealed_secret=secret, epoch=epoch, parent_frontier_root=self.parent_root,
            label="gate")
        self.confirm_entropy = ea.derive_entropy_value(
            revealed_secret=secret, epoch=epoch, parent_frontier_root=self.parent_root,
            label="confirm")
        self.bases = {
            label: ea.selection_base(
                label=label,
                entropy_value=self.gate_entropy if label == "gate" else self.confirm_entropy,
                candidate_hash=candidate_hash, season_root=SEASON_ROOT,
                profile_id=TARGET_PROFILE, round_id="round-0001")
            for label in ea.SELECTION_LABELS}
        self.cases = {label: selection_cases(self.bases[label], indices)
                      for label in ea.SELECTION_LABELS}
        self.wrapper = make_receipt_wrapper(
            gate_entropy=self.gate_entropy, confirm_entropy=self.confirm_entropy,
            gate_cases=self.cases["gate"], confirm_cases=self.cases["confirm"], admit=admit,
            candidate_hash=candidate_hash, **receipt_kwargs)
        self.law = ea.load_counter_resource_law()
        self.parts = {"parent": self.parent, "law": self.law, "wrapper": self.wrapper}
        self.availability = publish_required(self.parts, self.store)
        self.artifact = ea.build_artifact(
            epoch=epoch, parent_manifest=self.parent, transition=self.transition,
            candidate_hash=candidate_hash, receipt_wrapper=self.wrapper,
            revealed_entropy_secret=secret, counter_resource_law=self.law,
            availability=self.availability, canary=canary)
        self.eval_report_hash = ea.publish_artifact(self.artifact, store=self.store)
        self.transition_bytes = fr.canonical_bytes(self.transition)
        self.entropy_commitment = ea.entropy_commitment_of(secret)
        self.transition_index = transition_index
        self.block_number = block_number
        self.log_index = log_index

    # -- logs ----------------------------------------------------------------
    def advance_log(self, **overrides) -> Dict[str, Any]:
        kwargs = dict(
            address=V5_REGISTRY, epoch=self.epoch, transition_index=self.transition_index,
            miner=MINER, parent_frontier_root=self.parent_root,
            new_frontier_root=self.new_root,
            candidate_release_root=self.artifact["candidate"]["release_root"],
            composition_root=self.artifact["frontier"]["composition_root"],
            eval_report_hash=self.eval_report_hash,
            benchmark_law_root=self.parent["benchmark_law_root"],
            runtime_abi_root=self.parent["runtime_abi_root"],
            transition_bytes=self.transition_bytes, block_number=self.block_number,
            log_index=self.log_index)
        kwargs.update(overrides)
        return dp.encode_frontier_advanced_log(**kwargs)

    def event(self, **overrides) -> dp.FrontierAdvanced:
        return dp.decode_frontier_advanced(self.advance_log(**overrides))

    def credit_log(self, **overrides) -> Dict[str, Any]:
        words = [f"{self.transition_index:064x}", "cc" * 32, self.parent_root, self.new_root,
                 dp.PROFILE_ID_HASHES[TARGET_PROFILE],
                 self.artifact["candidate"]["release_root"],
                 self.artifact["frontier"]["composition_root"], self.eval_report_hash,
                 f"{1000:064x}"]
        for key, value in overrides.items():
            words[{"solve_index": 0, "receipt_hash": 1, "parent_frontier_root": 2,
                   "new_frontier_root": 3, "target_profile_id": 4,
                   "candidate_release_root": 5, "composition_root": 6,
                   "eval_report_hash": 7, "credits_earned": 8}[key]] = value
        log = dp.encode_simple_log(
            address=V5_REGISTRY, topic0=dp.V5_CREDIT_ACCEPTED_TOPIC0,
            indexed=[f"{self.epoch:064x}", "0" * 24 + MINER[2:]], words=words,
            block_number=self.block_number, log_index=self.log_index + 1)
        log["transactionHash"] = self.advance_log()["transactionHash"]
        return log

    def credit_event(self, **overrides) -> dp.CreditAccepted:
        return dp.decode_credit_accepted(self.credit_log(**overrides))

    def context_log(self, **overrides) -> Dict[str, Any]:
        # LAW PINS ONLY — the context no longer carries a head (ruling §17.237).
        words = [overrides.get("runtime_abi_root", self.parent["runtime_abi_root"]),
                 overrides.get("benchmark_law_root", self.parent["benchmark_law_root"]),
                 overrides.get("counter_resource_law_root",
                               self.artifact["counter_resource_law_root"])]
        return dp.encode_simple_log(address=V5_REGISTRY, topic0=dp.V5_EPOCH_CONTEXT_SET_TOPIC0,
                                    indexed=[f"{self.epoch:064x}"], words=words,
                                    block_number=self.block_number - 10, log_index=0)

    def inherited_log(self, **overrides) -> Dict[str, Any]:
        """The epoch-head publication the registry emits inside the epoch's FIRST transition.

        This scenario's epoch is the earliest one with a transition, so it inherits the deployment
        genesis root — which, for a scenario whose parent manifest IS the deployment's starting
        state, is ``self.parent_root``.
        """
        kwargs = dict(address=V5_REGISTRY, epoch=self.epoch, inherited_from_epoch=self.epoch,
                      inherited_parent_root=self.parent_root, new_frontier_root=self.new_root,
                      from_genesis=True, block_number=self.block_number,
                      log_index=max(self.log_index - 1, 0))
        kwargs.update(overrides)
        log = dp.encode_epoch_inherited_log(**kwargs)
        log["transactionHash"] = self.advance_log()["transactionHash"]
        return log

    @property
    def genesis_frontier_root(self) -> str:
        """The deployment genesis root this scenario's earliest epoch inherits."""
        return self.parent_root

    def commit_log(self, commitment: Optional[str] = None) -> Dict[str, Any]:
        return dp.encode_simple_log(
            address=V5_REGISTRY, topic0=dp.V5_EPOCH_COMMIT_SET_TOPIC0,
            indexed=[f"{self.epoch:064x}", commitment or self.entropy_commitment], words=[],
            block_number=self.block_number - 9, log_index=0)

    def reveal_log(self, secret: Optional[str] = None) -> Dict[str, Any]:
        return dp.encode_simple_log(
            address=V5_REGISTRY, topic0=dp.V5_EPOCH_SECRET_REVEALED_TOPIC0,
            indexed=[f"{self.epoch:064x}"], words=[secret or self.secret],
            block_number=self.block_number + 50, log_index=0)

    def context_logs(self, *, reveal: bool = False) -> List[Dict[str, Any]]:
        logs = [self.context_log(), self.commit_log()]
        if reveal:
            logs.append(self.reveal_log())
        return logs

    # -- pins ----------------------------------------------------------------
    def pins(self, *, reveal: bool = False, **overrides) -> dp.EpochPins:
        kwargs = dict(epoch=self.epoch,
                      runtime_abi_root=self.parent["runtime_abi_root"],
                      benchmark_law_root=self.parent["benchmark_law_root"],
                      counter_resource_law_root=self.artifact["counter_resource_law_root"],
                      entropy_commitment=self.entropy_commitment,
                      revealed_secret=self.secret if reveal else None)
        kwargs.update(overrides)
        return dp.EpochPins(**kwargs)

    def resolver(self, *, reveal: bool = False, **overrides) -> dp.PinResolver:
        return dp.pins_from_mapping({self.epoch: self.pins(reveal=reveal, **overrides)})

    # -- replay --------------------------------------------------------------
    def replay(self, *, screen=None, sandbox=None, event=None, **kwargs) -> rp.ReplayResult:
        """A fully-wired replay with declared test doubles (opt-in is explicit)."""
        kwargs.setdefault("allow_test_doubles", True)
        kwargs.setdefault("pins", self.resolver())
        return rp.replay_advance(event or self.event(), store=self.store,
                                 screen=screen if screen is not None else FixtureScreen(),
                                 sandbox=sandbox if sandbox is not None else StubSandbox(),
                                 **kwargs)


def unknown_topic_log(address: str = V5_REGISTRY) -> Dict[str, Any]:
    """A log with a topic0 no CoreTex decoder knows — must be IGNORED, never fatal."""
    return dp.encode_simple_log(address=address, topic0="de" * 32,
                                indexed=[f"{9:064x}"], words=["ab" * 32], block_number=1,
                                log_index=0)


def v4_advance_log(*, address: str = V4_REGISTRY, epoch: int = 3, transition_index: int = 0,
                   patch: bytes = b"\x01\x02\x03") -> Dict[str, Any]:
    """A ``CoreTexStateAdvanced`` log, ABI-encoded exactly as CoreTexRegistry emits it."""
    head = "".join(f"{int(v, 16):064x}" for v in
                   ("aa" * 32, "bb" * 32, "cc" * 32, "dd" * 32, "ee" * 32, "ff" * 32, "11" * 32))
    head += f"{4200:064x}"                      # improvementCredits (uint256)
    head += f"{1024:064x}"                      # wordCount (uint16)
    head += f"{10 * 32:064x}"                   # bytes offset
    padded = patch + b"\x00" * ((32 - len(patch) % 32) % 32)
    data = head + f"{len(patch):064x}" + padded.hex()
    return {"address": address,
            "topics": ["0x" + dp.V4_STATE_ADVANCED_TOPIC0, "0x" + f"{epoch:064x}",
                       "0x" + f"{transition_index:064x}", "0x" + "0" * 24 + MINER[2:]],
            "data": "0x" + data, "blockNumber": 5, "logIndex": 0,
            "transactionHash": "0x" + "0" * 64}
