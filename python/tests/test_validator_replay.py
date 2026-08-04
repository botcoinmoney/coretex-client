# SPDX-License-Identifier: UNLICENSED
"""Cut V5-E — THE CONSENSUS-CRITICAL REPLAY.

§17.236's walk, executed and attacked: read confirmed event -> fetch parent manifest + verify its
root -> apply transitionBytes -> reproduce newFrontierRoot -> fetch the artifact by
evalReportHash -> rehash -> verify EVERY binding -> re-derive the selection from the committed
entropy -> prove no legitimate index was skipped -> execute the candidate in the pinned
networkless sandbox -> recompute utility/safety/rendered cost/fuel/storage -> confirm it beat the
EXACT parent incumbent.

Two discipline rules run through every test here:

  * a binding that was reproduced and DISAGREED is a FAIL;
  * a binding that could not be REACHED is a BACKLOG — never a pass, and never a fail either.
"""
from __future__ import annotations

import copy
import os

import pytest

import eval_artifact as ea
import frontier as fr
import publication as pub
from validator import backlog as bl
from validator import dispatch as dp
from validator import replay as rp
from validator import sync as sy

from validator_fixtures import (FixtureScreen, RaisingScreen, Scenario, StubSandbox,
                                UnavailableScreen)


@pytest.fixture()
def scenario():
    return Scenario()


class AmnesiacFor(pub.InMemoryCAS):
    """A store that has everything except one root — the "not published yet" surface."""

    def __init__(self, base: pub.InMemoryCAS, missing: str) -> None:
        super().__init__()
        self._objects = dict(base._objects)
        self.missing = missing

    def get(self, root: str) -> bytes:
        if root == self.missing:
            raise pub.ObjectNotFoundError(f"no object at {root}")
        return super().get(root)

    def has(self, root: str) -> bool:
        return root != self.missing and super().has(root)


class SubstitutingStore(pub.InMemoryCAS):
    """A surface that serves OTHER bytes at a requested root. The read-back must catch it."""

    def __init__(self, base: pub.InMemoryCAS, root: str, replacement: bytes) -> None:
        super().__init__()
        self._objects = dict(base._objects)
        self.root = root
        self.replacement = replacement

    def get(self, root: str) -> bytes:
        if root == self.root:
            return self.replacement
        return super().get(root)


# --------------------------------------------------------------------------- #
# happy path
# --------------------------------------------------------------------------- #
def test_happy_path_replays_to_pass(scenario):
    result = scenario.replay()
    assert result.outcome is bl.PASS
    assert result.ok is True and result.backlog_entry is None
    assert result.detail["verdict"]["verdict"] == "ADMIT"
    assert result.detail["target_profile"] == "doc.tool.v1"
    assert result.new_manifest["profiles"]["doc.tool.v1"] == "d" * 64


def test_happy_path_runs_every_named_stage(scenario):
    checks = scenario.replay().checks
    for stage in ("event", "epoch_pins", "parent_manifest", "frontier_replay", "artifact_rehash",
                  "bindings", "entropy_expansion", "selection_completeness", "sandbox",
                  "recompute", "incumbent_law"):
        assert stage in checks, stage


def test_the_result_is_json_safe_and_declares_consensus_criticality(scenario):
    record = scenario.replay().as_dict()
    fr.canonical_bytes({k: v for k, v in record.items() if k != "auxiliary"})
    assert record["consensus_critical"] is True
    assert record["outcome"] == "PASS"


def test_the_reproduced_child_manifest_hashes_to_the_events_new_root(scenario):
    result = scenario.replay()
    assert fr.frontier_root(result.new_manifest) == scenario.new_root


# --------------------------------------------------------------------------- #
# the event itself
# --------------------------------------------------------------------------- #
def test_a_removed_log_is_refused(scenario):
    log = scenario.advance_log()
    log["removed"] = True
    result = scenario.replay(event=dp.decode_frontier_advanced(log))
    assert result.outcome is bl.FAIL and result.code == "reorged_log"


def test_a_zero_root_event_is_refused(scenario):
    result = scenario.replay(event=scenario.event(new_frontier_root="0" * 64))
    assert result.outcome is bl.FAIL and result.code == "zero_root"


def test_a_no_op_advance_is_refused(scenario):
    result = scenario.replay(event=scenario.event(new_frontier_root=scenario.parent_root))
    assert result.outcome is bl.FAIL and result.code == "no_op_advance"


def test_a_wrong_parent_event_fails_the_live_root_cas(scenario):
    result = scenario.replay(live_root="1" * 64)
    assert result.outcome is bl.FAIL and result.code == "live_root_mismatch"
    assert "exactly one candidate per parent" in result.reason


# --------------------------------------------------------------------------- #
# per-epoch pins
# --------------------------------------------------------------------------- #
def test_missing_epoch_pins_are_a_backlog_not_a_pass(scenario):
    result = scenario.replay(pins=dp.pins_from_mapping({}))
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.EPOCH_PINS_UNAVAILABLE
    assert result.ok is False


def test_pins_come_from_the_events_own_epoch(scenario):
    other = Scenario(epoch=8)
    # only epoch 8's pins are known; the epoch-7 event must NOT borrow them
    result = scenario.replay(pins=other.resolver())
    assert result.outcome is bl.BACKLOG
    assert "epoch 7" in result.reason


def test_a_benchmark_law_pin_mismatch_fails(scenario):
    result = scenario.replay(pins=scenario.resolver(benchmark_law_root="0" * 63 + "1"))
    assert result.outcome is bl.FAIL and result.code == "benchmark_law_root_mismatch"


def test_a_runtime_abi_pin_mismatch_fails(scenario):
    result = scenario.replay(pins=scenario.resolver(runtime_abi_root="0" * 63 + "2"))
    assert result.outcome is bl.FAIL and result.code == "runtime_abi_root_mismatch"


def test_a_counter_law_pin_mismatch_fails(scenario):
    result = scenario.replay(pins=scenario.resolver(counter_resource_law_root="0" * 63 + "3"))
    assert result.outcome is bl.FAIL and result.stage == "bindings"


def test_an_entropy_commitment_pin_mismatch_fails(scenario):
    # THE binding V4 declares and never reads (see V4_DEAD_PATH_DEFECT). Here it bites.
    result = scenario.replay(pins=scenario.resolver(entropy_commitment="0" * 63 + "4"))
    assert result.outcome is bl.FAIL and result.stage == "bindings"
    assert "commitment" in result.reason


def test_the_chain_revealed_secret_is_cross_checked(scenario):
    good = scenario.replay(pins=scenario.resolver(reveal=True))
    assert good.outcome is bl.PASS and "chain_revealed_secret" in good.checks
    bad = scenario.replay(pins=scenario.resolver(reveal=True, revealed_secret="a" * 64))
    assert bad.outcome is bl.FAIL and bad.code == "revealed_secret_mismatch"


# --------------------------------------------------------------------------- #
# parent manifest
# --------------------------------------------------------------------------- #
def test_an_unfetchable_parent_manifest_is_a_backlog(scenario):
    store = AmnesiacFor(scenario.store, scenario.parent_root)
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.UNFETCHABLE_MANIFEST
    assert result.backlog_entry.subject == scenario.parent_root


def test_a_substituted_parent_manifest_is_a_fail(scenario):
    other = fr.canonical_bytes({"format": fr.MANIFEST_FORMAT, "epoch": 7,
                                "benchmark_law_root": "1" * 64, "runtime_abi_root": "2" * 64,
                                "default_composition_root": "5" * 64,   # differs from the real one
                                "parent_frontier_root": "9" * 64,
                                "profiles": {"conv.pref.v1": "a" * 64, "doc.tool.v1": "b" * 64,
                                             "event.schema.v1": "c" * 64}})
    store = SubstitutingStore(scenario.store, scenario.parent_root, other)
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.FAIL and result.stage == "parent_manifest"


# --------------------------------------------------------------------------- #
# transitionBytes and the new root
# --------------------------------------------------------------------------- #
def test_tampered_transition_bytes_break_the_new_root(scenario):
    tampered = fr.canonical_bytes(fr.make_transition(
        target_profile="doc.tool.v1", expected_prior_release_root="b" * 64,
        new_release_root="1" * 64, resulting_composition_root="4" * 64))
    result = scenario.replay(event=scenario.event(transition_bytes=tampered))
    assert result.outcome is bl.FAIL and result.code == "new_root_mismatch"
    assert "reproduced frontier root" in result.reason


def test_non_canonical_transition_bytes_are_refused(scenario):
    import json
    pretty = json.dumps(scenario.transition, indent=2).encode("utf-8")
    result = scenario.replay(event=scenario.event(transition_bytes=pretty))
    assert result.outcome is bl.FAIL and result.code == "transition_bytes_invalid"


def test_a_stale_parent_transition_is_refused(scenario):
    stale = fr.canonical_bytes(fr.make_transition(
        target_profile="doc.tool.v1", expected_prior_release_root="7" * 64,
        new_release_root="d" * 64, resulting_composition_root="4" * 64))
    result = scenario.replay(event=scenario.event(transition_bytes=stale))
    assert result.outcome is bl.FAIL and result.code == "transition_rejected"


def test_the_event_release_root_must_match_the_transition(scenario):
    # keep the manifest edit intact but rename the release the event advertises
    event = scenario.event(candidate_release_root="8" * 64)
    result = scenario.replay(event=event)
    assert result.outcome is bl.FAIL
    assert result.code in ("candidate_release_root_mismatch", "new_root_mismatch")


# --------------------------------------------------------------------------- #
# the artifact
# --------------------------------------------------------------------------- #
def test_a_missing_artifact_is_a_backlog_not_a_pass(scenario):
    store = AmnesiacFor(scenario.store, scenario.eval_report_hash)
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.MISSING_ARTIFACT
    assert result.ok is False and result.is_fail is False


def test_an_event_naming_an_unpublished_artifact_is_a_backlog(scenario):
    result = scenario.replay(event=scenario.event(eval_report_hash="5" * 64))
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.MISSING_ARTIFACT


def test_a_substituted_artifact_is_a_fail(scenario):
    other = Scenario(epoch=7, candidate_hash="f" * 64)
    payload = fr.canonical_bytes(other.artifact)
    store = SubstitutingStore(scenario.store, scenario.eval_report_hash, payload)
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.FAIL and result.stage == "artifact"


def test_an_unfetchable_receipt_is_a_backlog(scenario):
    store = AmnesiacFor(scenario.store, scenario.artifact["receipt"]["wrapper_root"])
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.RECEIPT_UNAVAILABLE


def test_an_unfetchable_counter_law_is_a_backlog(scenario):
    store = AmnesiacFor(scenario.store, scenario.artifact["counter_resource_law_root"])
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.COUNTER_LAW_UNAVAILABLE


# --------------------------------------------------------------------------- #
# entropy expansion — the V5-C cross-cut
# --------------------------------------------------------------------------- #
def test_entropy_expansion_is_byte_identical_to_v5c():
    for epoch in (0, 1, 7, 4096, 2 ** 40):
        for secret in ("0" * 64, "7" * 64, "de" * 32):
            for parent in ("1" * 64, "ab" * 32):
                for label in ("gate", "confirm"):
                    assert rp.expand_entropy(revealed_secret=secret, epoch=epoch,
                                             parent_frontier_root=parent, label=label) == \
                        ea.derive_entropy_value(revealed_secret=secret, epoch=epoch,
                                                parent_frontier_root=parent, label=label)


def test_the_entropy_domain_constant_is_the_v5c_one():
    assert rp.ENTROPY_DOMAIN == ea.ENTROPY_DOMAIN == "coretex.memory-frontier/entropy/v1"
    assert rp.ENTROPY_LABELS == tuple(ea.SELECTION_LABELS)


def test_expansion_binds_epoch_and_parent_root():
    a = rp.expand_entropy(revealed_secret="7" * 64, epoch=7, parent_frontier_root="1" * 64,
                          label="gate")
    assert a != rp.expand_entropy(revealed_secret="7" * 64, epoch=8,
                                  parent_frontier_root="1" * 64, label="gate")
    assert a != rp.expand_entropy(revealed_secret="7" * 64, epoch=7,
                                  parent_frontier_root="2" * 64, label="gate")
    assert a != rp.expand_entropy(revealed_secret="7" * 64, epoch=7,
                                  parent_frontier_root="1" * 64, label="confirm")


def test_a_drifting_v5c_implementation_stops_replay(monkeypatch):
    monkeypatch.setattr(ea, "derive_entropy_value",
                        lambda **kw: "0" * 64, raising=True)
    with pytest.raises(rp.EntropyDomainDriftError, match="byte-identical"):
        rp.expand_entropy(revealed_secret="7" * 64, epoch=7, parent_frontier_root="1" * 64,
                          label="gate")


def test_an_unknown_entropy_label_is_refused():
    with pytest.raises(rp.EntropyDomainDriftError):
        rp.expand_entropy(revealed_secret="7" * 64, epoch=7, parent_frontier_root="1" * 64,
                          label="probe")


# --------------------------------------------------------------------------- #
# selection completeness — the half V5-C left open
# --------------------------------------------------------------------------- #
def test_a_contiguous_walk_is_complete(scenario):
    report = scenario.replay().detail["selection_completeness"]
    assert report["labels"]["gate"]["cases"] == 3
    assert report["screened_indices"] >= 6


def test_a_cherry_picked_walk_fails():
    sparse = Scenario(indices=(0, 2, 4))
    result = sparse.replay(screen=FixtureScreen())     # nothing is dirty: 1 and 3 were legitimate
    assert result.outcome is bl.FAIL
    assert result.code == "selection_incomplete"
    assert "cherry-picked" in result.reason


def test_a_skip_justified_by_the_oracle_screen_passes():
    sparse = Scenario(indices=(0, 2, 4))
    dirty = []
    for label in ("gate", "confirm"):
        for index in (1, 3):
            seed, scale = ea.derive_step(sparse.bases[label], index, ["small", "medium"])
            dirty.append(("doc.tool.v1", seed, scale))
    result = sparse.replay(screen=FixtureScreen(dirty=dirty))
    assert result.outcome is bl.PASS
    justified = result.detail["selection_completeness"]["labels"]["gate"]["justified_skips"]
    assert justified["oracle_dirty"] == 2


def test_a_skip_justified_by_a_burn_passes():
    sparse = Scenario(indices=(0, 2))
    burned = []
    for label in ("gate", "confirm"):
        seed, scale = ea.derive_step(sparse.bases[label], 1, ["small", "medium"])
        burned.append(ea.instance_id("doc.tool.v1", seed, scale))
    result = sparse.replay(screen=FixtureScreen(), burned=burned)
    assert result.outcome is bl.PASS
    assert result.detail["selection_completeness"]["labels"]["gate"][
        "justified_skips"]["burned"] == 1


def test_scoring_an_oracle_dirty_instance_fails(scenario):
    seed, scale = ea.derive_step(scenario.bases["gate"], 0, ["small", "medium"])
    result = scenario.replay(screen=FixtureScreen(dirty=[("doc.tool.v1", seed, scale)]))
    assert result.outcome is bl.FAIL and result.code == "selection_incomplete"
    assert "SCORED index 0" in result.reason


def test_scoring_a_burned_instance_fails(scenario):
    seed, scale = ea.derive_step(scenario.bases["gate"], 0, ["small", "medium"])
    result = scenario.replay(burned=[ea.instance_id("doc.tool.v1", seed, scale)])
    assert result.outcome is bl.FAIL and "SCORED burned instance" in result.reason


def test_no_screen_is_a_backlog_not_a_pass(scenario):
    result = rp.replay_advance(scenario.event(), store=scenario.store, pins=scenario.resolver(),
                               screen=None, sandbox=StubSandbox(), allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.ORACLE_SCREEN_UNAVAILABLE
    assert "UNDETERMINED" in result.reason


def test_an_unavailable_screen_is_a_backlog(scenario):
    result = scenario.replay(screen=UnavailableScreen())
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.ORACLE_SCREEN_UNAVAILABLE


def test_a_screen_that_dies_mid_walk_is_a_backlog(scenario):
    result = scenario.replay(screen=RaisingScreen())
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.ORACLE_SCREEN_UNAVAILABLE


def test_a_non_consensus_grade_screen_is_refused_by_default(scenario):
    result = rp.replay_advance(scenario.event(), store=scenario.store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox())
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.ORACLE_SCREEN_UNAVAILABLE
    assert "NOT consensus-grade" in result.reason


def test_the_completeness_budget_is_unresolved_work_not_a_verdict():
    far = Scenario(indices=(0, 1, 9000))
    result = far.replay(screen=FixtureScreen())
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.ORACLE_SCREEN_UNAVAILABLE
    assert "budget" in result.reason


def test_the_completeness_report_names_the_screen_it_used(scenario):
    report = scenario.replay().detail["selection_completeness"]
    assert "TEST DOUBLE" in report["screen"]
    assert report["consensus_grade"] is False


# --------------------------------------------------------------------------- #
# sandbox
# --------------------------------------------------------------------------- #
def test_no_sandbox_is_a_backlog_not_a_pass(scenario):
    result = rp.replay_advance(scenario.event(), store=scenario.store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=None, allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.SANDBOX_UNAVAILABLE
    assert "UNVERIFIED" in result.reason


def test_an_unavailable_sandbox_is_a_backlog(scenario):
    result = scenario.replay(sandbox=StubSandbox(available=False))
    assert result.outcome is bl.BACKLOG
    assert result.backlog_entry.reason == bl.SANDBOX_UNAVAILABLE


def test_a_non_consensus_grade_sandbox_is_refused_by_default(scenario):
    result = rp.replay_advance(scenario.event(), store=scenario.store, pins=scenario.resolver(),
                               screen=rp.AcceptAllScreen(), sandbox=StubSandbox())
    assert result.outcome is bl.BACKLOG


def test_sandbox_divergence_is_a_fail_not_a_backlog(scenario):
    result = scenario.replay(sandbox=StubSandbox(reproduced=False))
    assert result.outcome is bl.FAIL and result.code == "sandbox_divergence"


def test_a_sandbox_that_does_not_assert_networkless_is_refused(scenario):
    result = scenario.replay(sandbox=StubSandbox(networkless=False))
    assert result.outcome is bl.FAIL and result.code == "sandbox_not_networkless"
    assert "no networkless demonstration at all" in result.reason


# ---- ruling §9 W2: "networkless" must be a DEMONSTRATION, never a constant ---------------
_PROVEN = {"proof_version": 1, "enforced": True, "unenforced_families": [],
           "probes": {"AF_INET": {"created": False, "errno": 1, "errno_name": "EPERM"},
                      "AF_INET6": {"created": False, "errno": 1, "errno_name": "EPERM"}}}
_UNENFORCED = {"proof_version": 1, "enforced": False, "unenforced_families": ["AF_INET"],
               "probes": {"AF_INET": {"created": True, "errno": None},
                          "AF_INET6": {"created": False, "errno": 1, "errno_name": "EPERM"}}}


def test_a_consensus_grade_sandbox_with_no_demonstration_is_refused(scenario):
    """The W2 defect itself: a bare `networkless: True` is a constant, so it proves nothing."""
    result = scenario.replay(sandbox=StubSandbox(consensus_grade=True))
    assert result.outcome is bl.FAIL and result.code == "sandbox_networkless_unproven"
    assert "a constant is not a proof" in result.reason


def test_a_sandbox_whose_own_probe_created_an_ip_socket_is_refused(scenario):
    """Enforced-and-proven vs unenforced: the second may not pass, even claiming the flag."""
    result = scenario.replay(sandbox=StubSandbox(consensus_grade=True, networkless=True,
                                                 networkless_evidence=_UNENFORCED))
    assert result.outcome is bl.FAIL and result.code == "sandbox_not_networkless"
    assert "['AF_INET']" in result.reason and "'created': True" in result.reason


def test_a_sandbox_that_demonstrates_denial_passes_and_the_basis_is_recorded(scenario):
    result = scenario.replay(sandbox=StubSandbox(consensus_grade=True, networkless=True,
                                                 networkless_evidence=_PROVEN))
    assert result.ok, result.reason
    sandbox_detail = result.detail["sandbox"]
    assert sandbox_detail["networkless"] is True
    assert sandbox_detail["networkless_evidence"] == _PROVEN
    assert sandbox_detail["networkless_basis"].startswith("demonstrated: ")
    assert "DEMONSTRATED (not asserted)" in result.reason


def test_a_test_double_without_a_demonstration_says_so_in_the_evidence(scenario):
    """A declared test double may still assert the flag — but the detail must NOT imply a proof."""
    result = scenario.replay(sandbox=StubSandbox())
    assert result.ok, result.reason
    basis = result.detail["sandbox"]["networkless_basis"]
    assert "NOT " in basis and "demonstrated" in basis
    # absent, not null: the canonical value grammar admits no nulls (frontier._check_value)
    assert "networkless_evidence" not in result.detail["sandbox"]


def test_the_real_sandbox_derives_networkless_from_the_childs_probe():
    """The frozen-literal is gone: BenchmarkV2Sandbox's child probes, and the parent keys on it."""
    import inspect
    source = inspect.getsource(rp.BenchmarkV2Sandbox.execute)
    assert '"networkless": True' not in source, "the hard-coded literal must not come back"
    assert '"networkless": proven' in source
    child = rp._SANDBOX_CHILD
    assert "apply_networkless()" in child and "prove_networkless(" in child
    assert child.index("apply_networkless()") < child.index("from validator import replay"), \
        "the filter must be installed BEFORE the frozen replay (and the candidate) can run"


def test_the_real_sandbox_child_actually_proves_networkless_denial():
    """THE W2 proof, taken from the REAL sandbox child (not a double, not a constant).

    A deliberately malformed wrapper makes ``replay_receipt`` return ``malformed_wrapper`` in a
    second or two — but the child has by then installed the seccomp filter and attempted a real
    ``AF_INET``/``AF_INET6`` socket in the very process that would have run the candidate. That is
    the demonstration the parent gate keys on, so this asserts it against actual syscall outcomes."""
    sandbox = rp.BenchmarkV2Sandbox()
    if not sandbox.available():
        pytest.skip(f"the pinned sandbox is not provisioned here: {sandbox.unavailable_reason}")
    execution = sandbox.execute(receipt_wrapper={"receipt": {}}, artifact={})
    assert execution["reproduced"] is False and execution["code"] == "malformed_wrapper"
    proof = execution["networkless_evidence"]
    assert proof["enforced"] is True, proof
    assert proof["unenforced_families"] == [], proof
    for family in ("AF_INET", "AF_INET6"):
        assert proof["probes"][family]["created"] is False, proof
        assert proof["probes"][family]["errno_name"] == "EPERM", proof
    assert proof["install"]["installed"] is True and proof["install"]["revocable"] is False
    assert execution["networkless"] is True          # derived from the above, not hard-coded


#: An isolation module that installs NOTHING but probes HONESTLY — what an unprotected host looks
#: like. It reuses the real ``prove_networkless``/``probe_address_families`` so the only difference
#: from the production path is that no filter was installed.
_UNENFORCED_ISOLATION = '''
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("_real_iso", {real!r})
_real = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_real)


def apply_networkless(**kwargs):
    return {{"mechanism": "NONE - test stub, no filter installed", "installed": False}}


def prove_networkless(**kwargs):
    return _real.prove_networkless(**kwargs)
'''


def test_the_real_sandbox_reports_unenforced_when_nothing_denies_sockets(tmp_path):
    """The other half of the taxonomy: with no filter in force the child's probe CREATES sockets,
    so the sandbox reports ``networkless: False`` and the replay FAILS. An unproven sandbox must
    never pass as networkless — which is precisely what the old hard-coded literal did."""
    real = rp.BenchmarkV2Sandbox()
    if not real.available():
        pytest.skip(f"the pinned sandbox is not provisioned here: {real.unavailable_reason}")
    stub = tmp_path / "no_isolation.py"
    stub.write_text(_UNENFORCED_ISOLATION.format(real=real.isolation_path))
    sandbox = rp.BenchmarkV2Sandbox(isolation_path=str(stub))
    execution = sandbox.execute(receipt_wrapper={"receipt": {}}, artifact={})
    proof = execution["networkless_evidence"]
    assert proof["enforced"] is False, proof
    assert proof["probes"]["AF_INET"]["created"] is True, proof
    assert sorted(proof["unenforced_families"]) == ["AF_INET", "AF_INET6"], proof
    assert execution["networkless"] is False          # derived, so it can actually be False

    # ... and that verdict is what the replay gate keys on.
    scenario = Scenario()

    class _Unenforced(rp.BenchmarkV2Sandbox):
        consensus_grade = True

        def available(self):
            return True

        def execute(self, **kwargs):
            return dict(execution, reproduced=True, receipt_hash=None, body=None)

    result = scenario.replay(sandbox=_Unenforced())
    assert result.outcome is bl.FAIL and result.code == "sandbox_not_networkless"
    assert "STILL CREATABLE" in result.reason and "AF_INET" in result.reason


def test_the_real_sandbox_is_unavailable_without_the_isolation_module(tmp_path):
    """No enforcement module -> BACKLOG (unavailable), never a run without network denial."""
    sandbox = rp.BenchmarkV2Sandbox(isolation_path=str(tmp_path / "nope.py"))
    assert sandbox.available() is False
    assert "networkless" in sandbox.unavailable_reason
    with pytest.raises(rp.SandboxUnavailable):
        sandbox.execute(receipt_wrapper={}, artifact={})


def test_a_malformed_sandbox_result_is_refused(scenario):
    result = scenario.replay(sandbox=StubSandbox(malformed=True))
    assert result.outcome is bl.FAIL and result.code == "sandbox_malformed_result"


def test_a_sandbox_rebuilding_a_different_receipt_hash_is_refused(scenario):
    result = scenario.replay(sandbox=StubSandbox(receipt_hash="a" * 64))
    assert result.outcome is bl.FAIL and result.code == "sandbox_receipt_hash_mismatch"


def test_the_default_sandbox_is_null_and_never_silently_passes():
    assert rp.NullSandbox().available() is False
    with pytest.raises(rp.SandboxUnavailable, match="UNVERIFIED"):
        rp.NullSandbox().execute(receipt_wrapper={}, artifact={})


# --------------------------------------------------------------------------- #
# recomputation from the executed body
# --------------------------------------------------------------------------- #
def test_measurements_are_recomputed_from_the_executed_body(scenario):
    body = copy.deepcopy(scenario.wrapper["receipt"])
    body["scores"]["confirm"]["candidate"]["rendered_cost"] = 1.0
    result = scenario.replay(sandbox=StubSandbox(body=body))
    assert result.outcome is bl.FAIL and result.code == "measurement_mismatch"
    assert "rendered_cost_micro" in result.reason


def test_a_safety_violation_in_the_executed_body_fails(scenario):
    body = copy.deepcopy(scenario.wrapper["receipt"])
    body["scores"]["confirm"]["candidate"]["hard"]["validity_violations"] = 1
    result = scenario.replay(sandbox=StubSandbox(body=body))
    assert result.outcome is bl.FAIL and result.code == "safety_violation"


def test_a_non_replay_identical_candidate_fails(scenario):
    body = copy.deepcopy(scenario.wrapper["receipt"])
    body["scores"]["confirm"]["candidate"]["hard"]["replay_identical"] = False
    result = scenario.replay(sandbox=StubSandbox(body=body))
    assert result.outcome is bl.FAIL and "replay-identical" in result.reason


def test_a_body_with_no_hard_block_is_not_treated_as_safe(scenario):
    body = copy.deepcopy(scenario.wrapper["receipt"])
    body["scores"]["confirm"]["candidate"].pop("hard")
    result = scenario.replay(sandbox=StubSandbox(body=body))
    assert result.outcome is bl.FAIL and result.code == "safety_block_missing"


def test_the_safety_report_records_the_measured_gates(scenario):
    safety = scenario.replay().detail["safety"]
    assert safety["validity_violations"] == 0 and safety["replay_identical"] is True


def test_resource_accounting_is_recomputed_not_trusted(scenario):
    tampered = copy.deepcopy(scenario.artifact)
    tampered["resource_accounting"]["utility_after_ppm"] = 999999
    store = SubstitutingStore(scenario.store, scenario.eval_report_hash,
                              fr.canonical_bytes(tampered))
    # the substituted artifact no longer hashes to the event's root, so the surface is caught
    result = rp.replay_advance(scenario.event(), store=store, pins=scenario.resolver(),
                               screen=FixtureScreen(), sandbox=StubSandbox(),
                               allow_test_doubles=True)
    assert result.outcome is bl.FAIL and result.stage == "artifact"


# --------------------------------------------------------------------------- #
# did it beat the EXACT parent incumbent?
# --------------------------------------------------------------------------- #
def test_a_rejected_candidate_never_advances_the_frontier():
    rejected = Scenario(admit=False)
    result = rejected.replay()
    assert result.outcome is bl.FAIL and result.code == "not_admitted"


def test_a_candidate_that_did_not_improve_utility_is_refused():
    worse = Scenario(candidate_composite=60.0, incumbent_composite=64.0)
    result = worse.replay()
    assert result.outcome is bl.FAIL and result.code == "no_utility_improvement"


def test_the_incumbent_report_names_the_exact_parent_release(scenario):
    report = scenario.replay().detail["incumbent"]
    assert report["parent_release_root"] == scenario.parent["profiles"]["doc.tool.v1"]
    assert report["utility_gain_ppm"] == (report["utility_after_ppm"]
                                          - report["utility_before_ppm"])


def test_the_incumbent_side_must_evaluate_to_exactly_one_million_ppm(scenario):
    assert scenario.replay().detail["resource_accounting"]["resource_before_ppm"] == 1_000_000


# --------------------------------------------------------------------------- #
# miner / credit binding
# --------------------------------------------------------------------------- #
def test_the_credit_event_binds_the_miner(scenario):
    result = scenario.replay(credit_event=scenario.credit_event())
    assert result.outcome is bl.PASS and "miner_binding" in result.checks


def test_a_credit_for_a_different_miner_fails(scenario):
    log = scenario.credit_log()
    log["topics"][2] = "0x" + "0" * 24 + "1" * 40
    result = scenario.replay(credit_event=dp.decode_credit_accepted(log))
    assert result.outcome is bl.FAIL and result.code == "credit_binding_mismatch"
    assert "miner binding" in result.reason


def test_a_credit_for_a_different_profile_fails(scenario):
    credit = scenario.credit_event(target_profile_id=dp.PROFILE_ID_HASHES["conv.pref.v1"])
    result = scenario.replay(credit_event=credit)
    assert result.outcome is bl.FAIL and result.code == "credit_binding_mismatch"
    assert "conv.pref.v1" in result.reason


def test_a_credit_for_a_different_artifact_fails(scenario):
    credit = scenario.credit_event(eval_report_hash="3" * 64)
    result = scenario.replay(credit_event=credit)
    assert result.outcome is bl.FAIL and "evalReportHash" in result.reason


# --------------------------------------------------------------------------- #
# stream replay
# --------------------------------------------------------------------------- #
def _chained(base: Scenario):
    """A second advance built on the first one's confirmed child manifest."""
    child = fr.apply_transition(base.parent, base.transition)
    second = Scenario(epoch=base.epoch, store=base.store, transition_index=1,
                      block_number=base.block_number + 1, candidate_hash="a" * 64)
    return child, second


def test_a_stream_threads_the_live_root_through_an_epoch(scenario):
    events = [scenario.event()]
    result = rp.replay_stream(events, store=scenario.store, pins=scenario.resolver(),
                              screen=FixtureScreen(), sandbox=StubSandbox(),
                              allow_test_doubles=True)
    assert result.outcome is bl.PASS
    assert result.final_root_by_epoch == {7: scenario.new_root}


def test_a_stream_stops_at_a_wrong_parent(scenario):
    # the second event claims the same parent as the first, which the CAS already consumed
    events = [scenario.event(), scenario.event(transition_index=1)]
    result = rp.replay_stream(events, store=scenario.store, pins=scenario.resolver(),
                              screen=FixtureScreen(), sandbox=StubSandbox(),
                              allow_test_doubles=True)
    assert result.outcome is bl.FAIL
    assert result.results[1].code == "live_root_mismatch"
    assert result.stopped_at == (7, 1)


def test_a_stream_continues_past_a_backlog(scenario):
    store = AmnesiacFor(scenario.store, scenario.eval_report_hash)
    events = [scenario.event()]
    log = bl.Backlog()
    result = rp.replay_stream(events, store=store, pins=scenario.resolver(),
                              backlog_store=log, screen=FixtureScreen(), sandbox=StubSandbox(),
                              allow_test_doubles=True)
    assert result.outcome is bl.BACKLOG
    assert result.stopped_at is None
    # the confirmed new root is still chain truth, so the frontier advanced
    assert result.final_root_by_epoch == {7: scenario.new_root}
    assert len(log.open_entries()) == 1


def test_a_stream_records_every_backlog_entry(scenario):
    store = AmnesiacFor(scenario.store, scenario.eval_report_hash)
    log = bl.Backlog()
    rp.replay_stream([scenario.event()], store=store, pins=scenario.resolver(),
                     backlog_store=log, screen=FixtureScreen(), sandbox=StubSandbox(),
                     allow_test_doubles=True)
    rp.replay_stream([scenario.event()], store=store, pins=scenario.resolver(),
                     backlog_store=log, screen=FixtureScreen(), sandbox=StubSandbox(),
                     allow_test_doubles=True)
    assert len(log) == 1 and log.open_entries()[0].attempts == 2


def test_a_stream_first_event_must_build_on_the_derived_genesis_root(scenario):
    """§17.237: the earliest epoch inherits the DEPLOYMENT genesis root, and nothing else.

    (This replaces the old assertion that it must build on the epoch context's *pinned* genesis
    root — that pin is gone, because it was a coordinator-selected head.)
    """
    result = rp.replay_stream([scenario.event()], store=scenario.store,
                              pins=scenario.resolver(), genesis_frontier_root="6" * 64,
                              screen=FixtureScreen(), sandbox=StubSandbox(),
                              allow_test_doubles=True)
    assert result.outcome is bl.FAIL
    assert result.results[0].code == "live_root_mismatch"
    assert result.epoch_parents[7].inherited_parent_root == "6" * 64, \
        "the DERIVED value is what the replayer used, not the one the event claimed"


def test_a_stream_without_a_genesis_root_reports_the_head_unresolved(scenario):
    """An unwired validator reports unverified work; it never reports a pass it did not earn."""
    result = rp.replay_stream([scenario.event()], store=scenario.store,
                              pins=scenario.resolver(), screen=FixtureScreen(),
                              sandbox=StubSandbox(), allow_test_doubles=True)
    assert result.epoch_parents == {}
    assert "genesis_root_unknown" in result.unresolved_inheritance[7]


def test_a_reorg_of_an_epochs_first_transition_invalidates_its_inheritance(scenario):
    """§17.237 rule 7, reorg: surfaced, and NEVER silently re-derived from the survivors."""
    first = scenario.event()
    second = scenario.event(transition_index=1, parent_frontier_root=scenario.new_root,
                            new_frontier_root="a1" * 32)
    reorged = dp.decode_frontier_advanced(dict(scenario.advance_log(), removed=True))
    result = rp.replay_stream([reorged, second], store=scenario.store, pins=scenario.resolver(),
                              genesis_frontier_root=scenario.genesis_frontier_root,
                              screen=FixtureScreen(), sandbox=StubSandbox(),
                              allow_test_doubles=True)
    assert result.epoch_parents == {}, "no epoch head survives the reorg"
    assert "reorg_invalidated_epoch_inheritance" in result.unresolved_inheritance[7]
    # the reorged advance itself is a hard FAIL, not a pass and not a backlog
    assert result.results[0].code == "reorged_log"
    assert first.provenance.removed is False


def _sealed(epoch: int, final_root: str) -> dp.MemoryEpochFinalized:
    """A confirmed ``CoreTexMemoryEpochFinalized`` — the only thing that makes a root inheritable."""
    return dp.MemoryEpochFinalized(
        epoch=epoch, parent_frontier_root="0" * 63 + "1", final_frontier_root=final_root,
        runtime_abi_root="2" * 64, benchmark_law_root="1" * 64,
        counter_resource_law_root="3" * 64, transitions=1)


def test_an_epoch_inherits_the_previous_epochs_final_root(scenario):
    """The whole rule, end to end over a two-epoch stream, derived from history alone."""
    e7_first = scenario.event()
    e7_last = scenario.event(transition_index=1, parent_frontier_root=scenario.new_root,
                             new_frontier_root="b2" * 32, block_number=scenario.block_number + 1)
    # epoch 8 is EMPTY; epoch 9's first transition inherits epoch 7's SEALED FINAL root
    e9_first = scenario.event(epoch=9, transition_index=0, parent_frontier_root="b2" * 32,
                              new_frontier_root="c3" * 32,
                              block_number=scenario.block_number + 5)
    derived, anomalies = sy.derive_epoch_parents(
        [e7_first, e7_last, e9_first], genesis_frontier_root=scenario.genesis_frontier_root,
        finalizations=[_sealed(7, "b2" * 32)])
    assert anomalies == []
    assert derived[7].inherited_parent_root == scenario.genesis_frontier_root
    assert derived[7].from_genesis is True and derived[7].inherited_from_epoch is None
    assert derived[9].inherited_parent_root == "b2" * 32
    assert derived[9].inherited_from_epoch == 7, "epoch 8 was empty and is skipped"
    assert 8 not in derived


def test_an_unfinalized_preceding_epoch_leaves_the_head_unresolved(scenario):
    """§17.237 as ruled: only a CONFIRMED FINAL root may be inherited.

    An unfinalized epoch's live root can still advance, so treating it as inheritable would admit
    two lawful initializations of epoch 9 against two different parents. The validator reports
    ``preceding_epoch_not_finalized`` — the same condition the registry reverts on and the
    coordinator reports as EPOCH_HEAD_UNRESOLVED.
    """
    e7_first = scenario.event()
    e9_first = scenario.event(epoch=9, transition_index=0, parent_frontier_root=scenario.new_root,
                              new_frontier_root="c3" * 32,
                              block_number=scenario.block_number + 5)
    derived, anomalies = sy.derive_epoch_parents(
        [e7_first, e9_first], genesis_frontier_root=scenario.genesis_frontier_root)
    assert [a.code for a in anomalies] == ["preceding_epoch_not_finalized"]
    assert 9 not in derived, "unresolved, never assumed"
    assert 7 in derived, "epoch 7's own genesis inheritance is unaffected"

    # sealing epoch 7 resolves it, at the sealed root and nothing else
    derived, anomalies = sy.derive_epoch_parents(
        [e7_first, e9_first], genesis_frontier_root=scenario.genesis_frontier_root,
        finalizations=[_sealed(7, scenario.new_root)])
    assert anomalies == []
    assert derived[9].inherited_parent_root == scenario.new_root


def test_a_sealed_root_that_disagrees_with_replay_is_reported(scenario):
    e7_first = scenario.event()
    e9_first = scenario.event(epoch=9, transition_index=0, parent_frontier_root="d4" * 32,
                              new_frontier_root="c3" * 32,
                              block_number=scenario.block_number + 5)
    derived, anomalies = sy.derive_epoch_parents(
        [e7_first, e9_first], genesis_frontier_root=scenario.genesis_frontier_root,
        finalizations=[_sealed(7, "d4" * 32)])
    assert [a.code for a in anomalies] == ["final_root_disagrees_with_replay"]
    assert derived[9].inherited_parent_root == "d4" * 32, "the SEALED value is what is inherited"


def test_a_skipped_history_parent_is_derived_against_and_reported(scenario):
    """Naming an OLDER epoch's root while a later confirmed epoch exists."""
    e7_first = scenario.event()
    e9_first = scenario.event(epoch=9, transition_index=0,
                              parent_frontier_root=scenario.parent_root,  # reaches back past 7
                              new_frontier_root="c3" * 32,
                              block_number=scenario.block_number + 5)
    derived, anomalies = sy.derive_epoch_parents(
        [e7_first, e9_first], genesis_frontier_root=scenario.genesis_frontier_root,
        finalizations=[_sealed(7, scenario.new_root)])
    assert [a.code for a in anomalies] == ["epoch_parent_mismatch"]
    assert derived[9].inherited_parent_root == scenario.new_root, \
        "the rule's answer is recorded, not the advance's claim"


def test_stream_result_is_json_safe(scenario):
    import json
    result = rp.replay_stream([scenario.event()], store=scenario.store, pins=scenario.resolver(),
                              screen=FixtureScreen(), sandbox=StubSandbox(),
                              allow_test_doubles=True)
    json.dumps(result.as_dict())


# --------------------------------------------------------------------------- #
# the registered V4 defect
# --------------------------------------------------------------------------- #
def test_the_v4_dead_path_defect_is_registered_as_evidence():
    defect = rp.V4_DEAD_PATH_DEFECT
    assert defect["id"] == "V4-REPLAY-DEAD-HIDDEN-SEED-COMMIT"
    assert "expectedHiddenSeedCommit" in defect["finding"]
    assert "HIDDEN_SEED_COMMIT_MISMATCH" in defect["finding"]
    assert any("dist" in v for v in defect["verified_in"])
    assert defect["live_callers_passing_it"]


def test_v5_actually_checks_what_v4_declared_and_never_read(scenario):
    # the positive control for the defect: V5's epoch-commit binding is load-bearing
    good = scenario.replay()
    bad = scenario.replay(pins=scenario.resolver(entropy_commitment="c" * 64))
    assert good.outcome is bl.PASS
    assert bad.outcome is bl.FAIL


# --------------------------------------------------------------------------- #
# the REAL oracle screen (opt-in: ~60s, needs the frozen generators + wasm runtime)
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not os.environ.get("V5E_RUN_REAL_ORACLE_SCREEN"),
                    reason="set V5E_RUN_REAL_ORACLE_SCREEN=1 — runs the frozen generators + wasm "
                           "runtime in a child interpreter (~60s); kept out of the default suite "
                           "so the lane stays fast, but this IS the consensus-grade screen")
def test_the_real_oracle_screen_reproduces_the_documented_ground_truth():
    """The child-interpreter isolation is real, and so is the screen.

    ``scoring/oracle_screen.py`` documents doc.tool.v1 dev seed 1001 as oracle-INCONSISTENT
    (q0035, gold not servable under the runtime disclosure gate) — a seed on which EVERY
    candidate including the zero-hook reference incumbent fails the validity hard gate. Seed 1002
    is clean. If the ``frontier`` package-name collision were not actually solved by the child
    interpreter, this could not run at all.
    """
    screen = rp.ChildInterpreterOracleScreen()
    if not screen.available():                          # pragma: no cover - host-dependent
        pytest.skip("the frozen generators/runtime are not on this host")
    assert screen("doc.tool.v1", 1001, "small") is False
    assert screen("doc.tool.v1", 1002, "small") is True
    assert screen.child_calls >= 1
