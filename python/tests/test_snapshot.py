from __future__ import annotations

from types import SimpleNamespace

from coretex_validator import snapshot
from coretex_validator import join
from coretex_validator import rig_events
from coretex_validator.dispatch import LogProvenance


def _full_replay_fixture(monkeypatch, *, eval_fetch_error=False, replay_error=False):
    roots = {
        "parent": "1" * 64,
        "child": "2" * 64,
        "transition": "3" * 64,
        "evaluation": "4" * 64,
        "context": "5" * 64,
        "report": "6" * 64,
        "counter": "7" * 64,
    }
    advance = SimpleNamespace(
        join_key=(9, roots["parent"], "8" * 64),
        compact_patch_bytes=b"descriptor",
        patch_hash="8" * 64,
        parent_state_root=roots["parent"],
        new_state_root=roots["child"],
        transition_format_version=33,
        epoch_context_root=roots["context"],
        epoch=9,
        transition_index=0,
        eval_report_hash=roots["evaluation"],
    )
    joined = SimpleNamespace(
        receipt={"scoreAfterPpm": 2, "scoreBeforePpm": 1},
        credit=SimpleNamespace(provenance=SimpleNamespace(position=(10, 1))))
    context_event = SimpleNamespace(
        epoch_context_root=roots["context"], parent_state_root=roots["parent"])
    scan = SimpleNamespace(decoded=SimpleNamespace(
        advances=[advance], context_for=lambda epoch: context_event))
    monkeypatch.setattr(
        snapshot, "_seed_genesis_objects", lambda release, store: {"state": "parent"})
    monkeypatch.setattr(
        snapshot, "_transition_rows",
        lambda decoded, rpc, views, **kwargs: (
            SimpleNamespace(screener_passes=[]), {advance.join_key: joined}))
    monkeypatch.setattr(
        snapshot.rig_events, "decode_transition_descriptor",
        lambda *args, **kwargs: SimpleNamespace(patch_artifact_hash=roots["transition"]))
    monkeypatch.setattr(
        snapshot.rig_events, "verify_transition_artifact_bytes",
        lambda *args, **kwargs: {"verified": True})
    monkeypatch.setattr(
        snapshot.rig_events, "replay_transition_artifact",
        lambda current, artifact, epoch_pins: {"state": "child"})
    monkeypatch.setattr(
        snapshot.frontier, "frontier_root",
        lambda value: roots[value["state"]])
    monkeypatch.setattr(
        snapshot.replay, "verify_epoch_context",
        lambda *args, **kwargs: {"benchmark_law_root": "a" * 64,
                                "runtime_abi_root": "b" * 64})
    monkeypatch.setattr(snapshot.evaluation, "eval_report_hash", lambda value: roots["evaluation"])
    monkeypatch.setattr(snapshot.publication, "validate_availability", lambda value: value)
    evaluation = {
        "availability": {
            "counter_resource_law": {
                "bytes": 2, "hash_rule": snapshot.publication.HASH_RULE_FRONTIER_JSON,
                "root": roots["counter"]},
            "eval_report": {
                "bytes": 2, "hash_rule": snapshot.publication.HASH_RULE_FRONTIER_JSON,
                "root": roots["report"]},
        },
        "determinism_witness": {"source_root": roots["report"]},
    }
    evaluation_raw = snapshot._json_bytes(evaluation)  # noqa: SLF001

    def fetch(root, _rule):
        if root == roots["transition"]:
            return b"transition"
        if root == roots["evaluation"]:
            if eval_fetch_error:
                raise OSError("evaluation object unavailable")
            return evaluation_raw
        if root == roots["context"]:
            return b"{}"
        return b"{}"

    monkeypatch.setattr(
        snapshot, "_fetch_item",
        lambda item, fetch, store, label: store.put(item["root"], b"{}"))
    monkeypatch.setattr(
        snapshot.publication, "fetch_json",
        lambda root, **kwargs: {"root": root})
    called = []

    def full_replay(**kwargs):
        called.append(kwargs)
        if replay_error:
            raise snapshot.replay.ReplayError(
                "VERDICT_MISMATCH", "evaluation report was tampered")

    monkeypatch.setattr(snapshot.replay, "replay_descriptor_v3", full_replay)
    return roots, scan, fetch, called


def _credit(*, kind, solve_index, receipt_hash, block, log_index):
    return SimpleNamespace(
        rig_id=73,
        solve_index=solve_index,
        receipt_hash=receipt_hash,
        provenance=SimpleNamespace(
            block_number=block,
            log_index=log_index,
            position=(block, log_index),
            transaction_hash="0x" + f"{solve_index + 20:064x}",
        ),
        kind=kind,
    )


class _Views:
    def __init__(self, index, receipt_hash):
        self.index = index
        self.receipt_hash = receipt_hash

    def rig_next_index(self, rig_id):
        assert rig_id == 73
        return self.index

    def rig_last_receipt_hash(self, rig_id):
        assert rig_id == 73
        return self.receipt_hash


def test_receipt_window_anchors_nonzero_pre_activation_and_interleaves_standard_lane():
    start_hash = "1" * 64
    standard_first = _credit(
        kind="standard", solve_index=5, receipt_hash="2" * 64, block=101, log_index=2)
    coretex = _credit(
        kind="coretex", solve_index=6, receipt_hash="3" * 64, block=102, log_index=4)
    standard_last = _credit(
        kind="standard", solve_index=7, receipt_hash="4" * 64, block=103, log_index=1)
    decoded = SimpleNamespace(
        coretex_credits=[coretex], standard_credits=[standard_first, standard_last])
    scan = SimpleNamespace(decoded=decoded)
    joined = SimpleNamespace(
        transitions=[SimpleNamespace(
            credit=coretex, receipt={"prevReceiptHash": standard_first.receipt_hash})],
        screener_passes=[],
    )
    rows = snapshot._rig_receipt_rows(  # noqa: SLF001 - exact public-window invariant
        scan=scan,
        activation_views=_Views(5, start_hash),
        head_views=_Views(8, standard_last.receipt_hash),
        joined=joined,
    )
    assert rows == [{
        "end_index": 8,
        "end_receipt_hash": standard_last.receipt_hash,
        "receipts": [
            {
                "block_number": 101, "kind": "standard", "log_index": 2,
                "receipt_hash": standard_first.receipt_hash, "solve_index": 5,
                "transaction_hash": standard_first.provenance.transaction_hash,
            },
            {
                "block_number": 102, "kind": "coretex", "log_index": 4,
                "receipt_hash": coretex.receipt_hash, "solve_index": 6,
                "transaction_hash": coretex.provenance.transaction_hash,
            },
            {
                "block_number": 103, "kind": "standard", "log_index": 1,
                "receipt_hash": standard_last.receipt_hash, "solve_index": 7,
                "transaction_hash": standard_last.provenance.transaction_hash,
            },
        ],
        "rig_id": 73,
        "start_index": 5,
        "start_receipt_hash": start_hash,
    }]


def test_receipt_window_refuses_a_coretex_predecessor_that_skips_standard_history():
    standard = _credit(
        kind="standard", solve_index=5, receipt_hash="2" * 64, block=101, log_index=2)
    coretex = _credit(
        kind="coretex", solve_index=6, receipt_hash="3" * 64, block=102, log_index=4)
    scan = SimpleNamespace(decoded=SimpleNamespace(
        coretex_credits=[coretex], standard_credits=[standard]))
    joined = SimpleNamespace(
        transitions=[SimpleNamespace(credit=coretex, receipt={"prevReceiptHash": "1" * 64})],
        screener_passes=[],
    )
    import pytest
    with pytest.raises(snapshot.SnapshotBuildError, match="shared predecessor"):
        snapshot._rig_receipt_rows(  # noqa: SLF001
            scan=scan, activation_views=_Views(5, "1" * 64),
            head_views=_Views(7, coretex.receipt_hash), joined=joined)


def test_snapshot_join_requires_and_propagates_coordinator_signature_refusal(monkeypatch):
    def refused(*args, **kwargs):
        assert kwargs["verify_signature"] is True
        raise join.JoinError("JOIN_SIGNATURE_INVALID", "corrupted signature")

    monkeypatch.setattr(snapshot.join, "join_all", refused)
    views = SimpleNamespace(
        domain_separator=lambda: b"x" * 32,
        coordinator_signer=lambda: "0x" + "1" * 40,
    )
    with __import__("pytest").raises(join.JoinError, match="JOIN_SIGNATURE_INVALID"):
        snapshot._transition_rows(  # noqa: SLF001
            SimpleNamespace(), rpc=SimpleNamespace(), views=views)


def test_snapshot_uses_signer_active_at_each_receipt_block_across_rotation(monkeypatch):
    before = "0x" + "11" * 20
    after = "0x" + "22" * 20
    update = rig_events.CoordinatorSignerUpdated(
        old_signer=before, new_signer=after,
        provenance=LogProvenance(block_number=105, log_index=3))
    observed = []

    def joined(_decoded, **kwargs):
        signer_for = kwargs["coordinator_signer"]
        observed.extend([
            signer_for(LogProvenance(block_number=104, log_index=9)),
            signer_for(LogProvenance(block_number=105, log_index=4)),
        ])
        return SimpleNamespace(transitions=[], screener_passes=[], unresolved=[])

    monkeypatch.setattr(snapshot.join, "join_all", joined)
    scan = SimpleNamespace(signer_updates=(update,))
    release = SimpleNamespace(authority={"initial_coordinator_signer": before})
    views = SimpleNamespace(domain_separator=lambda: b"x" * 32)
    snapshot._transition_rows(  # noqa: SLF001
        SimpleNamespace(advances=[]), rpc=SimpleNamespace(), views=views,
        scan=scan, release=release)
    assert observed == [before, after]


def test_real_join_refuses_a_cryptographically_malformed_signature(monkeypatch):
    operator = "0x" + "11" * 20
    roots = {name: char * 64 for name, char in {
        "prev": "1", "challenge": "2", "parent": "3", "new": "4", "context": "5",
        "core": "6", "eval": "7", "patch": "8", "artifact": "9", "policy": "a",
    }.items()}
    values = {
        "rigId": 73, "operator": operator, "epochId": 9, "solveIndex": 4,
        "prevReceiptHash": roots["prev"], "outcome": 2,
        "challengeId": roots["challenge"], "parentStateRoot": roots["parent"],
        "newStateRoot": roots["new"], "epochContextRoot": roots["context"],
        "coreVersionHash": roots["core"], "evalReportHash": roots["eval"],
        "patchHash": roots["patch"], "artifactHash": roots["artifact"],
        "worldSeed": 1, "rulesVersion": 1, "workPolicyHash": roots["policy"],
        "workUnitsBps": 10_000, "difficultyCountSnapshot": 1,
        "transitionFormatVersion": 33, "scoreBeforePpm": 1, "scoreAfterPpm": 2,
        "issuedAt": 1, "expiresAt": 2, "compactPatchBytes": b"descriptor",
        "signature": b"\0" * 65,
    }
    receipt = join.CoreTexReceipt(values)
    domain = b"\x01" * 32
    credit = rig_events.CoreTexCreditAccepted(
        epoch=9, rig_id=73, operator=operator, solve_index=4,
        receipt_hash=receipt.receipt_hash(receipt.digest(domain)),
        challenge_id=roots["challenge"], work_units_bps=10_000, credits_earned=1,
        provenance=LogProvenance(transaction_hash="0x" + "ab" * 32))
    advance = rig_events.StateAdvanced(
        epoch=9, transition_index=0, miner=operator,
        parent_state_root=roots["parent"], new_state_root=roots["new"],
        patch_hash=roots["patch"], eval_report_hash=roots["eval"],
        core_version_hash=roots["core"], epoch_context_root=roots["context"],
        improvement_credits=1, transition_format_version=33,
        compact_patch_bytes=b"descriptor",
        provenance=LogProvenance(transaction_hash="0x" + "ab" * 32))
    monkeypatch.setattr(join, "decode_submit_calldata", lambda calldata: receipt)
    with __import__("pytest").raises(join.JoinError, match="JOIN_SIGNATURE_INVALID"):
        join.join_advance(
            advance, credit, "0x00", domain_separator=domain,
            coordinator_signer="0x" + "22" * 20, verify_signature=True)


def test_zero_transition_epoch_still_refuses_bad_addressed_context_bytes():
    context = {
        "core_version_hash": "1" * 64,
        "epoch_context_root": "2" * 64,
        "parent_state_root": "3" * 64,
    }
    with __import__("pytest").raises(snapshot.SnapshotBuildError, match="context object"):
        snapshot._verify_current_context_object(  # noqa: SLF001
            epoch=188, context=context, release=SimpleNamespace(),
            object_fetch=lambda root, rule: b"{}")


def test_epoch_context_parent_is_epoch_initial_across_multiple_immediate_parents():
    first_context = SimpleNamespace(
        epoch=9, epoch_context_root="a" * 64, parent_state_root="1" * 64)
    second_context = SimpleNamespace(
        epoch=10, epoch_context_root="b" * 64, parent_state_root="3" * 64)
    decoded = SimpleNamespace(
        context_for=lambda epoch: first_context if epoch == 9 else second_context)
    advances = [
        SimpleNamespace(epoch=9, transition_index=0, epoch_context_root="a" * 64,
                        parent_state_root="1" * 64),
        SimpleNamespace(epoch=9, transition_index=1, epoch_context_root="a" * 64,
                        parent_state_root="2" * 64),
        SimpleNamespace(epoch=10, transition_index=0, epoch_context_root="b" * 64,
                        parent_state_root="3" * 64),
    ]
    assert [snapshot._context_event_for_advance(decoded, item).parent_state_root  # noqa: SLF001
            for item in advances] == ["1" * 64, "1" * 64, "3" * 64]


def test_snapshot_reconstruction_requires_full_descriptor_evaluation_replay(monkeypatch):
    roots, scan, fetch, called = _full_replay_fixture(monkeypatch)
    current, _artifacts = snapshot._reconstruct_frontier(  # noqa: SLF001
        release=SimpleNamespace(), scan=scan, rpc=SimpleNamespace(), views=SimpleNamespace(),
        fetch=fetch, store=snapshot.publication.InMemoryCAS(),
        benchmark_runner=SimpleNamespace())
    assert snapshot.frontier.frontier_root(current) == roots["child"]
    assert len(called) == 1
    assert called[0]["require_availability"] is True
    assert called[0]["resolve_witness_source"] is True


def test_snapshot_reconstruction_refuses_unavailable_evaluation_artifact(monkeypatch):
    _roots, scan, fetch, _called = _full_replay_fixture(
        monkeypatch, eval_fetch_error=True)
    with __import__("pytest").raises(snapshot.SnapshotBuildError, match="evaluation artifact"):
        snapshot._reconstruct_frontier(  # noqa: SLF001
            release=SimpleNamespace(), scan=scan, rpc=SimpleNamespace(),
            views=SimpleNamespace(), fetch=fetch,
            store=snapshot.publication.InMemoryCAS(), benchmark_runner=SimpleNamespace())


def test_snapshot_reconstruction_refuses_tampered_evaluation_report(monkeypatch):
    _roots, scan, fetch, _called = _full_replay_fixture(monkeypatch, replay_error=True)
    with __import__("pytest").raises(snapshot.SnapshotBuildError, match="VERDICT_MISMATCH"):
        snapshot._reconstruct_frontier(  # noqa: SLF001
            release=SimpleNamespace(), scan=scan, rpc=SimpleNamespace(),
            views=SimpleNamespace(), fetch=fetch,
            store=snapshot.publication.InMemoryCAS(), benchmark_runner=SimpleNamespace())


def _screener_replay_fixture(monkeypatch, *, missing_artifact=False, replay_error=False):
    roots = {name: char * 64 for name, char in {
        "parent": "1", "evaluation": "2", "context": "3", "report": "4",
        "counter": "5", "witness": "6", "artifact": "9",
    }.items()}
    credit = SimpleNamespace(
        epoch=9, rig_id=73, solve_index=4,
        provenance=SimpleNamespace(position=(12, 3)))
    receipt = {
        "artifactHash": roots["artifact"], "evalReportHash": roots["evaluation"],
        "epochContextRoot": roots["context"],
    }
    screener = SimpleNamespace(credit=credit, receipt=receipt)
    joined = SimpleNamespace(screener_passes=[screener])
    context_event = SimpleNamespace(
        epoch_context_root=roots["context"], parent_state_root=roots["parent"])
    scan = SimpleNamespace(decoded=SimpleNamespace(
        advances=[], context_for=lambda _epoch: context_event))
    monkeypatch.setattr(
        snapshot, "_seed_genesis_objects", lambda release, store: {"state": "parent"})
    monkeypatch.setattr(
        snapshot, "_transition_rows", lambda *args, **kwargs: (joined, {}))
    monkeypatch.setattr(snapshot.frontier, "frontier_root", lambda value: roots[value["state"]])
    monkeypatch.setattr(snapshot.evaluation, "eval_report_hash", lambda _value: roots["evaluation"])
    monkeypatch.setattr(snapshot.publication, "validate_availability", lambda value: value)
    monkeypatch.setattr(
        snapshot.publication, "root_of",
        lambda _raw, _rule: roots["witness"])
    monkeypatch.setattr(
        snapshot, "_fetch_item",
        lambda item, fetch, store, label: store.put(item["root"], b"{}"))
    monkeypatch.setattr(
        snapshot.publication, "fetch_json", lambda root, **kwargs: {"root": root})
    monkeypatch.setattr(snapshot.replay, "verify_epoch_context", lambda *args, **kwargs: {})
    evaluation = {
        "candidate": {"release_root": roots["artifact"]},
        "availability": {
            "counter_resource_law": {
                "bytes": 2, "hash_rule": snapshot.publication.HASH_RULE_FRONTIER_JSON,
                "root": roots["counter"]},
            "eval_report": {
                "bytes": 2, "hash_rule": snapshot.publication.HASH_RULE_FRONTIER_JSON,
                "root": roots["report"]},
        },
        "determinism_witness": {"source_root": roots["witness"]},
    }
    raw = snapshot._json_bytes(evaluation)  # noqa: SLF001

    def fetch(root, _rule):
        if root == roots["evaluation"]:
            if missing_artifact:
                raise OSError("not published")
            return raw
        if root == roots["context"]:
            return b"{}"
        return b"{}"

    called = []

    def verify(**kwargs):
        called.append(kwargs)
        if replay_error:
            raise snapshot.replay.ReplayError("FORGED_REPORT", "full scorer diverged")

    monkeypatch.setattr(snapshot.replay, "replay_screener", verify)
    return scan, fetch, called


def test_screener_credit_requires_full_evidence_and_reexecution(monkeypatch):
    scan, fetch, called = _screener_replay_fixture(monkeypatch)
    current, _ = snapshot._reconstruct_frontier(  # noqa: SLF001
        release=SimpleNamespace(), scan=scan, rpc=SimpleNamespace(), views=SimpleNamespace(),
        fetch=fetch, store=snapshot.publication.InMemoryCAS(),
        benchmark_runner=SimpleNamespace())
    assert current == {"state": "parent"}
    assert len(called) == 1
    assert called[0]["parent_manifest"] == {"state": "parent"}


def test_screener_credit_refuses_absent_evaluation_artifact(monkeypatch):
    scan, fetch, _called = _screener_replay_fixture(monkeypatch, missing_artifact=True)
    with __import__("pytest").raises(snapshot.SnapshotBuildError, match="screener evaluation"):
        snapshot._reconstruct_frontier(  # noqa: SLF001
            release=SimpleNamespace(), scan=scan, rpc=SimpleNamespace(), views=SimpleNamespace(),
            fetch=fetch, store=snapshot.publication.InMemoryCAS(),
            benchmark_runner=SimpleNamespace())


def test_screener_credit_refuses_report_that_full_scorer_does_not_reproduce(monkeypatch):
    scan, fetch, _called = _screener_replay_fixture(monkeypatch, replay_error=True)
    with __import__("pytest").raises(snapshot.SnapshotBuildError, match="FORGED_REPORT"):
        snapshot._reconstruct_frontier(  # noqa: SLF001
            release=SimpleNamespace(), scan=scan, rpc=SimpleNamespace(), views=SimpleNamespace(),
            fetch=fetch, store=snapshot.publication.InMemoryCAS(),
            benchmark_runner=SimpleNamespace())


def _genesis_release_fixture(tmp_path, monkeypatch):
    frontier_root = "a" * 64
    manifest = {"state": "genesis"}
    monkeypatch.setattr(snapshot.frontier, "frontier_root", lambda value: frontier_root)
    (tmp_path / "GENESIS-FRONTIER.json").write_bytes(snapshot._json_bytes({  # noqa: SLF001
        "format": "coretex.genesis-frontier/v1",
        "frontier_root": frontier_root,
        "manifest": manifest,
    }))

    composition_body = {"format": "coretex.genesis-composition/v1", "profiles": {}}
    composition_root = snapshot._sha(snapshot._canonical(composition_body))  # noqa: SLF001
    composition = dict(composition_body, composition_root=composition_root)
    (tmp_path / "GENESIS-COMPOSITION.json").write_bytes(
        snapshot._json_bytes(composition))  # noqa: SLF001

    baseline_body = {
        "format": "coretex.genesis-baseline/v1",
        "law_id": "benchmark-v2-law/dominance-fixed-suite.v1",
        "profiles": {},
        "suite_root": "b" * 64,
    }
    baseline_root = snapshot._sha(snapshot._canonical(baseline_body))  # noqa: SLF001
    baseline = dict(baseline_body, baseline_root=baseline_root)
    baseline_raw = snapshot._json_bytes(baseline)  # noqa: SLF001
    (tmp_path / "GENESIS-BASELINE.json").write_bytes(baseline_raw)

    profile_releases = {}
    for index, profile_id in enumerate(snapshot.PROFILE_IDS):
        descriptor = {"format": "test-reference", "profile_id": profile_id}
        descriptor_root = snapshot._sha(snapshot._canonical(descriptor))  # noqa: SLF001
        filename = f"profile-{index}.json"
        (tmp_path / filename).write_bytes(snapshot._json_bytes(descriptor))  # noqa: SLF001
        profile_releases[profile_id] = {"path": filename, "root": descriptor_root}

    release = SimpleNamespace(
        path=str(tmp_path),
        genesis_frontier_root=frontier_root,
        release=SimpleNamespace(raw={
            "genesis": {
                "baseline_root": baseline_root,
                "composition_root": composition_root,
                "profile_releases": profile_releases,
            },
        }),
    )
    return release, manifest, baseline_root, baseline_raw


def test_snapshot_seeds_exact_final_genesis_baseline_bytes(tmp_path, monkeypatch):
    release, manifest, baseline_root, baseline_raw = _genesis_release_fixture(
        tmp_path, monkeypatch)
    store = snapshot.publication.InMemoryCAS()
    assert snapshot._seed_genesis_objects(release, store) == manifest  # noqa: SLF001
    assert store.get(baseline_root) == baseline_raw


def test_snapshot_refuses_genesis_baseline_whose_body_does_not_rehash(tmp_path, monkeypatch):
    release, _manifest, _baseline_root, _baseline_raw = _genesis_release_fixture(
        tmp_path, monkeypatch)
    baseline_path = tmp_path / "GENESIS-BASELINE.json"
    baseline = snapshot._load_json_bytes(  # noqa: SLF001
        baseline_path.read_bytes(), "GENESIS-BASELINE.json")
    baseline["suite_root"] = "c" * 64
    baseline_path.write_bytes(snapshot._json_bytes(baseline))  # noqa: SLF001
    with __import__("pytest").raises(snapshot.SnapshotBuildError, match="does not reproduce"):
        snapshot._seed_genesis_objects(  # noqa: SLF001
            release, snapshot.publication.InMemoryCAS())
