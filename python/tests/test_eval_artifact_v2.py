# SPDX-License-Identifier: Apache-2.0
"""Focused public-client coverage for chain-committed eval-artifact v2."""
from __future__ import annotations

import copy

import pytest

import eval_artifact as ea
import publication as pub
from conftest import make_artifact, verify_kwargs
from validator import backlog as bl
from validator_fixtures import Scenario


def _as_v2(artifact, report, store):
    out = copy.deepcopy(artifact)
    out["format"] = ea.ARTIFACT_FORMAT
    out["receipt"] = {
        "code_roots": dict(report["code_roots"]),
        "eval_report_root": ea.eval_report_root(report),
        "measurement_policy": report["measurement_policy"],
        "outputs_hash": report["outputs_hash"],
    }
    out["availability"].pop("receipt_wrapper")
    out["availability"]["eval_report"] = pub.publish_item(
        report, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    return out


def _v2_fixture():
    historical, parts, store = make_artifact()
    report = parts["wrapper"]["receipt"]
    artifact = _as_v2(historical, report, store)
    kwargs = verify_kwargs(artifact, parts)
    kwargs.pop("receipt_wrapper")
    kwargs["eval_report"] = report
    return artifact, report, store, kwargs


def test_v2_verifies_the_addressed_report_without_an_offchain_signature():
    artifact, _, _, kwargs = _v2_fixture()
    verified = ea.verify_artifact(artifact, **kwargs)
    assert verified["ok"] is True
    assert verified["authority_law"] == ea.al.LAW_CHAIN_COMMITTED_V2
    assert "receipt_signature" not in verified["checks"]


def test_v2_refuses_report_substitution_and_historical_signature_inputs():
    artifact, report, _, kwargs = _v2_fixture()
    substituted = copy.deepcopy(report)
    substituted["outputs_hash"] = "f" * 64
    with pytest.raises(ea.ReceiptBindingError, match="canonical bytes hash"):
        ea.verify_artifact(artifact, **dict(kwargs, eval_report=substituted))
    with pytest.raises(ea.ReceiptBindingError, match="cannot be authorized"):
        ea.verify_artifact(artifact, **dict(kwargs, signature_verifier=lambda _: True))
    with pytest.raises(ea.al.WrongLawError):
        ea.verify_signed_era_artifact(artifact, **kwargs)


def test_v2_report_is_fetched_and_rehashed_through_the_public_store():
    artifact, _, store, kwargs = _v2_fixture()
    kwargs.pop("eval_report")
    verified = ea.verify_artifact(artifact, store=store, **kwargs)
    assert verified["ok"] is True


def test_replay_advance_dispatches_v2_without_mixing_the_signed_wrapper_law():
    scenario = Scenario()
    report = scenario.wrapper["receipt"]
    scenario.artifact = _as_v2(scenario.artifact, report, scenario.store)
    scenario.eval_report_hash = ea.publish_artifact(scenario.artifact, store=scenario.store)

    result = scenario.replay()
    assert result.outcome is bl.PASS
    assert result.ok is True
