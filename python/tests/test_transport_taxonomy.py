# SPDX-License-Identifier: Apache-2.0
"""Transport absence is unresolved work; disagreeing bytes are a refutation.

These tests exercise the public fetch boundaries rather than only the HTTP adapter.  A timeout
and a missing object are two members of one unavailable family: neither proves that committed
bytes are wrong.  Canonical, integrity, and schema failures remain publication defects and must
never be softened into BACKLOG.
"""
from __future__ import annotations

import http.client
import json
import os
from types import SimpleNamespace
import urllib.error

import pytest

from coretex_validator import chain_first as cf
from coretex_validator import cli
from coretex_validator import pipeline
from coretex_validator import publication as pub
from coretex_validator import rig_discovery as rd
from validator_fixtures import Scenario


class _FailingRootStore(pub.ContentStore):
    """Delegate every object except one whose fetch raises the requested publication error."""

    def __init__(self, delegate: pub.ContentStore, root: str, error_type) -> None:
        self.delegate = delegate
        self.root = root
        self.error_type = error_type

    def put(self, root: str, data: bytes) -> None:
        self.delegate.put(root, data)

    def get(self, root: str) -> bytes:
        if root == self.root:
            raise self.error_type(f"fixture failure fetching {root}")
        return self.delegate.get(root)

    def has(self, root: str) -> bool:
        return root != self.root and self.delegate.has(root)


def _http_error(code: int):
    def fail(request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else request
        raise urllib.error.HTTPError(url, code, "fixture", {}, None)
    return fail


def _network_error(error):
    def fail(request, timeout=None):
        raise error
    return fail


def test_publication_unavailable_is_a_closed_two_case_family():
    assert issubclass(pub.ObjectNotFoundError, pub.PublicationUnavailableError)
    assert issubclass(pub.TransportUnavailableError, pub.PublicationUnavailableError)
    assert not issubclass(pub.AvailabilityError, pub.PublicationUnavailableError)
    assert not issubclass(pub.ReadBackMismatchError, pub.PublicationUnavailableError)


@pytest.mark.parametrize("code", [400, 408, 429, 500, 503])
def test_non_404_http_errors_are_transport_unavailable(monkeypatch, code):
    monkeypatch.setattr(pipeline.urllib.request, "urlopen", _http_error(code))
    store = pipeline.UrlContentStore("https://cas.example/objects")
    with pytest.raises(pub.TransportUnavailableError):
        store.get_for_rule("a" * 64, pub.HASH_RULE_BYTES)


@pytest.mark.parametrize("error", [urllib.error.URLError("dns unavailable"),
                                    OSError("socket unavailable"),
                                    http.client.IncompleteRead(b"partial", 12)])
def test_network_errors_are_transport_unavailable(monkeypatch, error):
    monkeypatch.setattr(pipeline.urllib.request, "urlopen", _network_error(error))
    store = pipeline.UrlContentStore("https://cas.example/objects")
    with pytest.raises(pub.TransportUnavailableError):
        store.get_for_rule("b" * 64, pub.HASH_RULE_BYTES)


@pytest.mark.parametrize("error_type", [pub.ObjectNotFoundError,
                                         pub.TransportUnavailableError])
def test_verify_availability_preserves_the_unavailable_subtype(error_type):
    root = "c" * 64
    items = {"candidate": pub.availability_item(root, pub.HASH_RULE_BYTES, 1)}
    store = _FailingRootStore(pub.InMemoryCAS(), root, error_type)
    with pytest.raises(error_type):
        pub.verify_availability(items, store=store, required=("candidate",))


def test_verify_availability_keeps_integrity_failure_structural():
    root = "d" * 64
    items = {"candidate": pub.availability_item(root, pub.HASH_RULE_BYTES, 1)}
    store = _FailingRootStore(pub.InMemoryCAS(), root, pub.ReadBackMismatchError)
    with pytest.raises(pub.AvailabilityError):
        pub.verify_availability(items, store=store, required=("candidate",))


@pytest.mark.parametrize(
    "error_type,expected_outcome",
    [
        (pub.ObjectNotFoundError, "BACKLOG"),
        (pub.TransportUnavailableError, "BACKLOG"),
        (pub.ReadBackMismatchError, "FAIL"),
        (pub.HashRuleError, "FAIL"),
        (pub.AvailabilityError, "FAIL"),
    ],
)
def test_pipeline_initial_artifact_classifies_unavailable_vs_refuted(
        monkeypatch, error_type, expected_outcome):
    selected = SimpleNamespace(advance=SimpleNamespace(eval_report_hash="e" * 64))

    def fail(*args, **kwargs):
        raise error_type("fixture fetch failure")

    monkeypatch.setattr(pipeline.pub, "fetch_json", fail)
    artifact, report = pipeline._admit(
        selected, SimpleNamespace(), pub.InMemoryCAS(), allow_test_doubles=False)
    assert artifact is None
    assert report["outcome"] == expected_outcome


@pytest.mark.parametrize(
    "root_of,expected_stage",
    [
        (lambda scenario: scenario.parent_root, "parent_manifest"),
        (lambda scenario: scenario.eval_report_hash, "artifact"),
        (lambda scenario: scenario.artifact["receipt"]["wrapper_root"], "receipt"),
        (lambda scenario: scenario.artifact["counter_resource_law_root"],
         "counter_resource_law"),
    ],
)
@pytest.mark.parametrize(
    "error_type,expected_outcome",
    [
        (pub.ObjectNotFoundError, "BACKLOG"),
        (pub.TransportUnavailableError, "BACKLOG"),
        (pub.AvailabilityError, "FAIL"),
    ],
)
def test_replay_fetch_boundaries_do_not_call_transport_a_refutation(
        root_of, expected_stage, error_type, expected_outcome):
    scenario = Scenario()
    scenario.store = _FailingRootStore(scenario.store, root_of(scenario), error_type)
    result = scenario.replay()
    assert str(result.outcome) == expected_outcome
    assert result.stage == expected_stage


@pytest.mark.parametrize(
    "error_type,expected_outcome",
    [
        (pub.ObjectNotFoundError, "BACKLOG"),
        (pub.TransportUnavailableError, "BACKLOG"),
        (pub.ReadBackMismatchError, "FAIL"),
        (pub.AvailabilityError, "FAIL"),
    ],
)
def test_rig_projection_does_not_call_transport_corruption(monkeypatch, error_type,
                                                            expected_outcome):
    def fail(*args, **kwargs):
        raise error_type("fixture fetch failure")

    monkeypatch.setattr(rd.pub, "fetch_json", fail)
    with pytest.raises(rd.ProjectionError) as excinfo:
        rd._fetch_artifact("f" * 64, store=pub.InMemoryCAS())
    assert excinfo.value.outcome == expected_outcome


@pytest.mark.parametrize(
    "error_type,expected_outcome",
    [
        (pub.ObjectNotFoundError, "BACKLOG"),
        (pub.TransportUnavailableError, "BACKLOG"),
        (pub.ReadBackMismatchError, "FAIL"),
        (pub.AvailabilityError, "FAIL"),
    ],
)
def test_rig_epoch_context_does_not_call_transport_malformed(monkeypatch, error_type,
                                                              expected_outcome):
    root = "2" * 64
    advance = SimpleNamespace(epoch=184, epoch_context_root=root)
    feed = SimpleNamespace(decoded=object())
    monkeypatch.setattr(rd.hl, "law_for_epoch", lambda *_: SimpleNamespace(
        epoch_context_root=root))

    def fail(*args, **kwargs):
        raise error_type("fixture fetch failure")

    monkeypatch.setattr(rd.pub, "read_back", fail)
    with pytest.raises(rd.ProjectionError) as excinfo:
        rd.pins_for(advance, feed=feed, store=pub.InMemoryCAS())
    assert excinfo.value.outcome == expected_outcome


@pytest.mark.parametrize(
    "error_type,expected_code",
    [
        (pub.ObjectNotFoundError, "MISSING_ARTIFACT"),
        (pub.TransportUnavailableError, "MISSING_ARTIFACT"),
        (pub.ReadBackMismatchError, "ARTIFACT_INTEGRITY_FAILURE"),
        (pub.AvailabilityError, "ARTIFACT_INTEGRITY_FAILURE"),
    ],
)
def test_chain_first_fetch_does_not_call_transport_integrity(error_type, expected_code):
    root = "1" * 64
    store = _FailingRootStore(pub.InMemoryCAS(), root, error_type)
    commitment = cf.ArtifactCommitment(
        "fixture", root, pub.HASH_RULE_BYTES, "application/octet-stream", 1)
    with pytest.raises(cf.ChainFirstError) as excinfo:
        cf._fetch(commitment, store)
    assert excinfo.value.code == expected_code


@pytest.mark.parametrize(
    "error_type,expected_outcome",
    [
        (pub.ObjectNotFoundError, "BACKLOG"),
        (pub.TransportUnavailableError, "BACKLOG"),
        (pub.ReadBackMismatchError, "FAIL"),
        (pub.AvailabilityError, "FAIL"),
    ],
)
def test_exact_parent_resolution_does_not_call_transport_invalid(error_type, expected_outcome):
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures", "e184-cas")
    report_root = "8471202b8a272a1326170d3a7299ec418a03c2b57a0229a562e97ffbf908d83c"
    artifact_root = "5ba4435ff46e73e4ff1dc568e96c11bed44369e0db98a3fe21e6cba7a63ed60a"
    parent_root = "79da014ab4153c1331657f4a5c04bbc69384bf2626d509ac83e71aa578f5a2f6"
    with open(os.path.join(fixtures, report_root), encoding="utf-8") as handle:
        report = json.load(handle)
    with open(os.path.join(fixtures, artifact_root), encoding="utf-8") as handle:
        artifact = json.load(handle)
    store = _FailingRootStore(pub.FilesystemCAS(fixtures), parent_root, error_type)
    execution, block = cli._resolve_incumbent_execution(
        report, artifact, store=store)
    assert execution is None
    assert block["outcome"] == expected_outcome
