# SPDX-License-Identifier: Apache-2.0
"""Rule-carrying object transport, over REAL epoch-184 production bytes.

THE PROBLEM. A content address is only half a contract; the other half is the HASH RULE the
address was committed under. Two of the four rules address bytes that are not the bytes on the
wire (``sha256-signed-manifest-body``), and one addresses a document that legitimately carries
FLOATS (``sha256-benchmark-canonical-json`` — a signed receipt binds rounded measurements). A
publication surface that does not know which rule a caller committed to cannot decide how to
serve the object, and the coordinator's public route says so out loud: it refuses a request that
names no rule.

So the rule travels WITH the request (``?hashRule=``) and the transport is raw
(``Accept: application/octet-stream``). What does NOT travel is trust: the server may report
``transportVerified`` and ``canonicalVerification: "client_required"`` all it likes; this client
recomputes the root from the bytes that arrived, under the rule it committed to, and a
disagreement is a REFUTATION rather than an outage. That is why the flipped-byte control below
asserts :class:`ReadBackMismatchError` and specifically NOT :class:`ObjectNotFoundError`: the
first is permanent and provable, the second is a retryable availability fact, and collapsing them
would let a substituting mirror hide in a backlog.

The fixtures are the nine content-addressed objects of the LIVE epoch-184 advance, copied
verbatim from production. The inner evaluation report (``8471202b…``, 29437 bytes, 128 float
tokens) is the exact float-bearing case: it addresses under the benchmark rule and NOT under the
float-refusing frontier rule, and its raw sha256 happens to equal its root — which is precisely
why a server may serve it raw, and precisely why raw-sha agreement must never be mistaken for
canonical verification.
"""
from __future__ import annotations

import json
import os

import pytest

from coretex_validator import pipeline as pl
from coretex_validator import publication as pub

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "e184-cas")

#: The float-bearing inner evaluation report of the epoch-184 advance, committed under the
#: benchmark rule. 29437 bytes, 128 float tokens.
E184_EVAL_REPORT = "8471202b8a272a1326170d3a7299ec418a03c2b57a0229a562e97ffbf908d83c"
#: The outer V5 eval artifact of the same advance, committed under the frontier rule.
E184_EVAL_ARTIFACT = "5ba4435ff46e73e4ff1dc568e96c11bed44369e0db98a3fe21e6cba7a63ed60a"
#: The candidate bundle: published bytes carry the self-hash and signature the BODY excludes, so
#: its raw sha256 is deliberately NOT its root.
E184_CANDIDATE_BUNDLE = "55cbb53387b8afe6b8d81a4768bbeecdd4912c856bb7ee6f128b0f9aaf6703c8"
#: The candidate adapter module: opaque bytes.
E184_ADAPTER_MODULE = "84d60a998ce357cb79e96d244856edf74e4074134c70c9dd0f358a2cfb098e5b"


def fixture_bytes(root: str) -> bytes:
    with open(os.path.join(FIXTURES, root), "rb") as fh:
        return fh.read()


@pytest.fixture()
def e184_store():
    """The published epoch-184 objects, served exactly as a third party would receive them."""
    return pub.FilesystemCAS(FIXTURES)


# --------------------------------------------------------------------------- #
# a fake http surface
# --------------------------------------------------------------------------- #
class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, *args):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Recorder:
    """Records every urlopen argument. No socket is ever opened."""

    def __init__(self, body: bytes = b"{}") -> None:
        self.body = body
        self.requests = []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        return _FakeResponse(self.body)

    @property
    def urls(self):
        return [r.full_url if hasattr(r, "full_url") else r for r in self.requests]

    def header(self, name: str):
        request = self.requests[-1]
        return request.get_header(name.capitalize()) if hasattr(request, "get_header") else None


# --------------------------------------------------------------------------- #
# the URL the rule travels in
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("hash_rule", list(pub.HASH_RULES))
def test_the_url_store_carries_the_committed_rule_as_a_query_parameter(monkeypatch, hash_rule):
    recorder = _Recorder()
    monkeypatch.setattr(pl.urllib.request, "urlopen", recorder)
    store = pl.UrlContentStore("https://cas.example/objects")
    store.get_for_rule("a" * 64, hash_rule)
    assert recorder.urls == [f"https://cas.example/objects/{'a' * 64}?hashRule={hash_rule}"]


def test_the_url_store_asks_for_raw_bytes_not_an_envelope(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(pl.urllib.request, "urlopen", recorder)
    store = pl.UrlContentStore("https://cas.example/objects")
    store.get_for_rule("b" * 64, pub.HASH_RULE_BENCHMARK_JSON)
    assert recorder.header("accept") == "application/octet-stream"


def test_for_coordinator_targets_the_public_object_route(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(pl.urllib.request, "urlopen", recorder)
    store = pl.UrlContentStore.for_coordinator("https://coordinator.example/")
    store.get_for_rule("c" * 64, pub.HASH_RULE_FRONTIER_JSON)
    assert recorder.urls == [
        "https://coordinator.example/coretex/v5/object/" + "c" * 64
        + "?hashRule=sha256-frontier-canonical-json"]


def test_plain_get_is_exactly_what_it_was(monkeypatch):
    """The rule-less route stays available and unchanged; this feature only ADDS a spelling."""
    recorder = _Recorder()
    monkeypatch.setattr(pl.urllib.request, "urlopen", recorder)
    store = pl.UrlContentStore("https://cas.example/objects")
    store.get("d" * 64)
    assert recorder.urls == ["https://cas.example/objects/" + "d" * 64]


def test_an_unknown_rule_never_reaches_the_wire(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(pl.urllib.request, "urlopen", recorder)
    store = pl.UrlContentStore("https://cas.example/objects")
    with pytest.raises(pub.HashRuleError):
        store.get_for_rule("e" * 64, "sha256-whatever-the-mirror-likes")
    assert recorder.requests == []


def test_a_404_from_the_rule_route_is_still_ABSENCE_not_corruption(monkeypatch):
    import urllib.error

    def boom(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 404, "gone", {}, None)

    monkeypatch.setattr(pl.urllib.request, "urlopen", boom)
    store = pl.UrlContentStore("https://cas.example/objects")
    with pytest.raises(pub.ObjectNotFoundError):
        store.get_for_rule("f" * 64, pub.HASH_RULE_BYTES)


# --------------------------------------------------------------------------- #
# the local stores answer the same question
# --------------------------------------------------------------------------- #
def test_a_store_whose_transport_does_not_vary_by_rule_answers_with_its_bytes(e184_store):
    memory = pub.InMemoryCAS()
    data = fixture_bytes(E184_EVAL_REPORT)
    memory.put(E184_EVAL_REPORT, data)
    assert memory.get_for_rule(E184_EVAL_REPORT, pub.HASH_RULE_BENCHMARK_JSON) == data
    assert e184_store.get_for_rule(E184_EVAL_REPORT, pub.HASH_RULE_BENCHMARK_JSON) == data


def test_the_store_contract_still_refuses_an_unknown_rule():
    memory = pub.InMemoryCAS()
    memory.put("a" * 64, b"{}")
    with pytest.raises(pub.HashRuleError):
        memory.get_for_rule("a" * 64, "sha256-something-else")


# --------------------------------------------------------------------------- #
# the REAL epoch-184 objects
# --------------------------------------------------------------------------- #
def test_the_live_float_bearing_report_round_trips_under_the_benchmark_rule(e184_store):
    """The exact FLOAT_NOT_REPRODUCIBLE case, verified locally rather than taken on trust."""
    data = pub.read_back(E184_EVAL_REPORT, hash_rule=pub.HASH_RULE_BENCHMARK_JSON,
                         store=e184_store)
    assert len(data) == 29437
    # it really does carry floats — which is why the frontier rule cannot address it
    text = data.decode("utf-8")
    assert sum(1 for token in text.replace(",", " ").replace(":", " ").split()
               if _is_float_token(token)) >= 100
    with pytest.raises(pub.HashRuleError):
        pub.root_of(data, pub.HASH_RULE_FRONTIER_JSON)
    # and the root is REPRODUCED from the bytes, under the committed rule
    assert pub.root_of(data, pub.HASH_RULE_BENCHMARK_JSON) == E184_EVAL_REPORT
    report = pub.fetch_json(E184_EVAL_REPORT, hash_rule=pub.HASH_RULE_BENCHMARK_JSON,
                            store=e184_store)
    assert report["format"] == "benchmark-v2/receipt/v1"
    assert report["profile_id"] == "doc.tool.v1"


def _is_float_token(token: str) -> bool:
    token = token.strip('"{}[]')
    if "." not in token:
        return False
    try:
        float(token)
    except ValueError:
        return False
    return True


def test_the_live_outer_eval_artifact_verifies_under_the_frontier_rule(e184_store):
    artifact = pub.fetch_json(E184_EVAL_ARTIFACT, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                             store=e184_store)
    assert artifact["frontier"]["new_frontier_root"] == (
        "ef080c11764616b17a307ecb3e7b017cbdc26ff69c9680aa56ff3f2792746bfa")
    # the outer artifact names the inner report under the benchmark rule, by root
    availability = artifact["availability"]
    assert availability["eval_report"] == {
        "bytes": 29437, "hash_rule": pub.HASH_RULE_BENCHMARK_JSON, "root": E184_EVAL_REPORT}


def test_the_live_signed_bundle_is_addressed_by_its_BODY_not_its_bytes(e184_store):
    """Raw-sha agreement is a TRANSPORT fact and nothing more: here it does not even hold."""
    import hashlib

    data = fixture_bytes(E184_CANDIDATE_BUNDLE)
    assert hashlib.sha256(data).hexdigest() != E184_CANDIDATE_BUNDLE
    assert pub.root_of(data, pub.HASH_RULE_SIGNED_MANIFEST_BODY) == E184_CANDIDATE_BUNDLE
    assert pub.read_back(E184_CANDIDATE_BUNDLE,
                         hash_rule=pub.HASH_RULE_SIGNED_MANIFEST_BODY, store=e184_store) == data


def test_one_flipped_byte_in_the_float_bearing_report_is_a_REFUTATION_not_a_backlog(tmp_path):
    """A substituted body must never be indistinguishable from an outage. Both are refused, but
    only one of them can be fixed by asking again, and this is not it."""
    data = fixture_bytes(E184_EVAL_REPORT)
    tampered = data.replace(b'"records":0', b'"records":1', 1)
    assert len(tampered) == len(data) and tampered != data
    # still canonical, still parseable — the ONLY thing wrong with it is that it is not the
    # document the chain committed to.
    assert pub.benchmark_canonical_bytes(json.loads(tampered.decode("utf-8"))) == tampered
    store = pub.FilesystemCAS(str(tmp_path))
    with open(os.path.join(str(tmp_path), E184_EVAL_REPORT), "wb") as fh:
        fh.write(tampered)
    with pytest.raises(pub.ReadBackMismatchError):
        pub.read_back(E184_EVAL_REPORT, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    # and emphatically NOT the retryable outcome
    try:
        pub.read_back(E184_EVAL_REPORT, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    except pub.PublicationError as exc:
        assert not isinstance(exc, pub.ObjectNotFoundError)


def test_the_opaque_module_bytes_are_addressed_raw(e184_store):
    data = pub.read_back(E184_ADAPTER_MODULE, hash_rule=pub.HASH_RULE_BYTES, store=e184_store)
    assert data.startswith(b"# SPDX-License-Identifier: Apache-2.0")


# --------------------------------------------------------------------------- #
# every validator-side fetch carries the rule
# --------------------------------------------------------------------------- #
class _RuleRecordingCAS(pub.InMemoryCAS):
    """An honest store that records which spelling each fetch used."""

    def __init__(self) -> None:
        super().__init__()
        self.rule_calls = []
        self.plain_calls = []

    def get(self, root: str) -> bytes:
        self.plain_calls.append(root)
        return super().get(root)

    def get_for_rule(self, root: str, hash_rule: str) -> bytes:
        self.rule_calls.append((root, hash_rule))
        return super().get_for_rule(root, hash_rule)


def test_read_back_and_fetch_json_route_through_the_rule_aware_spelling():
    store = _RuleRecordingCAS()
    data = fixture_bytes(E184_EVAL_REPORT)
    store.put(E184_EVAL_REPORT, data)
    pub.read_back(E184_EVAL_REPORT, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    pub.fetch_json(E184_EVAL_REPORT, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    assert store.rule_calls == [(E184_EVAL_REPORT, pub.HASH_RULE_BENCHMARK_JSON)] * 2


def test_a_full_advance_replay_asks_for_every_object_under_its_committed_rule():
    """The route is exercised end to end, not only at the seam: the receipt is committed under
    the benchmark rule and the manifests under the frontier rule, and replay must say so."""
    import validator_fixtures as vf

    store = _RuleRecordingCAS()
    scenario = vf.Scenario(store=store)
    result = scenario.replay(pins=scenario.resolver(reveal=True))
    assert str(result.outcome) in ("PASS", "BACKLOG", "FAIL")
    rules = dict((root, rule) for root, rule in store.rule_calls)
    assert rules[scenario.parent_root] == pub.HASH_RULE_FRONTIER_JSON
    assert rules[scenario.eval_report_hash] == pub.HASH_RULE_FRONTIER_JSON
    assert pub.HASH_RULE_BENCHMARK_JSON in set(rules.values())
