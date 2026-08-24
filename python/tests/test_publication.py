# SPDX-License-Identifier: Apache-2.0
"""Cut V5-C — ARTIFACT AVAILABILITY: publish, fetch back, rehash, fail closed.

The property under test is narrow and load-bearing: a root in a signed receipt must name bytes a
third party can actually GET. Every test here attacks the "we just wrote it, it must be there"
assumption from a different angle — absence, mutation, re-encoding, and a store whose addressing
disagrees with ours.
"""
from __future__ import annotations

import os

import pytest

import frontier as fr
import publication as pub


class LyingStore(pub.InMemoryCAS):
    """A store that serves bytes other than the ones published. The single most important
    adversary for a read-back check: hashing the local copy would never notice it."""

    def __init__(self, replacement: bytes):
        super().__init__()
        self.replacement = replacement

    def get(self, root: str) -> bytes:
        super().get(root)                               # still raise on genuine absence
        return self.replacement


class AmnesiacStore(pub.InMemoryCAS):
    """A store that accepts a put and then serves nothing."""

    def put(self, root: str, data: bytes) -> None:
        fr.check_root(root, "root")                     # accepted, and dropped on the floor


class ReprettifyingStore(pub.InMemoryCAS):
    """A store that round-trips JSON through a pretty-printer: the bytes still DECODE to the same
    document, but they are no longer the canonical byte string the root names."""

    def get(self, root: str) -> bytes:
        import json
        return json.dumps(json.loads(super().get(root).decode("utf-8")), indent=2).encode("utf-8")


DOC = {"alpha": 1, "beta": ["x", "y"], "gamma": {"nested": "value"}}


# --------------------------------------------------------------------------- #
# hash rules
# --------------------------------------------------------------------------- #
def test_bytes_rule_is_sha256_over_the_exact_bytes():
    data = b"\x00\x01 arbitrary bundle bytes \xff"
    assert pub.root_of(data, pub.HASH_RULE_BYTES) == fr.sha256_hex(data)


def test_frontier_json_rule_is_the_v5a_canonical_rule():
    data = pub.encode(DOC, pub.HASH_RULE_FRONTIER_JSON)
    assert data == fr.canonical_bytes(DOC)
    assert pub.root_of(data, pub.HASH_RULE_FRONTIER_JSON) == fr.sha256_hex(fr.canonical_bytes(DOC))


def test_frontier_json_rule_rejects_floats_like_the_v5a_law_does():
    with pytest.raises(fr.CanonicalizationError):
        pub.encode({"cost": 1.5}, pub.HASH_RULE_FRONTIER_JSON)


def test_benchmark_json_rule_tolerates_floats_because_receipts_carry_them():
    """A signed receipt legitimately binds rounded floats. That object is ADDRESSED under this
    rule and referenced by root; it is never inlined into V5 canonical bytes."""
    body = {"composite": 71.5, "rendered_cost": 880.25}
    data = pub.encode(body, pub.HASH_RULE_BENCHMARK_JSON)
    assert pub.root_of(data, pub.HASH_RULE_BENCHMARK_JSON) == fr.sha256_hex(data)


def test_signed_manifest_body_rule_strips_the_two_attestation_fields():
    """This is ``coretex_memory.release.canonical_manifest_bytes`` — the rule a release root and
    a composition root ALREADY are, so V5 mints no new one."""
    doc = {"format": "benchmark-v2/g8-deployment-signed/v1", "operator_key_id": "k",
           "manifest_self_sha256": "whatever", "operator_signature": "whatever"}
    body = {"format": doc["format"], "operator_key_id": "k"}
    data = pub.encode(doc, pub.HASH_RULE_SIGNED_MANIFEST_BODY)
    assert pub.root_of(data, pub.HASH_RULE_SIGNED_MANIFEST_BODY) == \
        fr.sha256_hex(pub.benchmark_canonical_bytes(body))


def test_signed_manifest_root_ignores_the_self_hash_and_signature_values():
    a = {"format": "f", "x": 1, "manifest_self_sha256": "aa", "operator_signature": "bb"}
    b = {"format": "f", "x": 1, "manifest_self_sha256": "cc", "operator_signature": "dd"}
    assert pub.root_of(pub.encode(a, pub.HASH_RULE_SIGNED_MANIFEST_BODY),
                       pub.HASH_RULE_SIGNED_MANIFEST_BODY) == \
        pub.root_of(pub.encode(b, pub.HASH_RULE_SIGNED_MANIFEST_BODY),
                    pub.HASH_RULE_SIGNED_MANIFEST_BODY)


def test_non_canonical_json_bytes_are_refused_not_recanonicalized():
    """One root must address exactly ONE byte string (the parse_transition_bytes discipline)."""
    pretty = b'{\n  "alpha": 1\n}'
    with pytest.raises(pub.HashRuleError):
        pub.root_of(pretty, pub.HASH_RULE_FRONTIER_JSON)
    with pytest.raises(pub.HashRuleError):
        pub.root_of(pretty, pub.HASH_RULE_BENCHMARK_JSON)


def test_duplicate_json_keys_are_refused_by_the_store_layer_too():
    with pytest.raises(pub.HashRuleError):
        pub.root_of(b'{"a":1,"a":2}', pub.HASH_RULE_FRONTIER_JSON)


def test_unknown_hash_rule_is_refused():
    with pytest.raises(pub.HashRuleError):
        pub.root_of(b"{}", "sha256-whatever")
    with pytest.raises(pub.HashRuleError):
        pub.encode({}, "sha256-whatever")


def test_non_utf8_bytes_under_a_json_rule_fail_closed():
    with pytest.raises(pub.HashRuleError):
        pub.root_of(b"\xff\xfe", pub.HASH_RULE_FRONTIER_JSON)


# --------------------------------------------------------------------------- #
# publish + read back
# --------------------------------------------------------------------------- #
def test_publish_and_read_back_returns_the_root_and_the_object_is_fetchable():
    store = pub.InMemoryCAS()
    root = pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    assert root == fr.sha256_hex(fr.canonical_bytes(DOC))
    assert pub.fetch_json(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store) == DOC


def test_read_back_failure_absent_object_fails_closed():
    store = AmnesiacStore()
    with pytest.raises(pub.ObjectNotFoundError):
        pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)


def test_read_back_failure_store_returns_different_bytes_fails_closed():
    store = LyingStore(b'{"alpha":2}')
    with pytest.raises(pub.StoreIntegrityError):
        pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)


def test_read_back_failure_store_reencodes_the_bytes_fails_closed():
    """The document still decodes; the BYTES are no longer the ones the root names."""
    store = ReprettifyingStore()
    with pytest.raises(pub.StoreIntegrityError):
        pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)


def test_read_back_of_an_earlier_publication_rehashes_the_fetched_bytes():
    store = pub.InMemoryCAS()
    root = pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    assert pub.read_back(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store) == \
        fr.canonical_bytes(DOC)


def test_read_back_detects_content_that_no_longer_matches_its_root():
    store = pub.InMemoryCAS()
    root = pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    store._objects[root] = fr.canonical_bytes({"alpha": 2})       # surface corrupted after the fact
    with pytest.raises(pub.ReadBackMismatchError):
        pub.read_back(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)


def test_read_back_checks_the_recorded_byte_length():
    store = pub.InMemoryCAS()
    root = pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    with pytest.raises(pub.ReadBackMismatchError):
        pub.read_back(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store,
                      expected_bytes_len=1)


def test_publish_refuses_when_the_object_is_not_the_one_the_caller_expected():
    store = pub.InMemoryCAS()
    with pytest.raises(pub.ReadBackMismatchError):
        pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store,
                                  expected_root="9" * 64)


def test_missing_object_raises_object_not_found_not_a_false():
    store = pub.InMemoryCAS()
    with pytest.raises(pub.ObjectNotFoundError):
        pub.read_back("1" * 64, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)


# --------------------------------------------------------------------------- #
# the store is an interface
# --------------------------------------------------------------------------- #
def test_filesystem_cas_is_a_drop_in_for_the_in_memory_one(tmp_path):
    for store in (pub.InMemoryCAS(), pub.FilesystemCAS(str(tmp_path / "cas"))):
        root = pub.publish_and_read_back(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
        assert store.has(root)
        assert pub.read_back(root, hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                             store=store) == fr.canonical_bytes(DOC)


def test_filesystem_cas_names_files_by_root_and_refuses_path_traversal(tmp_path):
    store = pub.FilesystemCAS(str(tmp_path / "cas"))
    root = pub.publish_and_read_back(b"payload", hash_rule=pub.HASH_RULE_BYTES, store=store)
    assert os.path.exists(os.path.join(store.root_dir, root))
    with pytest.raises(fr.FrontierValueError):
        store.get("../../etc/passwd")


def test_abstract_store_is_an_interface_not_an_implementation():
    for method, args in (("put", ("0" * 64, b"")), ("get", ("0" * 64,)), ("has", ("0" * 64,))):
        with pytest.raises(NotImplementedError):
            getattr(pub.ContentStore(), method)(*args)


# --------------------------------------------------------------------------- #
# availability records
# --------------------------------------------------------------------------- #
def test_availability_item_is_a_closed_record():
    store = pub.InMemoryCAS()
    item = pub.publish_item(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    assert set(item) == set(pub.AVAILABILITY_ITEM_FIELDS)
    assert item["bytes"] == len(fr.canonical_bytes(DOC))


def test_availability_rejects_an_unknown_field():
    with pytest.raises(pub.AvailabilityError):
        pub.validate_availability({"x": {"bytes": 1, "hash_rule": pub.HASH_RULE_BYTES,
                                         "root": "0" * 64, "extra": 1}})


def test_availability_rejects_a_missing_field():
    with pytest.raises(pub.AvailabilityError):
        pub.validate_availability({"x": {"hash_rule": pub.HASH_RULE_BYTES, "root": "0" * 64}})


def test_verify_availability_reads_every_object_back():
    store = pub.InMemoryCAS()
    items = {"a": pub.publish_item(DOC, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store),
             "b": pub.publish_item(b"raw", hash_rule=pub.HASH_RULE_BYTES, store=store)}
    assert set(pub.verify_availability(items, store=store, required=("a", "b"))) == {"a", "b"}


def test_verify_availability_fails_closed_on_an_unpublished_object():
    store = pub.InMemoryCAS()
    items = {"a": pub.availability_item("3" * 64, pub.HASH_RULE_BYTES, 4)}
    with pytest.raises(pub.ObjectNotFoundError):
        pub.verify_availability(items, store=store)


def test_verify_availability_fails_closed_when_a_required_name_is_absent():
    """"The artifact did not mention it" must never be a way to avoid publishing it."""
    store = pub.InMemoryCAS()
    items = {"a": pub.publish_item(b"raw", hash_rule=pub.HASH_RULE_BYTES, store=store)}
    with pytest.raises(pub.AvailabilityError):
        pub.verify_availability(items, store=store, required=("a", "candidate_bundle"))
