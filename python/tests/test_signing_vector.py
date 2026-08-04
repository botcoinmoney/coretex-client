# SPDX-License-Identifier: Apache-2.0
"""The signing digest, asserted against a COMMITTED VECTOR rather than against ourselves.

This file reads `fixtures/signing-vector.json` — a copy of the resolver lane's own fixture — and
checks this package's construction against it. That indirection is the whole value: a test that
recomputed the digest using the same constants it is testing would pass whatever the domain tag
said, and a tag change would silently re-key every signature both lanes can verify. Reading a
committed vector makes such a change fail loudly, on both sides, at the same moment.

The vector also carries the digest under the SUPERSEDED tag, deliberately. It is not dead weight:
it is what lets a stale signature be diagnosed rather than merely rejected, and it is the evidence
that the flip happened before any real snapshot existed.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from coretex_validator import snapshot as snap
from coretex_validator.keccak256 import keccak256

FIXTURE_PATH = pathlib.Path(__file__).resolve().parent / "fixtures" / "signing-vector.json"
#: Recorded in `fixtures/PROVENANCE.md`. Pinned here so a silent edit to the copy is caught.
FIXTURE_SHA256 = "e19b0f513b4ebeb66bdd698ed95a6cd72eb38cac8bd990d11b071d76d332ba1c"


@pytest.fixture(scope="module")
def vector():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_the_fixture_has_not_drifted_from_the_copy_that_was_reviewed():
    observed = hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()
    assert observed == FIXTURE_SHA256, (
        "the vendored signing vector changed. If the resolver lane re-issued it, re-copy it AND "
        "update fixtures/PROVENANCE.md — the point of the pin is that this cannot happen quietly")


def test_the_domain_tag_matches_the_published_schema(vector):
    assert snap.SNAPSHOT_SIGNING_DOMAIN.hex() == vector["signing_domain_hex"][2:]
    assert snap.SUPERSEDED_SIGNING_DOMAIN.hex() == vector["superseded_domain_hex"][2:]
    # The tag names the PUBLISHED schema, which is the resolver's, not this package's own id.
    assert b"coretex.rig-state.resolver-snapshot/v1" in snap.SNAPSHOT_SIGNING_DOMAIN
    assert snap.SNAPSHOT_SIGNING_DOMAIN.startswith(b"\x19")
    assert snap.SNAPSHOT_SIGNING_DOMAIN.endswith(b"\n")


def test_the_canonical_bytes_of_the_vector_payload_reproduce(vector):
    produced = snap.canonical_bytes(vector["payload"])
    assert produced == bytes.fromhex(vector["canonical_bytes_hex"][2:])
    assert produced.decode("utf-8") == vector["canonical_bytes_utf8"]
    assert len(produced) == vector["canonical_byte_length"]


def test_the_signing_digest_matches_the_vector(vector):
    assert "0x" + snap.signing_digest(vector["payload"]).hex() == vector["signing_digest"]


def test_the_superseded_digest_matches_too_so_the_flip_stays_auditable(vector):
    assert ("0x" + snap.superseded_signing_digest(vector["payload"]).hex()
            == vector["superseded_signing_digest"])
    # The two must differ, or the flip would have been a no-op and the audit trail meaningless.
    assert vector["signing_digest"] != vector["superseded_signing_digest"]


def test_payload_sha256_and_signing_digest_are_DIFFERENT_values(vector):
    """The two published fields are not two spellings of one thing, and conflating them is a hole.

    `payload_sha256` is IDENTITY: what a snapshot is addressed by, compared by, and reproduced
    against. `signing_digest` is what the signature actually COVERS. An artifact naming a correct
    `payload_sha256` alongside a wrong `signing_digest` would otherwise satisfy the identity check
    and then be verified against a digest nobody computed — the "the hash matched" substitution
    the whole design exists to prevent.
    """
    assert snap.payload_hash(vector["payload"]) == vector["payload_sha256"]
    assert vector["payload_sha256"] != vector["signing_digest"].removeprefix("0x")
    # And the digest is NOT a re-hash of the identity: it covers the domain tag too.
    assert snap.signing_digest(vector["payload"]) != keccak256(
        snap.canonical_bytes(vector["payload"]))


def test_the_digest_is_structurally_unusable_as_a_contract_signature(vector):
    """EIP-191 0x19, but none of the envelopes a contract accepts."""
    tag = snap.SNAPSHOT_SIGNING_DOMAIN
    assert not tag.startswith(b"\x19\x01")                       # not EIP-712
    assert not tag.startswith(b"\x19Ethereum Signed Message:\n")  # not personal_sign
