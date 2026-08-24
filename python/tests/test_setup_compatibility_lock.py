# SPDX-License-Identifier: Apache-2.0
"""The compatibility lock, fetched from a PUBLIC surface and verified against its own address.

THE GAP THIS CLOSES. Descriptor-v3's ``coreVersionHash`` is the address of exactly one
``coretex.compatibility-lock/v1`` document, and until now a clean validator could not obtain it:
the coordinator's object route refused the rule, so ``setup`` finished without ever seeing the
lock and snapshot reproduction only worked on a host where somebody had seeded the document by
hand. A pin nobody can fetch is not a pin.

THREE THINGS ARE KEPT APART HERE, and the tests are organised by them.

* **TRANSPORT.** ``compatibility-lock-root`` is a rule a request may CARRY. It is not a rule
  ``root_of`` can compute, because the address is a domain-separated keccak of the canonical body
  with ``lock_root`` removed — not a sha256 of the served bytes. So it is accepted by
  ``check_hash_rule`` (you may ask for it) and refused by ``root_of``/``read_back`` (this side
  cannot verify it there), with the refusal naming the verifier that CAN.
* **VERIFICATION.** ``resolver_snapshot.fetch_compatibility_lock`` requires the served bytes to BE
  the canonical serialisation, then re-addresses the document and demands the recomputation, the
  document's own ``lock_root`` and the requested root all agree. The coordinator's envelope says
  ``verified: true``; that is a report about the server and is never read.
* **OUTCOME.** Bytes that cannot be reached are a soft BACKLOG (setup completes, exit 0, with a
  remedy). Bytes that arrive and contradict their address are a FAILURE. A surface that is down
  and a surface that is lying must never produce the same verdict.

The fixture is the LIVE lock. Its canonical bytes are DERIVED in-test from the checked-in
pretty-printed document rather than pasted, so the served byte string is reproduced by the same
grammar the chain commits to; the pretty-printed file itself is then the non-canonical control.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import urllib.error

import pytest

from coretex_validator import canonical as cn
from coretex_validator import law
from coretex_validator import pipeline as pl
from coretex_validator import publication as pub
from coretex_validator import resolver_snapshot as rs
from coretex_validator import setup as su

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures",
                       "compatibility-lock-v1.json")

#: The chain word of the live lock: keccak256 over the domain tag and the canonical body.
LIVE_LOCK_ROOT = "93eb7a00dad8c9e5cdf81187dac85191f7475273cb2bfda0e91843dd37a6902c"
#: The raw sha256 of the CANONICAL bytes the coordinator serves — a transport fact, not the root.
LIVE_LOCK_RAW_SHA256 = "0c106339b06110a8c37d97440861a6442f165461ab5e26d3ca0a30ebc50345f7"
LIVE_LOCK_BYTES = 2852

COORDINATOR = "https://coordinator.example"


def lock_document() -> dict:
    with open(FIXTURE, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def canonical_lock_bytes() -> bytes:
    """The exact byte string the public route serves — rebuilt under the frontier grammar."""
    return cn.canonical_bytes(lock_document())


def pretty_lock_bytes() -> bytes:
    """The same document, indented. Decodes identically; is NOT what the root addresses."""
    with open(FIXTURE, "rb") as handle:
        return handle.read()


# --------------------------------------------------------------------------- #
# a coordinator that serves the object route
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


class FakeCoordinator:
    """``GET /coretex/v5/object/<root>?hashRule=...``, in memory. No socket is ever opened.

    ``status`` forces one HTTP outcome for every request, which is how the old-image (400) and
    outage (503) cases are reproduced without pretending to know anything else about the server.
    """

    def __init__(self, objects=None, *, status=None) -> None:
        self.objects = dict(objects or {})
        self.status = status
        self.requests = []

    def install(self, monkeypatch) -> "FakeCoordinator":
        monkeypatch.setattr(pl.urllib.request, "urlopen", self)
        return self

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        url = request.full_url if hasattr(request, "full_url") else request
        if self.status is not None:
            raise urllib.error.HTTPError(url, self.status, "forced", {}, None)
        path, _, query = url.partition("?")
        if "hashRule=" not in query:
            # the real route refuses a request that names no rule
            raise urllib.error.HTTPError(url, 400, "hashRule required", {}, None)
        root = path.rsplit("/", 1)[-1]
        if root not in self.objects:
            raise urllib.error.HTTPError(url, 404, "artifact_not_published", {}, None)
        return _FakeResponse(self.objects[root])

    @property
    def urls(self):
        return [r.full_url if hasattr(r, "full_url") else r for r in self.requests]


@pytest.fixture()
def live_coordinator(monkeypatch):
    return FakeCoordinator({LIVE_LOCK_ROOT: canonical_lock_bytes()}).install(monkeypatch)


def coordinator_store() -> pub.ContentStore:
    return pl.UrlContentStore.for_coordinator(COORDINATOR)


# --------------------------------------------------------------------------- #
# 1. the fixture is the live document
# --------------------------------------------------------------------------- #
def test_the_fixture_is_the_live_lock_and_its_three_identities_are_distinct():
    """Root, canonical-bytes sha256 and file sha256 are three different numbers, on purpose."""
    canonical = canonical_lock_bytes()
    assert len(canonical) == LIVE_LOCK_BYTES
    assert hashlib.sha256(canonical).hexdigest() == LIVE_LOCK_RAW_SHA256
    assert rs.validate_compatibility_lock(
        lock_document(), expected_root="0x" + LIVE_LOCK_ROOT) == LIVE_LOCK_ROOT
    assert lock_document()["lock_root"] == LIVE_LOCK_ROOT
    # the pretty-printed file is a different byte string, and its sha256 addresses nothing
    assert pretty_lock_bytes() != canonical
    assert hashlib.sha256(pretty_lock_bytes()).hexdigest() != LIVE_LOCK_RAW_SHA256


# --------------------------------------------------------------------------- #
# 2. transport: askable, not root_of-able
# --------------------------------------------------------------------------- #
def test_the_lock_rule_is_a_transport_rule_and_not_an_addressing_rule():
    assert pub.check_hash_rule(pub.HASH_RULE_COMPATIBILITY_LOCK) == "compatibility-lock-root"
    assert pub.HASH_RULE_COMPATIBILITY_LOCK in pub.HASH_RULES
    assert pub.HASH_RULE_COMPATIBILITY_LOCK not in pub.ADDRESSABLE_HASH_RULES
    assert len(pub.HASH_RULES) == 5 and len(pub.ADDRESSABLE_HASH_RULES) == 4


@pytest.mark.parametrize("call", [
    lambda: pub.root_of(canonical_lock_bytes(), pub.HASH_RULE_COMPATIBILITY_LOCK),
    lambda: pub.encode(lock_document(), pub.HASH_RULE_COMPATIBILITY_LOCK),
    lambda: pub.read_back(LIVE_LOCK_ROOT, hash_rule=pub.HASH_RULE_COMPATIBILITY_LOCK,
                          store=pub.InMemoryCAS()),
    lambda: pub.fetch_json(LIVE_LOCK_ROOT, hash_rule=pub.HASH_RULE_COMPATIBILITY_LOCK,
                           store=pub.InMemoryCAS()),
    lambda: pub.availability_item(LIVE_LOCK_ROOT, pub.HASH_RULE_COMPATIBILITY_LOCK, 2852),
])
def test_the_generic_addressing_path_refuses_the_lock_rule_and_names_the_verifier(call):
    with pytest.raises(pub.HashRuleError) as excinfo:
        call()
    assert "fetch_compatibility_lock" in str(excinfo.value)


def test_read_back_never_reaches_the_store_with_the_lock_rule():
    """The refusal is a REFUSAL, not a fetch that later fails: no transport happens."""
    class Exploding(pub.ContentStore):
        def get(self, root):                                  # pragma: no cover - must not run
            raise AssertionError("read_back fetched under a rule it cannot verify")

        def get_for_rule(self, root, hash_rule):              # pragma: no cover - must not run
            raise AssertionError("read_back fetched under a rule it cannot verify")

    with pytest.raises(pub.HashRuleError):
        pub.read_back(LIVE_LOCK_ROOT, hash_rule=pub.HASH_RULE_COMPATIBILITY_LOCK,
                      store=Exploding())


def test_the_url_store_asks_the_public_object_route_for_the_lock(live_coordinator):
    store = coordinator_store()
    assert store.get_for_rule(LIVE_LOCK_ROOT, pub.HASH_RULE_COMPATIBILITY_LOCK) == \
        canonical_lock_bytes()
    assert live_coordinator.urls == [
        f"{COORDINATOR}/coretex/v5/object/{LIVE_LOCK_ROOT}?hashRule=compatibility-lock-root"]
    assert live_coordinator.requests[-1].get_header("Accept") == "application/octet-stream"


# --------------------------------------------------------------------------- #
# 3. verification: the dedicated fetch+verify path
# --------------------------------------------------------------------------- #
def test_fetching_the_lock_verifies_canonical_bytes_and_both_copies_of_the_root(
        live_coordinator):
    document, served = rs.fetch_compatibility_lock(
        "0x" + LIVE_LOCK_ROOT, store=coordinator_store())
    assert served == canonical_lock_bytes()
    assert document["format"] == "coretex.compatibility-lock/v1"
    assert document["lock_root"] == LIVE_LOCK_ROOT
    # the bare-root spelling is the same request
    again, _ = rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=coordinator_store())
    assert again == document


def test_the_fetch_asks_for_the_rule_rather_than_falling_back_to_a_ruleless_get():
    class RuleOnly(pub.ContentStore):
        def __init__(self) -> None:
            self.rules = []

        def get(self, root):
            raise AssertionError("the lock was fetched without carrying its rule")

        def get_for_rule(self, root, hash_rule):
            self.rules.append((root, hash_rule))
            return canonical_lock_bytes()

    store = RuleOnly()
    rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=store)
    assert store.rules == [(LIVE_LOCK_ROOT, "compatibility-lock-root")]


def test_a_locally_seeded_artifact_dir_still_serves_the_lock_offline(tmp_path):
    """FilesystemCAS.get_for_rule falls through to get — a seeded store keeps working."""
    store = pub.FilesystemCAS(str(tmp_path))
    store.put(LIVE_LOCK_ROOT, canonical_lock_bytes())
    document, served = rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=store)
    assert served == canonical_lock_bytes()
    assert document["lock_root"] == LIVE_LOCK_ROOT


def test_noncanonical_bytes_are_a_refutation_and_never_a_soft_retry(monkeypatch):
    """The pretty-printed document decodes to the right value and is still refused."""
    FakeCoordinator({LIVE_LOCK_ROOT: pretty_lock_bytes()}).install(monkeypatch)
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=coordinator_store())
    assert excinfo.value.code == "COMPATIBILITY_LOCK_NON_CANONICAL"
    assert not isinstance(excinfo.value, pub.PublicationUnavailableError)


def test_a_valid_lock_served_under_a_different_root_is_refused(monkeypatch):
    other = "ab" * 32
    FakeCoordinator({other: canonical_lock_bytes()}).install(monkeypatch)
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.fetch_compatibility_lock(other, store=coordinator_store())
    assert excinfo.value.code == "COMPATIBILITY_LOCK_ROOT_MISMATCH"


def test_a_malformed_lock_is_refused(monkeypatch):
    broken = dict(lock_document())
    broken["unvalidated_extension"] = True
    FakeCoordinator({LIVE_LOCK_ROOT: cn.canonical_bytes(broken)}).install(monkeypatch)
    with pytest.raises(rs.ReproductionError) as excinfo:
        rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=coordinator_store())
    assert excinfo.value.code == "COMPATIBILITY_LOCK_MALFORMED"


def test_an_absent_publication_stays_an_availability_fact(monkeypatch):
    FakeCoordinator({}).install(monkeypatch)
    with pytest.raises(pub.ObjectNotFoundError):
        rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=coordinator_store())


def test_the_descriptor_v3_reproduction_reads_the_lock_through_the_verified_fetch():
    """The v3 snapshot rebuild must not go back to a rule-less ``store.get``."""
    source = inspect.getsource(rs.reproduce_from_chain)
    assert "fetch_compatibility_lock(" in source
    assert "store.get(compatibility_lock_root)" not in source


# --------------------------------------------------------------------------- #
# 4. setup: fetch, cache, bind
# --------------------------------------------------------------------------- #
def test_setup_verifies_caches_and_reports_the_public_lock(live_coordinator, tmp_path):
    packages = str(tmp_path / "packages")
    block = su.bind_compatibility_lock(
        COORDINATOR, core_version_hash="0x" + LIVE_LOCK_ROOT, packages_dir=packages)
    assert block["verified"] is True
    assert block["root"] == LIVE_LOCK_ROOT
    assert block["rawSha256"] == LIVE_LOCK_RAW_SHA256
    assert block["bytes"] == LIVE_LOCK_BYTES
    # the canonical bytes are on disk, under the root's own name, so a later offline
    # reproduction on this host finds them without the coordinator
    cached = block["cachedAt"]
    assert os.path.isfile(cached) and os.path.basename(cached) == LIVE_LOCK_ROOT
    with open(cached, "rb") as handle:
        assert handle.read() == canonical_lock_bytes()
    assert os.path.dirname(cached) == su.default_artifacts_dir(packages)


def test_the_cached_lock_is_what_a_later_offline_reproduction_reads(live_coordinator, tmp_path):
    packages = str(tmp_path / "packages")
    su.bind_compatibility_lock(COORDINATOR, core_version_hash=LIVE_LOCK_ROOT,
                               packages_dir=packages)
    offline = pub.FilesystemCAS(su.default_artifacts_dir(packages))
    document, served = rs.fetch_compatibility_lock(LIVE_LOCK_ROOT, store=offline)
    assert served == canonical_lock_bytes() and document["lock_root"] == LIVE_LOCK_ROOT


@pytest.mark.parametrize("status", [404, 503])
def test_an_unreachable_publication_is_a_soft_unverified_outcome(monkeypatch, tmp_path, status):
    FakeCoordinator(status=status).install(monkeypatch)
    block = su.bind_compatibility_lock(
        COORDINATOR, core_version_hash=LIVE_LOCK_ROOT, packages_dir=str(tmp_path))
    assert block["verified"] is False
    assert block["root"] == LIVE_LOCK_ROOT
    assert "cachedAt" not in block
    assert str(status) in block["reason"] or "not published" in block["reason"]
    assert "coordinator" in block["remedy"].lower()


def test_a_coordinator_that_refuses_the_rule_names_the_upgrade(monkeypatch, tmp_path):
    """The old image 400s the rule. That is an availability fact about the SERVER."""
    FakeCoordinator(status=400).install(monkeypatch)
    block = su.bind_compatibility_lock(
        COORDINATOR, core_version_hash=LIVE_LOCK_ROOT, packages_dir=str(tmp_path))
    assert block["verified"] is False
    assert "400" in block["reason"]
    assert "Upgrade the coordinator" in block["remedy"]
    assert "compatibility-lock-root" in block["remedy"]


@pytest.mark.parametrize("served,code", [
    (pretty_lock_bytes(), "COMPATIBILITY_LOCK_NON_CANONICAL"),
    (b"{}", "COMPATIBILITY_LOCK_MALFORMED"),
], ids=["non-canonical", "malformed"])
def test_bytes_that_contradict_their_address_fail_setup_loudly(monkeypatch, tmp_path, served,
                                                               code):
    FakeCoordinator({LIVE_LOCK_ROOT: served}).install(monkeypatch)
    with pytest.raises(rs.ReproductionError) as excinfo:
        su.bind_compatibility_lock(COORDINATOR, core_version_hash=LIVE_LOCK_ROOT,
                                   packages_dir=str(tmp_path))
    assert excinfo.value.code == code
    assert not os.path.isdir(su.default_artifacts_dir(str(tmp_path)))


def test_a_lock_served_under_the_wrong_root_fails_setup_loudly(monkeypatch, tmp_path):
    FakeCoordinator({"cd" * 32: canonical_lock_bytes()}).install(monkeypatch)
    with pytest.raises(rs.ReproductionError) as excinfo:
        su.bind_compatibility_lock(COORDINATOR, core_version_hash="cd" * 32,
                                   packages_dir=str(tmp_path))
    assert excinfo.value.code == "COMPATIBILITY_LOCK_ROOT_MISMATCH"


# --------------------------------------------------------------------------- #
# 5. the receipt binding
# --------------------------------------------------------------------------- #
def _installed_law(tmp_path):
    from test_law_sync import build_publication, write_set

    root, manifest_bytes, objects = build_publication()
    mirror = write_set(str(tmp_path / "mirror"), root, manifest_bytes, objects)
    cache_dir = str(tmp_path / "law-cache")
    law.sync_law(root, mirror=mirror, cache_dir=cache_dir)
    return root, cache_dir


def _active(root, cache_dir, **extra):
    return law.write_active_install(
        cache_dir=cache_dir, publication_root=root,
        kit_manifest_hash="1" * 64, miner_kit_sha256="2" * 64,
        miner_kit_filename="coretex-validator-miner-kit-" + "2" * 64 + ".tar",
        miner_kit_tree_sha256="3" * 64, **extra)


def test_the_active_install_receipt_records_which_lock_this_install_is_bound_to(tmp_path):
    root, cache_dir = _installed_law(tmp_path)
    document = _active(root, cache_dir, compatibility_lock={
        "bytes": LIVE_LOCK_BYTES, "root": LIVE_LOCK_ROOT, "sha256": LIVE_LOCK_RAW_SHA256})
    assert document["compatibility_lock"] == {
        "bytes": LIVE_LOCK_BYTES, "root": LIVE_LOCK_ROOT, "sha256": LIVE_LOCK_RAW_SHA256}
    reloaded = law.load_active_install(cache_dir=cache_dir)
    assert reloaded["compatibility_lock"]["root"] == LIVE_LOCK_ROOT


def test_a_receipt_written_before_the_lock_existed_still_loads(tmp_path):
    """The binding is ADDITIVE: an install from an older client is not invalidated by it."""
    root, cache_dir = _installed_law(tmp_path)
    document = _active(root, cache_dir)
    assert "compatibility_lock" not in document
    assert law.load_active_install(cache_dir=cache_dir) == document


def test_a_receipt_lock_binding_is_closed_and_range_checked(tmp_path):
    root, cache_dir = _installed_law(tmp_path)
    for broken in ({"root": LIVE_LOCK_ROOT, "sha256": LIVE_LOCK_RAW_SHA256},
                   {"bytes": LIVE_LOCK_BYTES, "root": LIVE_LOCK_ROOT,
                    "sha256": LIVE_LOCK_RAW_SHA256, "extra": 1},
                   {"bytes": -1, "root": LIVE_LOCK_ROOT, "sha256": LIVE_LOCK_RAW_SHA256},
                   {"bytes": LIVE_LOCK_BYTES, "root": "nope", "sha256": LIVE_LOCK_RAW_SHA256}):
        with pytest.raises(law.LawError):
            _active(root, cache_dir, compatibility_lock=broken)


# --------------------------------------------------------------------------- #
# 6. end to end through `setup.run`
# --------------------------------------------------------------------------- #
class _FakeRpc:
    def __init__(self, url, **kwargs) -> None:
        self.url = url

    def assert_chain(self, chain_id) -> None:
        return None

    def confirmed_head(self, depth) -> int:
        return 50_400_000


class _FakeViews:
    def __init__(self, rpc, deployment, *, block, has_context=True) -> None:
        self.block = block
        self.has_context = has_context

    def current_epoch(self) -> int:
        return 190

    def epoch_has_context(self, epoch) -> bool:
        return self.has_context

    def live_state_root(self, epoch) -> str:
        return "ab" * 32

    def transition_count(self, epoch) -> int:
        return 1

    def epoch_core_version_hash(self, epoch) -> str:
        return LIVE_LOCK_ROOT


class _FakeVerification:
    ok = True

    def as_dict(self):
        return {"ok": True, "block": 50_400_000, "contracts": {}, "wiring": {}, "failures": []}


class _FakeRelease:
    classification = "production"
    chain_id = 8453
    observation_block = None
    addresses = {"registry": "0x" + "11" * 20, "mining": "0x" + "22" * 20,
                 "verifier": "0x" + "33" * 20}
    deployment = None
    production_authority = True


def _install_chain(monkeypatch, *, has_context: bool = True) -> None:
    from coretex_validator import release as rel
    from coretex_validator import rpc as rpc_mod

    monkeypatch.setattr(rel, "discover", lambda location, **kw: _FakeRelease())
    monkeypatch.setattr(rel, "verify_deployment",
                        lambda release, rpc, *, block: _FakeVerification())
    monkeypatch.setattr(rpc_mod, "JsonRpc", _FakeRpc)
    monkeypatch.setattr(
        rpc_mod, "RigViews",
        lambda rpc, deployment, *, block: _FakeViews(rpc, deployment, block=block,
                                                     has_context=has_context))


def test_setup_run_reports_and_caches_the_lock(live_coordinator, monkeypatch, tmp_path):
    _install_chain(monkeypatch)
    report = su.run(rpc_url="https://rpc.example", coordinator=COORDINATOR,
                    packages_dir=str(tmp_path / "packages"),
                    skip_packages=True, skip_law=True, law_cache=str(tmp_path / "law"))
    assert report["ok"] is True
    assert report["lock"] == {
        "verified": True, "root": LIVE_LOCK_ROOT, "rawSha256": LIVE_LOCK_RAW_SHA256,
        "bytes": LIVE_LOCK_BYTES,
        "cachedAt": os.path.join(su.default_artifacts_dir(str(tmp_path / "packages")),
                                 LIVE_LOCK_ROOT)}
    assert os.path.isfile(report["lock"]["cachedAt"])


def test_setup_run_completes_with_an_unverified_lock_when_the_coordinator_is_old(
        monkeypatch, tmp_path):
    FakeCoordinator(status=400).install(monkeypatch)
    _install_chain(monkeypatch)
    report = su.run(rpc_url="https://rpc.example", coordinator=COORDINATOR,
                    packages_dir=str(tmp_path / "packages"),
                    skip_packages=True, skip_law=True, law_cache=str(tmp_path / "law"))
    assert report["ok"] is True                       # exit 0: nothing was DISPROVED
    assert report["lock"]["verified"] is False
    assert "Upgrade the coordinator" in report["lock"]["remedy"]


def test_setup_run_says_so_when_the_epoch_carries_no_context(monkeypatch, tmp_path):
    FakeCoordinator({}).install(monkeypatch)
    _install_chain(monkeypatch, has_context=False)
    report = su.run(rpc_url="https://rpc.example", coordinator=COORDINATOR,
                    packages_dir=str(tmp_path / "packages"),
                    skip_packages=True, skip_law=True, law_cache=str(tmp_path / "law"))
    assert report["ok"] is True
    assert report["lock"]["verified"] is False
    assert "context" in report["lock"]["reason"]
