# SPDX-License-Identifier: UNLICENSED
"""The RIG chain-first envelope's own refusals (§10).

WHAT THIS FILE IS FOR. ``validate_rig_chain_first`` is a THIN trust wrapper: the deterministic
replay is still the consensus implementation, and everything here happens BEFORE candidate code may
execute. So the thing worth testing in isolation is exactly the set of refusals that are unique to
the rig lane and that no other module makes:

  * the FOUR law pins the registry enforces, re-checked against pins a validator read for ITSELF.
    A snapshot that repeated the event's own roots back at it would agree with itself and catch
    nothing, so the substitution is injected into the SNAPSHOT, not into the event;
  * ``keccak256(LABEL ++ transitionBytes) == event.patchHash``. The rig advance carries NO
    ``transitionBytes`` — the edit is addressed by hash — so this single check is the entire reason
    fetching the edit is safe;
  * the rotated verifier -> registry pointer, which is the one link in the lane that is settable;
  * local coordinator state DEMOTED: a disagreement is a refusal, never a tie-break.

Every case stops before ``replay_advance`` is reached, so none of them needs a benchmark tree, a
sandbox or a signed receipt. The end-to-end path (real artifact, real replay) is proved by
``v5/e2e/rig_scenario.py``.
"""
from __future__ import annotations

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_V5_DIR = os.path.dirname(_HERE)
if _V5_DIR not in sys.path:
    sys.path.insert(0, _V5_DIR)

import frontier as fr                                                          # noqa: E402
import publication as pub                                                      # noqa: E402
from keccak256 import keccak256_hex                                            # noqa: E402
from validator import chain_first as cf                                        # noqa: E402
from validator import dispatch as dp                                           # noqa: E402

EPOCH = 9
REGISTRY = "0x00000000000000000000000000000000000000aa"
VERIFIER_REGISTRY = REGISTRY
RIG_ID = 2 ** 200 + 7

PARENT = "aa" * 32
NEW = "bb" * 32
CORPUS = "cc" * 32
FRONTIER = "dd" * 32
CORE = "ee" * 32
POLICY = "11" * 32
BASELINE = "55" * 32
SEED_COMMIT = "66" * 32

#: A well-formed canonical transition — the object whose bytes the advance's ``patchHash`` binds.
TRANSITION = fr.make_transition(
    target_profile="conv.pref.v1",
    expected_prior_release_root="ab" * 32,
    new_release_root="cd" * 32,
    resulting_composition_root="ef" * 32)
TRANSITION_BYTES = fr.canonical_bytes(TRANSITION)
PATCH = keccak256_hex(cf.RIG_PATCH_HASH_LABEL + TRANSITION_BYTES)


def _root(document) -> str:
    """The address the store must serve a document at — content addressing, not a label."""
    return fr.sha256_hex(fr.canonical_bytes(document))


CANDIDATE_MANIFEST = {"release_root": "manifest", "manifest_self_sha256": "unused"}
ARTIFACT = _root(CANDIDATE_MANIFEST)


def _pins(**overrides):
    values = {"corpus_root": CORPUS, "active_frontier_root": FRONTIER, "core_version_hash": CORE,
              "baseline_manifest_hash": BASELINE, "hidden_seed_commit": SEED_COMMIT,
              "work_policy_hash": POLICY, "entropy_commitment": SEED_COMMIT}
    values.update(overrides)
    return dp.RigEpochPins(epoch=EPOCH, **values)


def _event(**overrides):
    values = dict(
        epoch=EPOCH, transition_index=0, rig_id=RIG_ID, parent_state_root=PARENT,
        new_state_root=NEW, corpus_root=CORPUS, active_frontier_root=FRONTIER,
        core_version_hash=CORE, work_policy_hash=POLICY, eval_report_hash=REPORT,
        patch_hash=PATCH, artifact_hash=ARTIFACT,
        # Explicit, not left to the field default: these fixtures stand in for a DECODED log, and
        # a decoded log always knows its route (H-11). `None` means "reconstructed", which is a
        # different fact and has its own test below.
        via_legacy_route=False,
        provenance=dp.LogProvenance(address=REGISTRY, block_number=100, log_index=0))
    values.update(overrides)
    return dp.RigStateAdvanced(**values)


class _Store(pub.ContentStore):
    """A store whose contents are exactly what a test puts in it."""

    def __init__(self, objects):
        self.objects = dict(objects)

    def put(self, root, data):
        self.objects[root] = data

    def get(self, root):
        if root not in self.objects:
            raise pub.ObjectNotFoundError(f"no object published at {root}")
        return self.objects[root]

    def has(self, root):
        return root in self.objects


def _artifact_document(transition=TRANSITION, counter_root="14" * 32):
    return {
        "frontier": {"parent_frontier_root": PARENT, "new_frontier_root": NEW,
                     "transition": transition, "composition_root": "ef" * 32,
                     "benchmark_law_root": "12" * 32, "runtime_abi_root": "13" * 32},
        "candidate": {"release_root": ARTIFACT},
        "counter_resource_law_root": counter_root,
    }


ARTIFACT_DOCUMENT = _artifact_document()
REPORT = _root(ARTIFACT_DOCUMENT)


def _snapshot(**overrides):
    fields = dict(
        chain_id=31337, block_number=110, block_hash="0x" + "ab" * 32, finalized_block=110,
        epoch=EPOCH, live_state_root=NEW, transition_count=1, epoch_finalized=False,
        registry_address=REGISTRY, verifier_registry_address=VERIFIER_REGISTRY,
        pins=_pins(), counter_resource_law_root="14" * 32, scorer_root="15" * 32,
        deterministic_receipt_root="16" * 32, fresh_selection_root="17" * 32,
        supported_historical_laws=("12" * 32,),
        artifacts=(
            cf.ArtifactCommitment(kind="eval_artifact", root=REPORT,
                                  hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                  media_type="application/json",
                                  size=len(fr.canonical_bytes(ARTIFACT_DOCUMENT))),
            cf.ArtifactCommitment(kind="candidate_manifest", root=ARTIFACT,
                                  hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                                  media_type="application/json",
                                  size=len(fr.canonical_bytes(CANDIDATE_MANIFEST))),
        ))
    fields.update(overrides)
    snapshot = cf.RigCanonicalSnapshot(**fields)

    class _Source(cf.RigCanonicalChainSource):
        def snapshot(self, _event):
            return snapshot

    return _Source()


def _store_with(artifact_document=None):
    artifact_document = artifact_document or ARTIFACT_DOCUMENT
    return _Store({
        _root(artifact_document): fr.canonical_bytes(artifact_document),
        ARTIFACT: fr.canonical_bytes(CANDIDATE_MANIFEST),
    })


def _run(*, event=None, chain=None, store=None, **kwargs):
    return cf.validate_rig_chain_first(
        event or _event(), chain=chain or _snapshot(), store=store or _store_with(),
        manifest_verifier=lambda *_a: True,
        deterministic_receipt_verifier=lambda _r: True,
        rig_receipt=kwargs.pop("rig_receipt", {}), now=1_800_000_000, **kwargs)


# --------------------------------------------------------------------------- #
# The pins, read INDEPENDENTLY, are what a substituted registry cannot survive
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field", cf.RIG_ENFORCED_PIN_FIELDS)
def test_a_law_pin_the_registry_enforces_is_re_checked_against_an_independent_read(field):
    result = _run(chain=_snapshot(pins=_pins(**{field: "99" * 32})))
    assert result.ok is False
    assert result.code == f"RIG_{field.upper()}_SUBSTITUTION"
    assert "rig_chain_snapshot" in result.checks


@pytest.mark.parametrize("flag,route", [
    (False, "typed-submitStateAdvance"),
    (True, "legacy-0xa2d87e1d"),
    (None, "unobserved"),
])
def test_the_legacy_route_observable_survives_to_the_result_even_on_a_refusal(flag, route):
    """H-11: which route minted the advance is a property of the LOG.

    It therefore does not depend on whether the validator went on to admit the rest of it, and it
    is reported rather than enforced — the registry accepts both routes, so refusing a legacy-route
    advance here would be this lane inventing a consensus rule the chain does not have.
    """
    refused = _run(event=_event(via_legacy_route=flag),
                   chain=_snapshot(pins=_pins(corpus_root="99" * 32)))
    assert refused.ok is False, "this fixture is deliberately a refusal"
    assert refused.via_legacy_route is flag
    assert refused.route == route
    # ...and the "was it observed at all?" distinction reaches the check list.
    assert ("rig_route_provenance" in refused.checks) is (flag is not None)


def test_the_two_pins_the_advance_does_not_carry_are_not_pretended_to_be_checked():
    """``baselineManifestHash`` / ``hiddenSeedCommit`` ride on FINALIZATION, not on the advance.

    "Checking" them against an advance would be comparing a pin to a value the log never published,
    so the enforced set is deliberately four and not six.
    """
    assert set(cf.RIG_ENFORCED_PIN_FIELDS) == set(_pins().enforced_pins())
    assert "baseline_manifest_hash" not in cf.RIG_ENFORCED_PIN_FIELDS
    assert "hidden_seed_commit" not in cf.RIG_ENFORCED_PIN_FIELDS
    # ...and moving one of them does NOT refuse an advance, because nothing claimed it did.
    result = _run(chain=_snapshot(pins=_pins(baseline_manifest_hash="99" * 32)))
    assert result.code != "RIG_BASELINE_MANIFEST_HASH_SUBSTITUTION"


# --------------------------------------------------------------------------- #
# The patch-hash binding: the ONE check that makes fetching the edit by hash safe
# --------------------------------------------------------------------------- #
def test_the_patch_hash_binds_the_fetched_transition_to_the_confirmed_advance():
    other = fr.make_transition(
        target_profile="doc.tool.v1", expected_prior_release_root="ab" * 32,
        new_release_root="cd" * 32, resulting_composition_root="ef" * 32)
    swapped = _artifact_document(transition=other)
    result = _run(store=_Store({REPORT: fr.canonical_bytes(swapped),
                                ARTIFACT: fr.canonical_bytes(CANDIDATE_MANIFEST)}))
    assert result.ok is False
    # Content addressing catches it first — the substituted bytes no longer hash to REPORT — which
    # is the stronger refusal. The patch-hash check is the backstop for an artifact that DOES
    # self-address (a validator handed a different, well-formed artifact at a different root).
    assert result.code in ("ARTIFACT_INTEGRITY_FAILURE", "RIG_PATCH_HASH_MISMATCH")


def test_a_self_addressing_artifact_whose_transition_is_not_the_confirmed_patch_is_refused():
    other = fr.make_transition(
        target_profile="doc.tool.v1", expected_prior_release_root="ab" * 32,
        new_release_root="cd" * 32, resulting_composition_root="ef" * 32)
    swapped = _artifact_document(transition=other)
    root = _root(swapped)
    store = _Store({root: fr.canonical_bytes(swapped),
                    ARTIFACT: fr.canonical_bytes(CANDIDATE_MANIFEST)})
    snapshot = _snapshot(artifacts=(
        cf.ArtifactCommitment(kind="eval_artifact", root=root,
                              hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                              media_type="application/json",
                              size=len(fr.canonical_bytes(swapped))),
        cf.ArtifactCommitment(kind="candidate_manifest", root=ARTIFACT,
                              hash_rule=pub.HASH_RULE_FRONTIER_JSON,
                              media_type="application/json",
                              size=len(fr.canonical_bytes(CANDIDATE_MANIFEST))),
    ))
    result = _run(event=_event(eval_report_hash=root), chain=snapshot, store=store)
    assert result.ok is False
    assert result.code == "RIG_PATCH_HASH_MISMATCH"
    assert "the entire reason" in result.reason or "makes fetching the edit by hash safe" \
        in result.reason


def test_the_labelled_patch_rule_is_not_the_plain_one():
    """Q-10's two candidate readings differ for every input; there is no benign ambiguity."""
    assert cf._keccak_patch(TRANSITION_BYTES) != keccak256_hex(TRANSITION_BYTES)
    assert cf._keccak_patch(TRANSITION_BYTES) == PATCH


# --------------------------------------------------------------------------- #
# Rotation, adjacency and local-state demotion
# --------------------------------------------------------------------------- #
def test_a_rotated_verifier_registry_pointer_is_refused():
    result = _run(chain=_snapshot(verifier_registry_address="0x" + "11" * 20))
    assert result.ok is False
    assert result.code == "REGISTRY_SUBSTITUTION"


def test_the_epochs_LAST_confirmed_transition_must_be_the_registrys_live_root():
    result = _run(chain=_snapshot(live_state_root="99" * 32))
    assert result.ok is False
    assert result.code == "PARENT_ROOT_SUBSTITUTION"


def test_an_advance_the_chain_does_not_confirm_happened_is_refused():
    """`transitionCount` is monotone within an epoch, so an index at or beyond it is unconfirmed."""
    result = _run(chain=_snapshot(transition_count=0))
    assert result.ok is False
    assert result.code == "RIG_TRANSITION_UNCONFIRMED"


def test_a_HISTORICAL_advance_is_not_required_to_be_adjacent_to_the_current_head():
    """Transition 0 of a three-transition epoch is adjacent to nothing the registry now reports.

    Refusing it would make historical replay impossible, which is the one thing a public validator
    exists to do. The property that holds for head AND history is the transition INDEX.
    """
    result = _run(chain=_snapshot(transition_count=3, live_state_root="77" * 32))
    assert result.code not in ("PARENT_ROOT_SUBSTITUTION", "RIG_TRANSITION_UNCONFIRMED")
    assert "rig_head_or_history" in result.checks


def test_a_wrong_epoch_snapshot_is_refused():
    result = _run(chain=_snapshot(epoch=EPOCH + 1))
    assert result.ok is False
    assert result.code == "WRONG_EPOCH"


@pytest.mark.parametrize("local", [
    {"epoch": EPOCH + 3},
    {"state_root": "99" * 32},
    {"transition_count": 99},
    {"epoch_finalized": True},
])
def test_local_coordinator_state_is_demoted_never_a_tie_break(local):
    result = _run(local_state=local)
    assert result.ok is False
    assert result.code == "CHAIN_DATABASE_DISAGREEMENT"


def test_agreeing_local_state_is_not_a_refusal():
    """Demotion is not suspicion: a local row that AGREES simply adds nothing."""
    result = _run(local_state={"epoch": EPOCH, "state_root": NEW, "transition_count": 1,
                               "epoch_finalized": False})
    assert result.code != "CHAIN_DATABASE_DISAGREEMENT"


# --------------------------------------------------------------------------- #
# Artifact availability
# --------------------------------------------------------------------------- #
def test_an_unpublished_eval_artifact_is_MISSING_and_never_a_pass():
    result = _run(store=_Store({ARTIFACT: fr.canonical_bytes({"release_root": ARTIFACT})}))
    assert result.ok is False
    assert result.code == "MISSING_ARTIFACT"


def test_a_counter_law_the_policy_does_not_expect_is_refused():
    """The rig registry pins NO counter-resource law, so the expectation is operator policy."""
    result = _run(chain=_snapshot(counter_resource_law_root="98" * 32))
    assert result.ok is False
    assert result.code == "COUNTER_PACKAGE_SUBSTITUTION"
    assert "the rig registry pins no counter-resource law" in result.reason.lower()


# --------------------------------------------------------------------------- #
# One value, two spellings — the lane boundary, not a substitution
# --------------------------------------------------------------------------- #
def _rig_receipt(**overrides):
    """A signed rig receipt as the COORDINATOR renders it: roots `0x`-prefixed, uints as strings."""
    receipt = {
        "epochId": EPOCH,
        "rigId": str(RIG_ID),
        "parentStateRoot": f"0x{PARENT}",
        "newStateRoot": f"0x{NEW}",
        "corpusRoot": f"0x{CORPUS}",
        "activeFrontierRoot": f"0x{FRONTIER}",
        "coreVersionHash": f"0x{CORE}",
        "workPolicyHash": f"0x{POLICY}",
        "evalReportHash": f"0x{REPORT}",
        "patchHash": f"0x{PATCH}",
        "artifactHash": f"0x{ARTIFACT}",
        "outcome": 2,
        "stateWordCount": 1,
        "issuedAt": 1_800_000_000,
        "expiresAt": 1_800_000_600,
    }
    receipt.update(overrides)
    return receipt


def test_a_receipt_spelling_roots_with_0x_binds_to_a_log_that_spells_them_bare():
    """A decoded log renders roots BARE; the signed envelope renders them `0x`-prefixed.

    They are the same 32 bytes. Comparing them literally rejected a receipt that bound exactly what
    the chain confirmed — the Docker rehearsal stopped on it with
    `RIG_PARENTSTATEROOT_SUBSTITUTION` quoting two identical hex strings.
    """
    report = cf.verify_rig_receipt_bindings(
        _rig_receipt(), event=_event(), now=1_800_000_100, max_ttl=3600)
    assert "rig_event_bindings" in report["checks"]


def test_a_genuinely_substituted_root_still_fails_whichever_spelling_it_uses():
    for spelling in (f"0x{'99' * 32}", "99" * 32):
        with pytest.raises(cf.ChainFirstError) as caught:
            cf.verify_rig_receipt_bindings(
                _rig_receipt(newStateRoot=spelling), event=_event(),
                now=1_800_000_100, max_ttl=3600)
        assert caught.value.code == "RIG_NEWSTATEROOT_SUBSTITUTION"


def test_normalisation_only_touches_values_that_are_roots_on_BOTH_sides():
    assert cf._same_root_spelling(f"0x{PARENT}", PARENT) == PARENT
    assert cf._same_root_spelling(PARENT.upper(), PARENT) == PARENT
    # Not root-shaped: compared verbatim, so a short or non-hex value cannot be coerced into a match.
    assert cf._same_root_spelling("not-a-root", PARENT) == "not-a-root"
    assert cf._same_root_spelling("0x1234", PARENT) == "0x1234"
