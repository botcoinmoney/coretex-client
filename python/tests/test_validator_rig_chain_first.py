# SPDX-License-Identifier: UNLICENSED
"""The RIG chain-first envelope's own refusals (§10).

WHAT THIS FILE IS FOR. ``validate_rig_chain_first`` is a THIN trust wrapper: the deterministic
replay is still the consensus implementation, and everything here happens BEFORE candidate code may
execute. So the thing worth testing in isolation is exactly the set of refusals that are unique to
the rig lane and that no other module makes:

  * the THREE law pins the registry enforces, re-checked against pins a validator read for ITSELF.
    A snapshot that repeated the event's own roots back at it would agree with itself and catch
    nothing, so the substitution is injected into the SNAPSHOT, not into the event;
  * ``keccak256(LABEL ++ compactPatchBytes) == event.patchHash`` over the 97-byte TRANSITION
    DESCRIPTOR, followed by the descriptor's own decode. The rig advance carries no edit — it is
    addressed by hash — so this is the entire reason fetching the edit is safe. The preimage is the
    descriptor and NOT the canonical-JSON transition object (review M-9): the label and the
    preimage are one rule, and migrating either alone yields a check that can never pass;
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
EPOCH_CONTEXT = "cc" * 32
CORE = "ee" * 32
POLICY = "11" * 32
BASELINE = "55" * 32
SEED_COMMIT = "66" * 32

#: A well-formed canonical transition — the edit the eval artifact carries and replay consumes.
#: It is NOT what ``patchHash`` binds; see ``DESCRIPTOR`` below.
TRANSITION = fr.make_transition(
    target_profile="conv.pref.v1",
    expected_prior_release_root="ab" * 32,
    new_release_root="cd" * 32,
    resulting_composition_root="ef" * 32)
TRANSITION_BYTES = fr.canonical_bytes(TRANSITION)

#: THE 97-BYTE TRANSITION DESCRIPTOR — the bytes ``patchHash`` actually binds under
#: ``coretex.transition-descriptor/v3``: version(1) ‖ patchArtifactHash(32) ‖
#: parentStateRoot(32) ‖ newStateRoot(32).
#:
#: Built here from raw bytes rather than through ``rig_events.encode_transition_descriptor`` on
#: purpose: this file is the negative-control suite for the envelope, and a fixture produced by the
#: same module the envelope decodes with would agree with itself no matter what either of them did.
PATCH_ARTIFACT = "7e" * 32
DESCRIPTOR = (bytes([0x21]) + bytes.fromhex(PATCH_ARTIFACT) + bytes.fromhex(PARENT)
              + bytes.fromhex(NEW))
assert len(DESCRIPTOR) == 97
#: ``keccak256(LABEL ‖ THE DESCRIPTOR)``. It was ``keccak256(LABEL ‖ TRANSITION_BYTES)`` — the
#: right label on the wrong preimage, a value no genuine v2 advance can ever carry (review M-9).
PATCH = keccak256_hex(cf.RIG_PATCH_HASH_LABEL + DESCRIPTOR)


def _root(document) -> str:
    """The address the store must serve a document at — content addressing, not a label."""
    return fr.sha256_hex(fr.canonical_bytes(document))


CANDIDATE_MANIFEST = {"release_root": "manifest", "manifest_self_sha256": "unused"}
ARTIFACT = _root(CANDIDATE_MANIFEST)


def _pins(**overrides):
    values = {"epoch_context_root": EPOCH_CONTEXT, "core_version_hash": CORE,
              "baseline_manifest_hash": BASELINE, "hidden_seed_commit": SEED_COMMIT,
              "work_policy_hash": POLICY, "entropy_commitment": SEED_COMMIT}
    values.update(overrides)
    return dp.RigEpochPins(epoch=EPOCH, **values)


def _event(**overrides):
    values = dict(
        epoch=EPOCH, transition_index=0, rig_id=RIG_ID, parent_state_root=PARENT,
        new_state_root=NEW, epoch_context_root=EPOCH_CONTEXT,
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
    # The staged event shape carries no `compactPatchBytes`, so the descriptor is handed in beside
    # it. `setdefault`, not a positional default: a test that passes `compact_patch_bytes=None`
    # explicitly is testing the absent-descriptor refusal and must keep its None.
    kwargs.setdefault("compact_patch_bytes", DESCRIPTOR)
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
                   chain=_snapshot(pins=_pins(epoch_context_root="99" * 32)))
    assert refused.ok is False, "this fixture is deliberately a refusal"
    assert refused.via_legacy_route is flag
    assert refused.route == route
    # ...and the "was it observed at all?" distinction reaches the check list.
    assert ("rig_route_provenance" in refused.checks) is (flag is not None)


def test_the_two_pins_the_advance_does_not_carry_are_not_pretended_to_be_checked():
    """``baselineManifestHash`` / ``hiddenSeedCommit`` ride on FINALIZATION, not on the advance.

    "Checking" them against an advance would be comparing a pin to a value the log never published,
    so the enforced set is deliberately three and not five.
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
def test_a_substituted_eval_artifact_never_reaches_the_descriptor_check():
    other = fr.make_transition(
        target_profile="doc.tool.v1", expected_prior_release_root="ab" * 32,
        new_release_root="cd" * 32, resulting_composition_root="ef" * 32)
    swapped = _artifact_document(transition=other)
    result = _run(store=_Store({REPORT: fr.canonical_bytes(swapped),
                                ARTIFACT: fr.canonical_bytes(CANDIDATE_MANIFEST)}))
    assert result.ok is False
    # Content addressing catches it — the substituted bytes no longer hash to REPORT. Under v2 the
    # descriptor commits `patchArtifactHash`, `parentStateRoot`, and `newStateRoot`, NOT
    # the eval artifact's transition object, so the descriptor check is no longer the backstop for
    # a swapped transition and must not be advertised as one.
    assert result.code == "ARTIFACT_INTEGRITY_FAILURE"


def test_a_descriptor_that_is_not_the_confirmed_patch_hash_preimage_is_refused():
    """The backstop: a validator handed a well-formed descriptor that is not THIS advance's."""
    other = (bytes([0x21]) + bytes.fromhex("8f" * 32) + bytes.fromhex(PARENT)
             + bytes.fromhex(NEW))
    result = _run(compact_patch_bytes=other)
    assert result.ok is False
    assert result.code == "RIG_PATCH_HASH_MISMATCH"
    assert "makes fetching the edit by hash safe" in result.reason


def test_an_absent_descriptor_is_a_TYPED_REFUSAL_never_a_skipped_check():
    """M-9. The staged event carries no ``compactPatchBytes``; a caller that supplies none is
    refused BY NAME rather than checked against a preimage the v3 rule does not name."""
    result = _run(compact_patch_bytes=None)
    assert result.ok is False
    assert result.code == "RIG_TRANSITION_DESCRIPTOR_UNAVAILABLE"
    assert "97" in result.reason


@pytest.mark.parametrize("field,offset,code", [
    ("parentStateRoot", 33, "DESCRIPTOR_PARENT_MISMATCH"),
    ("newStateRoot", 65, "DESCRIPTOR_NEW_ROOT_MISMATCH"),
])
def test_the_descriptor_is_DECODED_not_merely_hashed(field, offset, code):
    """The layout is enforced too, so a descriptor whose roots disagree with the confirmed advance
    is refused with the field's own code — the binding the retired word patch could not express
    for ``newStateRoot`` at all."""
    mutated = bytearray(DESCRIPTOR)
    mutated[offset:offset + 32] = bytes.fromhex("99" * 32)
    mutated = bytes(mutated)
    # Its own patchHash, so the hash rule agrees and the DECODE is the only thing left to refuse.
    result = _run(event=_event(patch_hash=keccak256_hex(cf.RIG_PATCH_HASH_LABEL + mutated)),
                  compact_patch_bytes=mutated)
    assert result.ok is False
    assert result.code == code, f"{field} must refuse with its own code"


def test_a_descriptor_of_the_wrong_LENGTH_is_refused_before_anything_else():
    short = DESCRIPTOR[:-1]
    result = _run(event=_event(patch_hash=keccak256_hex(cf.RIG_PATCH_HASH_LABEL + short)),
                  compact_patch_bytes=short)
    assert result.ok is False
    assert result.code == "DESCRIPTOR_LENGTH_INVALID"


def test_the_labelled_patch_rule_is_not_the_plain_one():
    """Q-10's two candidate readings differ for every input; there is no benign ambiguity."""
    assert cf._keccak_patch(DESCRIPTOR) != keccak256_hex(DESCRIPTOR)
    assert cf._keccak_patch(DESCRIPTOR) == PATCH


def test_the_preimage_is_the_DESCRIPTOR_and_not_the_canonical_transition():
    """M-9, pinned: the two preimages give different values, so a check over the transition object
    can never pass on a genuine v3 advance no matter how correct its LABEL is."""
    assert cf._keccak_patch(TRANSITION_BYTES) != PATCH
    assert cf._keccak_patch(DESCRIPTOR) == PATCH


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
        "epochContextRoot": f"0x{EPOCH_CONTEXT}",
        "coreVersionHash": f"0x{CORE}",
        "workPolicyHash": f"0x{POLICY}",
        "evalReportHash": f"0x{REPORT}",
        "patchHash": f"0x{PATCH}",
        "artifactHash": f"0x{ARTIFACT}",
        "outcome": 2,
        "transitionFormatVersion": 0x21,
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


def test_transition_format_version_must_equal_the_descriptor_version_exactly():
    # coretex.transition-descriptor/v3: transitionFormatVersion is no longer a count with a
    # lower bound (the retired stateWordCount was "at least 1"); it is the FIXED zero-extension of
    # the descriptor's version byte, so anything else — including a plausible-looking small
    # integer — is refused.
    for bad in (0, 1, 4, 0x20, 0xff):
        with pytest.raises(cf.ChainFirstError) as caught:
            cf.verify_rig_receipt_bindings(
                _rig_receipt(transitionFormatVersion=bad), event=_event(),
                now=1_800_000_100, max_ttl=3600)
        assert caught.value.code == "RIG_TRANSITION_FORMAT_VERSION_INVALID"


def test_normalisation_only_touches_values_that_are_roots_on_BOTH_sides():
    assert cf._same_root_spelling(f"0x{PARENT}", PARENT) == PARENT
    assert cf._same_root_spelling(PARENT.upper(), PARENT) == PARENT
    # Not root-shaped: compared verbatim, so a short or non-hex value cannot be coerced into a match.
    assert cf._same_root_spelling("not-a-root", PARENT) == "not-a-root"
    assert cf._same_root_spelling("0x1234", PARENT) == "0x1234"
