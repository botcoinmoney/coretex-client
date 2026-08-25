# SPDX-License-Identifier: Apache-2.0
"""The fixed-suite (v4) era, against a REAL minted artifact.

WHY THE FIXTURE IS A REAL ONE. Every check here could be made to pass on a synthesised artifact,
and several of them would then be checking the synthesiser. `v3-cas/` holds the objects a real
`eval.candidate.v2` job published — the artifact, the evaluation report it addresses, the parent
frontier manifest, the release and composition manifests, the counter-resource law and the
transition artifact — copied verbatim out of the evaluator's own content-addressed store. The one
object added beside them is the published bridge-vector document the artifact's determinism witness
names, which is what makes the stored parent vector provenance rather than a number.

The three suites the P9 checklist asks for are here: STRIPPED-SUITE REFUSAL, OFFLINE DETERMINISM
(two runs, identical hashes) and the era-aware `worldSeed` recomputation, plus the aggregate
resource non-regression the public law promised and the replayer did not enforce.
"""
from __future__ import annotations

import copy
import json
import os

import pytest

from coretex_validator import canonical_suite as cs
from coretex_validator import eval_artifact as ea
from coretex_validator import frontier as fr
from coretex_validator import publication as pub
from coretex_validator import replay as rp

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CAS = os.path.join(FIXTURES, "v3-cas")
BRIDGE = os.path.join(FIXTURES, "bridge-vector.event.schema.genesis.json")

#: RE-SEEDED at the remediation-round-2 re-seal. The previous fixture
#: (`b56b8d24…` / report `869feaf4…` / witness source `60dc89e2…`) was minted under the FIRST
#: fixed-suite seal and is superseded: the law cut that followed bound `logical_durable_storage_
#: bytes` as a measured field and added the `candidate_module_bytes` telemetry, so a pre-cut v3
#: artifact no longer satisfies the closed v3 schema. These objects are the RIG-BEARING artifact a
#: real `eval.candidate.v2` job minted against the final seal, copied verbatim out of the
#: evaluator's own content-addressed store — so the fixture is still a real artifact rather than a
#: synthesised one, and it is now one a consumer can actually receive.
ARTIFACT_ROOT = "ff73475c723853797e6cbee37e5a6dd9cd8ff31438ea0974f20bfcca27b4e51b"
REPORT_ROOT = "9b05cdeceabe18efb56fab0bd5e7b71bdb6a96d9669f784376281c4668c4a9a0"
WITNESS_SOURCE_ROOT = "b6e9004e168f0f36458289d6baa758b8bcd247a407389f07e77ce4bd321c8980"
SUITE_ROOT = "dbb6582dca25d466c6eda4a0c5d30bf29437f74068531a7ee272b9a6462c410e"

#: The rehearsal opening the shadow run committed to. `world_seed` is a pure function of it, and
#: the fixture's signed value is what the coordinator's own derivation predicted independently.
REHEARSAL_SECRET = "7" * 64
EXPECTED_WORLD_SEED = 153161973798012115915136293741110411803


def _store():
    store = pub.InMemoryCAS()
    for name in sorted(os.listdir(CAS)):
        with open(os.path.join(CAS, name), "rb") as fh:
            store.put(name, fh.read())
    return store


def _publish_bridge(store):
    with open(BRIDGE, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    pub.publish_item(document, hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    return document


@pytest.fixture()
def artifact():
    with open(os.path.join(CAS, ARTIFACT_ROOT), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _verify(artifact, store, **overrides):
    front = artifact["frontier"]
    cand = artifact["candidate"]
    kwargs = {
        "expected_parent_root": front["parent_frontier_root"],
        "expected_new_root": front["new_frontier_root"],
        "expected_release_root": cand["release_root"],
        "expected_composition_root": front["composition_root"],
        "expected_runtime_abi_root": front["runtime_abi_root"],
        "expected_benchmark_law_root": front["benchmark_law_root"],
        "expected_counter_resource_law_root": artifact["counter_resource_law_root"],
        "expected_entropy_commitment": None,
        "expected_epoch": artifact["epoch"],
        "expected_target_profile": cand["target_profile"],
        "store": store,
        "resolve_witness_source": True,
        # The parent is constructor genesis (epoch 0) and this advance re-pinned the law, so the
        # inherited parent carries the PRE-CUT pins. That is the re-anchored path, and supplying
        # the independently verified epoch pins is how a validator says so.
        "epoch_pins": {"benchmark_law_root": front["benchmark_law_root"],
                       "runtime_abi_root": front["runtime_abi_root"]},
    }
    kwargs.update(overrides)
    return ea.verify_artifact(artifact, **kwargs)


# --------------------------------------------------------------------------- #
# 1. the honest artifact verifies, end to end, from published bytes only
# --------------------------------------------------------------------------- #
def test_a_real_v3_artifact_verifies_from_clean_public_objects(artifact):
    store = _store()
    _publish_bridge(store)
    report = _verify(artifact, store)

    # the era-specific steps ran, by name — a v3 artifact that quietly took the walk-era path
    # would still "pass" and would have proved nothing about the suite
    for check in ("suite_membership", "genesis_floor", "dominance", "dominance_report_binding",
                  "determinism_witness", "fixed_round_identity", "decided_vectors_are_measured",
                  "determinism_witness_source"):
        assert check in report["checks"], check
    # and the walk-era steps did NOT
    assert "entropy_commitment" not in report["checks"]
    assert "selection_walk" not in report["checks"]

    assert report["witness_provenance"]["resolved"] is True
    assert report["witness_provenance"]["source_kind"] == "bridge"
    assert report["witness_provenance"]["source_root"] == WITNESS_SOURCE_ROOT
    assert ea.deterministic_verdict(artifact)["verdict"] == "ADMIT"


def test_the_artifact_rehashes_to_the_eval_report_hash_the_chain_names(artifact):
    assert ea.eval_report_hash(artifact) == ARTIFACT_ROOT
    assert artifact["suite"]["suite_root"] == SUITE_ROOT == cs.suite_root()


# --------------------------------------------------------------------------- #
# 2. OFFLINE DETERMINISM — two runs, identical hashes
# --------------------------------------------------------------------------- #
def test_two_independent_verifications_produce_identical_hashes_and_reports(artifact):
    """Nothing outside the bytes may influence the outcome — not the store instance, not the
    order objects were published in, not a second copy of the artifact."""
    first_store = _store()
    _publish_bridge(first_store)
    first = _verify(copy.deepcopy(artifact), first_store)

    second_store = _store()
    _publish_bridge(second_store)
    second = _verify(copy.deepcopy(artifact), second_store)

    assert first["checks"] == second["checks"]
    assert first["witness_provenance"] == second["witness_provenance"]
    assert fr.canonical_bytes(first) == fr.canonical_bytes(second)
    assert ea.eval_report_hash(artifact) == ARTIFACT_ROOT
    assert ea.witness_root(artifact["determinism_witness"]) \
        == artifact["determinism_witness"]["witness_root"]


def test_the_uint128_world_seed_survives_a_json_round_trip_exactly(artifact):
    """The trap that cost the integration gate a run: `world_seed` is a uint128, and a reader that
    widens it to a float loses it silently. Python's `int` is exact, and the canonical encoder
    REFUSES a float — so the round trip is byte-identical or it raises."""
    seed = artifact["rig_receipt"]["world_seed"]
    assert isinstance(seed, int) and not isinstance(seed, bool)
    assert seed > 2 ** 53                              # beyond exact IEEE-754 integer range
    reparsed = fr.parse_json(fr.canonical_bytes(artifact).decode("utf-8"))
    assert reparsed["rig_receipt"]["world_seed"] == seed
    assert fr.canonical_bytes(reparsed) == fr.canonical_bytes(artifact)

    widened = copy.deepcopy(artifact)
    widened["rig_receipt"]["world_seed"] = float(seed)
    with pytest.raises(fr.FrontierError):
        fr.canonical_bytes(widened)


# --------------------------------------------------------------------------- #
# 3. STRIPPED-SUITE REFUSAL
# --------------------------------------------------------------------------- #
def test_a_stripped_suite_partition_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["gate"] = doctored["suite"]["cases"]["gate"][:-1]
    with pytest.raises(ea.EvalArtifactError):
        ea.validate_artifact(doctored)


def test_a_stripped_suite_partition_whose_count_was_restated_is_still_refused(artifact):
    """The interesting one: make the artifact internally consistent about the theft. It is the
    LAW's counts that decide, so restating them does not buy a smaller exam."""
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["gate"] = doctored["suite"]["cases"]["gate"][:-1]
    doctored["suite"]["counts"]["gate"] = len(doctored["suite"]["cases"]["gate"])
    with pytest.raises(ea.SuiteMembershipError) as exc:
        ea.verify_suite_membership(doctored)
    assert "never" in str(exc.value) and "subsetted" in str(exc.value)


def test_a_substituted_suite_case_is_refused_even_at_the_right_length(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["confirm"][0]["seed"] += 1
    with pytest.raises(ea.SuiteMembershipError):
        ea.verify_suite_membership(doctored)


def test_a_case_scored_on_a_different_instance_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["cases"]["confirm"][0]["instance_hash"] = "a" * 64
    with pytest.raises(ea.SuiteMembershipError) as exc:
        ea.verify_suite_membership(doctored)
    assert "not the case the law names" in str(exc.value)


def test_an_artifact_naming_another_suite_is_a_mismatch_not_a_variation(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["suite"]["suite_root"] = "b" * 64
    with pytest.raises(ea.SuiteMembershipError) as exc:
        ea.verify_suite_membership(doctored)
    assert "NEW LAW" in str(exc.value)


def test_a_doctored_genesis_floor_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["genesis_floor"]["partitions"]["gate"]["composite_micro"] -= 1
    with pytest.raises(ea.BindingMismatchError):
        ea.verify_genesis_floor(doctored)


def test_a_restated_floor_provenance_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["genesis_floor"]["source"] = "measured by someone, somewhere"
    with pytest.raises(ea.BindingMismatchError) as exc:
        ea.verify_genesis_floor(doctored)
    assert "provenance of the floor is part of the floor" in str(exc.value)


def test_a_doctored_determinism_witness_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["determinism_witness"]["partitions"]["confirm"]["composite_micro"] += 1
    doctored["determinism_witness"]["witness_root"] = ea.witness_root(
        doctored["determinism_witness"])
    with pytest.raises(ea.DeterminismWitnessMismatchError):
        ea.validate_artifact(doctored)


# --------------------------------------------------------------------------- #
# 4. witness provenance — unpublished BACKLOGs, substituted MISMATCHes
# --------------------------------------------------------------------------- #
def test_an_unpublished_witness_source_is_unavailable_not_a_pass(artifact):
    store = _store()                                   # bridge deliberately NOT published
    with pytest.raises(ea.WitnessSourceUnavailableError):
        _verify(artifact, store)


def test_verification_without_a_resolver_reports_unresolved_rather_than_silence(artifact):
    store = _store()
    report = _verify(artifact, store, resolve_witness_source=False)
    provenance = report["witness_provenance"]
    assert provenance["resolved"] is False
    assert provenance["source_root"] == WITNESS_SOURCE_ROOT
    assert "not fetched" in provenance["reason"]
    assert "determinism_witness_source" not in report["checks"]


def test_a_different_valid_bridge_document_at_the_witness_address_is_a_mismatch(artifact):
    store = _store()
    document = _publish_bridge(store)
    hostile = copy.deepcopy(document)
    hostile["partitions"]["gate"]["composite_micro"] += 1
    # SERVED AT the honest address: the substitution a hostile publication surface would attempt.
    store.put(WITNESS_SOURCE_ROOT, pub.encode(hostile, pub.HASH_RULE_FRONTIER_JSON))
    with pytest.raises(ea.WitnessSourceMismatchError):
        _verify(artifact, store)


# --------------------------------------------------------------------------- #
# 5. ERA-AWARE worldSeed
# --------------------------------------------------------------------------- #
def test_the_signed_world_seed_recomputes_from_the_revealed_secret(artifact):
    result = ea.verify_world_seed(artifact, revealed_secret=REHEARSAL_SECRET)
    assert result == {"checked": True, "world_seed": EXPECTED_WORLD_SEED}
    assert artifact["rig_receipt"]["world_seed"] == EXPECTED_WORLD_SEED
    assert ea.derive_world_seed(
        revealed_secret=REHEARSAL_SECRET, epoch=artifact["epoch"],
        parent_frontier_root=artifact["frontier"]["parent_frontier_root"]) == EXPECTED_WORLD_SEED


def test_a_world_seed_that_is_not_the_committed_secrets_expansion_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["rig_receipt"]["world_seed"] += 1
    with pytest.raises(ea.WorldSeedMismatchError) as exc:
        ea.verify_world_seed(doctored, revealed_secret=REHEARSAL_SECRET)
    assert "function of the committed secret" in str(exc.value)


def test_a_different_epoch_secret_does_not_open_this_receipts_seed(artifact):
    with pytest.raises(ea.WorldSeedMismatchError):
        ea.verify_world_seed(artifact, revealed_secret="8" * 64)


def test_an_artifact_with_no_rig_receipt_reports_nothing_to_check(artifact):
    without = {k: v for k, v in artifact.items() if k != "rig_receipt"}
    assert ea.verify_world_seed(without, revealed_secret=REHEARSAL_SECRET)["checked"] is False


# --------------------------------------------------------------------------- #
# 6. AGGREGATE RESOURCE NON-REGRESSION — the rule the public law promised
# --------------------------------------------------------------------------- #
def _parent_identity(artifact):
    """The exact parent execution, taken from the artifact's own resolved incumbent block.

    `_beat_incumbent` re-resolves this from public bytes when it is given a store; these tests
    are about the ARITHMETIC that follows, so the identity is supplied and the resolution is
    covered where it belongs, in the replay tests.
    """
    incumbent = dict(artifact["replay_inputs"]["incumbent"])
    return {"exec": incumbent["exec"], "id": incumbent["id"],
            "candidate_hash": incumbent["candidate_hash"],
            "release_root": incumbent["release_root"],
            "module": {"sha256": incumbent["module_sha256"]}}


def _accounting(**overrides):
    block = {"branch": "confirm", "utility_before_ppm": 667762, "utility_after_ppm": 721537,
             "resource_before_ppm": 1_000_000, "resource_after_ppm": 948_520}
    block.update(overrides)
    return block


def test_the_replayer_refuses_an_advance_that_spends_more_to_score_more(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["resource_accounting"] = _accounting(resource_after_ppm=1_000_001)
    outcome = rp._beat_incumbent(
        doctored, doctored["replay_inputs"]["parent_manifest"],
        doctored["candidate"]["target_profile"], doctored["resource_accounting"],
        ea.deterministic_verdict(doctored),
        resolved_parent_execution=_parent_identity(doctored), store=None)
    assert outcome["code"] == "resource_regression"
    assert "no aggregate resource regression" in outcome["reason"]


def test_the_honest_accounting_passes_the_same_check(artifact):
    outcome = rp._beat_incumbent(
        artifact, artifact["replay_inputs"]["parent_manifest"],
        artifact["candidate"]["target_profile"], artifact["resource_accounting"],
        ea.deterministic_verdict(artifact),
        resolved_parent_execution=_parent_identity(artifact), store=None)
    assert outcome["code"] is None
    report = outcome["report"]
    assert report["resource_after_ppm"] <= report["resource_before_ppm"]
    # the v3 summary a reader needs to see WHY it admitted
    assert report["dominance"]["engine"] == ea.DOMINANCE_ENGINE_ID
    for label in ("gate", "confirm"):
        part = report["dominance"]["partitions"][label]
        assert part["admit"] is True
        assert part["regressed_objectives"] == []
        assert part["regressed_resource_axes"] == []
        assert part["floor_regressions"] == []
    assert report["genesis_floor"]["status"] == "resolved"


# --------------------------------------------------------------------------- #
# 7. the eras are not cross-satisfiable
# --------------------------------------------------------------------------- #
def test_a_v3_artifact_presented_as_v2_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["format"] = ea.ARTIFACT_FORMAT
    with pytest.raises(ea.EvalArtifactError):
        ea.validate_artifact(doctored)


def test_a_v3_artifact_that_grew_an_entropy_block_is_refused(artifact):
    doctored = copy.deepcopy(artifact)
    doctored["entropy"] = {"commitment": "a" * 64, "commitment_scheme": "x",
                           "derivation_domain": ea.ENTROPY_DOMAIN}
    with pytest.raises(ea.EvalArtifactError):
        ea.validate_artifact(doctored)


def test_a_v3_artifact_may_not_be_checked_against_an_entropy_commitment(artifact):
    store = _store()
    _publish_bridge(store)
    with pytest.raises(ea.EntropyMismatchError) as exc:
        _verify(artifact, store, expected_entropy_commitment="c" * 64)
    assert "binds no entropy" in str(exc.value)


# --------------------------------------------------------------------------- #
# 8. `verify-receipt` resolves ALL THREE law-bound comparands, not just the parent
# --------------------------------------------------------------------------- #
def _report():
    with open(os.path.join(CAS, REPORT_ROOT), "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_verify_receipt_resolves_the_suite_the_parent_and_the_floor(artifact):
    from coretex_validator import cli

    block = cli._resolve_fixed_suite(_report(), artifact)
    assert block["applies"] is True and block["resolved"] is True
    assert "outcome" not in block                       # nothing refused
    assert block["law_id"] == ea.FIXED_SUITE_LAW_ID
    assert block["suite"]["resolved_root"] == block["suite"]["bound_root"] == SUITE_ROOT
    assert block["suite"]["counts"] == cs.suite_counts("event.schema.v1")
    assert block["genesis_floor"]["status"] == "resolved"
    assert block["genesis_floor"]["artifact_agrees"] is True


def test_a_walk_era_receipt_is_told_there_is_no_suite_rather_than_being_refused():
    """Era-aware, not era-blind: those receipts were never decided against a suite."""
    from coretex_validator import cli

    block = cli._resolve_fixed_suite(
        {"format": ea.EVAL_REPORT_FORMAT, "evaluation_law": {"law_id": "prior-era"}}, {})
    assert block == {"applies": False, "law_id": "prior-era", "reason": block["reason"]}
    assert "prior law era" in block["reason"]


def test_a_receipt_bound_to_another_suite_is_refused_before_anything_is_replayed():
    from coretex_validator import cli

    report = _report()
    report["evaluation_law"] = dict(report["evaluation_law"], canonical_suite_root="c" * 64)
    block = cli._resolve_fixed_suite(report, {})
    assert block["outcome"] == "FAIL"
    assert block["code"] == "CANONICAL_SUITE_MISMATCH"
    assert "NEW LAW" in block["reason"]


def test_a_receipt_whose_partition_was_trimmed_is_refused(artifact):
    from coretex_validator import cli

    report = _report()
    report["selection"] = {label: list(cases) for label, cases in report["selection"].items()}
    report["selection"]["gate"] = report["selection"]["gate"][:-1]
    block = cli._resolve_fixed_suite(report, artifact)
    assert block["outcome"] == "FAIL"
    assert block["code"] == "SUITE_PARTITION_MISMATCH"


def test_malformed_input_is_reported_rather_than_crashing():
    """It is handed caller-supplied JSON from a file, so every shape has to have an answer."""
    from coretex_validator import cli

    for bad in (None, [], "receipt", {"evaluation_law": "not a map"}, {}):
        block = cli._resolve_fixed_suite(bad, None)
        assert block["applies"] is False and block["reason"]


# --------------------------------------------------------------------------- #
# 9. `reproduce-snapshot` reads the artifact's REAL family off its own bytes
# --------------------------------------------------------------------------- #
def test_the_published_label_is_reported_but_the_bytes_decide():
    """`v5/resolver/artifacts.py` labels every eval-artifact ref v2 without opening the object, so
    a post-cut snapshot calls a v3 artifact v2. The label is reproduced (that is what reproduction
    means) and it is not read as evidence."""
    from coretex_validator import cli

    published = {"artifacts": [{"kind": ea.ARTIFACT_FORMAT, "root": ARTIFACT_ROOT}]}
    resolved = cli._snapshot_eval_artifact_families(published, store_dir=CAS)
    entry = resolved["entries"][0]
    assert entry["published_label"] == ea.ARTIFACT_FORMAT
    assert entry["observed_format"] == ea.ARTIFACT_FORMAT_V3
    assert "the BYTES win" in entry["note"]

    unresolved = cli._snapshot_eval_artifact_families(published, store_dir=None)
    assert unresolved["entries"][0]["observed_format"] is None
    assert "not evidence" in unresolved["entries"][0]["note"]


# --------------------------------------------------------------------------- #
# 10. the review findings — each one, as the shape that would have hurt
# --------------------------------------------------------------------------- #
def test_a_canary_on_a_v3_artifact_refuses_instead_of_raising_KeyError(artifact):
    """`ARTIFACT_FIELDS_V3` carries `canary` in the OPTIONAL set and `build_artifact_v3` accepts
    one, so this combination is constructible — and `verify_canary_block` read
    `artifact["entropy"]` unconditionally. A bare KeyError is not a refusal: `replay.canary_evidence`
    catches only the typed errors, so it escaped and crashed a public validator at the LAST step of
    an advance whose verdict had already been computed."""
    import hashlib

    policy = {"format": "benchmark-v2/canary/policy/v1", "model_id": "m", "temperature": 0.0,
              "max_answer_tokens": 64, "scale": "small", "n_questions": 48,
              "per_run_usd_cap": 1.0, "max_accuracy_drop_pp": 5.0,
              "selection_domain": "benchmark-v2/canary/select/v1"}
    base = hashlib.sha256("|".join(
        (policy["selection_domain"], "ab" * 32, artifact["candidate"]["candidate_hash"],
         artifact["frontier"]["parent_frontier_root"], artifact["candidate"]["target_profile"],
         str(artifact["epoch"]), policy["scale"])).encode("utf-8")).hexdigest()
    sealed = {
        "format": ea.CANARY_TRANSCRIPT_FORMAT, "external_model_attestation": True,
        "policy_hash": ea.canary_policy_hash(policy), "policy": policy,
        "code_identity": {"format": "benchmark-v2/canary/code-identity/v1",
                          "scorer_version": "canary-scorer.v3",
                          "scoring.py_sha256": "40" * 32, "questions.py_sha256": "41" * 32},
        "epoch_id": str(artifact["epoch"]), "run_id": "r", "mode": "dryrun",
        "entropy": {"hex": "ab" * 32, "domain": policy["selection_domain"],
                    "selection_base_sha256": base},
        "candidate_hash": artifact["candidate"]["candidate_hash"],
        "incumbent_root": artifact["frontier"]["parent_frontier_root"],
        "selection": {"profile_id": artifact["candidate"]["target_profile"], "scale": "small",
                      "n_questions": 48},
        "verdict": {"verdict": "PASS", "reasons": []},
    }
    with_canary = copy.deepcopy(artifact)
    with_canary["canary"] = ea.build_canary_block(sealed)
    outcome = ea.verify_canary_block(with_canary, sealed_transcript=sealed)
    assert outcome["ok"] is False
    assert outcome["code"] == "canary_era_mismatch"
    assert outcome["consensus_critical"] is False        # and it still cannot change a verdict


def test_the_sandbox_child_takes_a_v4_selection_from_the_law_not_from_a_walk():
    """The defect that made the headline capability unreachable.

    A v4 eval report's selection carries `suite_index`; the child compared on `derivation_index`
    and re-derived a WALK. Every fixed-suite receipt therefore died in the child with a raw
    KeyError and came back as a BACKLOG — fail-closed, but no v3 advance could ever be replayed to
    PASS through the real sandbox. Asserted on the child SOURCE because running it needs the pinned
    trees, wasmtime and minutes per case.
    """
    source = rp._SANDBOX_CHILD_V2
    assert "bench_law.selects_fixed_suite" in source
    assert "bench_suite.suite_selection(body[\"profile_id\"])" in source
    assert '"suite_index"' in source
    # the walk path is kept, not replaced
    assert "bench_select.select_for_candidate(round_rec, ch, burned)" in source
    assert '"derivation_index"' in source
    # a tree without the suite loader refuses rather than AttributeError-ing on None
    assert "canonical_suite_unavailable" in source
    # and a selection missing the field its own law requires is typed, not a traceback
    assert "selection_shape_mismatch" in source


def test_a_fail_outranks_a_backlog_when_both_resolvers_refuse():
    """A local BACKLOG must never mask a determination about the chain. `verify-receipt` resolves
    the incumbent and the suite independently; if the suite BACKLOGs (a pending floor) while the
    incumbent FAILs (the parent is not what the receipt names), reporting the BACKLOG would turn a
    refutation into unresolved work and exit 0."""
    import inspect

    from coretex_validator import cli

    body = inspect.getsource(cli._cmd_verify_receipt)
    assert 'key=lambda b: 0 if b["outcome"] == "FAIL" else 1' in body
    assert body.index("suite_block = _resolve_fixed_suite") < body.index("for block in sorted(")


def test_a_malformed_suite_selection_is_reported_not_raised():
    from coretex_validator import cli

    receipt = {"format": ea.EVAL_REPORT_FORMAT, "profile_id": "event.schema.v1",
               "evaluation_law": {"law_id": ea.FIXED_SUITE_LAW_ID,
                                  "canonical_suite_root": SUITE_ROOT},
               "selection": []}
    assert cli._resolve_fixed_suite(receipt, None)["code"] == "SUITE_SELECTION_MALFORMED"
    receipt["selection"] = {"gate": ["not-an-object"], "confirm": []}
    assert cli._resolve_fixed_suite(receipt, None)["code"] == "SUITE_SELECTION_MALFORMED"


def test_an_eval_artifact_ref_is_found_by_its_chain_binding_not_by_the_label():
    """Filtering on `kind` excluded exactly the ref this scan exists to catch — one the publisher
    labelled wrongly or not at all."""
    from coretex_validator import cli

    published = {"artifacts": [
        {"kind": "who-knows", "root": ARTIFACT_ROOT,
         "chain_binding": "registry log evalReportHash of transition 0"}]}
    resolved = cli._snapshot_eval_artifact_families(published, store_dir=CAS)
    assert resolved["refs"] == 1
    assert resolved["entries"][0]["observed_format"] == ea.ARTIFACT_FORMAT_V3
