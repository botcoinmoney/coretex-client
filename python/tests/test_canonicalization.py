# SPDX-License-Identifier: UNLICENSED
"""CANONICALIZATION cannot be gamed (spec §2/§3/§4).

Every test here answers one question: can two DIFFERENT documents end up addressing the SAME
root, or can one document produce two roots? Each way that could happen is closed here.
"""
from __future__ import annotations

import itertools
import json
import os
import sys

import pytest

from conftest import REPO, ROOT_A, ROOT_B, ROOT_C, make_manifest

import frontier as fr


# --------------------------------------------------------------------------- #
# The rule itself IS the runtime's rule
# --------------------------------------------------------------------------- #
def test_canonical_rule_is_byte_identical_to_the_runtime_rule(manifest):
    """The canonical bytes are exactly ``coretex_memory.release.canonical_manifest_bytes``.

    That runtime function drops the two attestation fields from the body; a frontier manifest
    carries neither, so on this input the two functions must agree BYTE FOR BYTE. If they ever
    diverge, every signed-artifact root and every frontier root stop speaking one dialect.
    """
    tree = os.path.join(REPO, "coretex-memory")
    if tree not in sys.path:
        sys.path.insert(0, tree)
    try:
        from coretex_memory import release as runtime_release
    except Exception as exc:                                   # pragma: no cover - env guard
        pytest.skip(f"coretex_memory runtime tree not importable: {exc}")
    assert fr.canonical_bytes(manifest) == runtime_release.canonical_manifest_bytes(manifest)
    assert fr.frontier_root(manifest) == runtime_release.manifest_self_hash(manifest)


def test_canonical_bytes_match_the_literal_written_rule(manifest):
    assert fr.canonical_bytes(manifest) == json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def test_canonical_bytes_have_no_whitespace_and_are_ascii(manifest):
    raw = fr.canonical_bytes(manifest)
    assert b" " not in raw and b"\n" not in raw and b"\t" not in raw
    raw.decode("ascii")                                        # ensure_ascii=True


# --------------------------------------------------------------------------- #
# Key order is not a degree of freedom
# --------------------------------------------------------------------------- #
def test_every_top_level_key_permutation_yields_one_root(manifest):
    roots = set()
    byte_forms = set()
    for order in itertools.permutations(sorted(manifest)):
        permuted = {k: manifest[k] for k in order}
        assert list(permuted) == list(order)                   # dict preserves insertion order
        byte_forms.add(fr.canonical_bytes(permuted))
        roots.add(fr.frontier_root(permuted))
    assert len(roots) == 1 and len(byte_forms) == 1
    assert roots == {fr.frontier_root(manifest)}


def test_profile_key_permutations_yield_one_root(manifest):
    roots = set()
    for order in itertools.permutations(fr.PROFILE_IDS):
        permuted = dict(manifest)
        permuted["profiles"] = {pid: manifest["profiles"][pid] for pid in order}
        roots.add(fr.frontier_root(permuted))
    assert len(roots) == 1


def test_json_text_key_order_and_whitespace_do_not_change_the_root(manifest):
    pretty = json.dumps(manifest, indent=4, sort_keys=False)
    reversed_keys = json.dumps({k: manifest[k] for k in sorted(manifest, reverse=True)})
    a = fr.frontier_root(fr.parse_manifest_json(pretty))
    b = fr.frontier_root(fr.parse_manifest_json(reversed_keys))
    assert a == b == fr.frontier_root(manifest)


def test_normative_profile_order_is_the_serializer_order():
    """The normative total order (UTF-8 byte order of the id) is what ``sort_keys`` emits."""
    assert list(fr.PROFILE_IDS) == sorted(fr.PROFILE_IDS)
    by_bytes = sorted(fr.PROFILE_IDS, key=lambda p: p.encode("utf-8"))
    assert list(fr.PROFILE_IDS) == by_bytes
    scrambled = {pid: "0" * 64 for pid in reversed(fr.PROFILE_IDS)}
    emitted = json.loads(fr.canonical_bytes(scrambled).decode())
    assert list(emitted) == list(fr.PROFILE_IDS)


# --------------------------------------------------------------------------- #
# CASE is rejected, never normalized
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["Conv.pref.v1", "CONV.PREF.V1", "conv.Pref.v1"])
def test_case_varied_profile_id_is_rejected_not_folded(bad):
    with pytest.raises(fr.UnknownProfileError):
        fr.check_profile_id(bad)
    manifest = make_manifest()
    manifest["profiles"] = {bad: ROOT_A, "doc.tool.v1": ROOT_B, "event.schema.v1": ROOT_C}
    with pytest.raises(fr.UnknownProfileError):
        fr.frontier_root(manifest)


@pytest.mark.parametrize("field", ["benchmark_law_root", "runtime_abi_root",
                                   "default_composition_root", "parent_frontier_root"])
def test_uppercase_hex_root_is_rejected_not_lowered(field):
    manifest = make_manifest(**{field: "A" * 64})
    with pytest.raises(fr.FrontierValueError) as exc:
        fr.frontier_root(manifest)
    assert "UPPERCASE" in str(exc.value)


def test_uppercase_release_root_is_rejected():
    manifest = make_manifest()
    manifest["profiles"]["doc.tool.v1"] = ROOT_B.upper()
    with pytest.raises(fr.FrontierValueError):
        fr.frontier_root(manifest)


def test_lower_and_upper_forms_never_share_a_root():
    """The point of rejecting rather than folding: only ONE byte string is addressable."""
    lower = make_manifest()
    upper = make_manifest(benchmark_law_root="1" * 63 + "A")
    assert fr.frontier_root(lower)
    with pytest.raises(fr.FrontierValueError):
        fr.frontier_root(upper)


@pytest.mark.parametrize("bad", ["0x" + "a" * 62, "0X" + "a" * 62])
def test_0x_prefixed_root_is_rejected(bad):
    with pytest.raises(fr.FrontierValueError) as exc:
        fr.check_root(bad, "probe")
    assert "0x-prefixed" in str(exc.value)


@pytest.mark.parametrize("bad", ["a" * 63, "a" * 65, "", "zz" + "a" * 62])
def test_malformed_root_is_rejected(bad):
    with pytest.raises(fr.FrontierValueError):
        fr.check_root(bad, "probe")


# --------------------------------------------------------------------------- #
# ABSENT vs NULL: distinct-and-invalid, never silently equal
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field", sorted(fr.MANIFEST_FIELDS))
def test_omitted_field_is_a_schema_error(field):
    manifest = make_manifest()
    del manifest[field]
    with pytest.raises(fr.FrontierSchemaError) as exc:
        fr.validate_manifest(manifest)
    assert "missing required field" in str(exc.value)


@pytest.mark.parametrize("field", sorted(fr.MANIFEST_FIELDS))
def test_explicitly_null_field_is_a_type_error_not_the_same_as_omitted(field):
    manifest = make_manifest(**{field: None})
    with pytest.raises((fr.FrontierTypeError, fr.FrontierSchemaError)) as exc:
        fr.validate_manifest(manifest)
    # DISTINCT from the omitted case: never the "missing required field" message, and for every
    # field that is type-checked it is a different error class entirely.
    assert "missing required field" not in str(exc.value)


def test_omitted_and_null_are_distinct_failures_never_one_root(manifest):
    omitted = dict(manifest)
    del omitted["runtime_abi_root"]
    nulled = dict(manifest, runtime_abi_root=None)
    with pytest.raises(fr.FrontierSchemaError) as omitted_exc:
        fr.frontier_root(omitted)
    with pytest.raises(fr.FrontierTypeError) as nulled_exc:
        fr.frontier_root(nulled)
    # Neither is addressable, and the two are DISTINCT errors — "absent" never means "null".
    assert type(omitted_exc.value) is not type(nulled_exc.value)
    assert str(omitted_exc.value) != str(nulled_exc.value)


def test_null_is_not_a_canonical_value_at_the_serializer_too():
    """Defense in depth: even bypassing schema validation, null cannot be serialized."""
    with pytest.raises(fr.CanonicalizationError) as exc:
        fr.canonical_bytes({"a": None})
    assert "null is not a canonical value" in str(exc.value)
    with pytest.raises(fr.CanonicalizationError):
        fr.canonical_bytes({"a": {"b": [1, None]}})


def test_null_profile_release_root_is_rejected():
    manifest = make_manifest()
    manifest["profiles"]["doc.tool.v1"] = None
    with pytest.raises(fr.FrontierTypeError):
        fr.validate_manifest(manifest)


# --------------------------------------------------------------------------- #
# DUPLICATE keys (the JSON-TEXT path — dicts dedupe silently)
# --------------------------------------------------------------------------- #
def test_duplicate_profile_key_in_json_text_is_rejected():
    text = ('{"benchmark_law_root":"' + "1" * 64 + '","default_composition_root":"' + "3" * 64
            + '","epoch":7,"format":"' + fr.MANIFEST_FORMAT + '","parent_frontier_root":"'
            + "9" * 64 + '","profiles":{"conv.pref.v1":"' + ROOT_A + '","doc.tool.v1":"' + ROOT_B
            + '","doc.tool.v1":"' + "d" * 64 + '","event.schema.v1":"' + ROOT_C
            + '"},"runtime_abi_root":"' + "2" * 64 + '"}')
    # sanity: stdlib json SILENTLY keeps the last value — which is exactly the hazard
    assert json.loads(text)["profiles"]["doc.tool.v1"] == "d" * 64
    with pytest.raises(fr.DuplicateKeyError) as exc:
        fr.parse_manifest_json(text)
    assert "doc.tool.v1" in str(exc.value)


def test_duplicate_top_level_key_in_json_text_is_rejected():
    text = '{"epoch":1,"epoch":2}'
    assert json.loads(text) == {"epoch": 2}
    with pytest.raises(fr.DuplicateKeyError):
        fr.parse_json(text)


def test_duplicate_key_in_transition_bytes_is_rejected():
    raw = fr.transition_bytes(
        target_profile="doc.tool.v1", expected_prior_release_root=ROOT_B,
        new_release_root="d" * 64, resulting_composition_root="4" * 64)
    # a SHORT duplicate, so the payload stays inside the size bound and the duplicate-key check
    # is what fires (the size guard runs first and would otherwise mask it)
    tampered = raw.replace(b'{"expected_prior_release_root"',
                           b'{"format":"x","expected_prior_release_root"')
    assert len(tampered) <= fr.MAX_TRANSITION_BYTES
    assert json.loads(tampered)["format"] == fr.TRANSITION_FORMAT   # stdlib keeps the LAST
    with pytest.raises(fr.DuplicateKeyError):
        fr.parse_transition_bytes(tampered)


# --------------------------------------------------------------------------- #
# UNKNOWN profiles / UNKNOWN fields (the schema is CLOSED)
# --------------------------------------------------------------------------- #
def test_unknown_profile_in_the_map_is_rejected():
    manifest = make_manifest()
    manifest["profiles"]["chat.voice.v1"] = "e" * 64
    with pytest.raises(fr.UnknownProfileError) as exc:
        fr.validate_manifest(manifest)
    assert "CLOSED profile set" in str(exc.value)


def test_legacy_profile_is_not_a_frontier_profile():
    manifest = make_manifest()
    manifest["profiles"][fr.LEGACY_PROFILE_ID] = "e" * 64
    with pytest.raises(fr.UnknownProfileError) as exc:
        fr.validate_manifest(manifest)
    assert "default_composition_root" in str(exc.value)


def test_missing_profile_is_rejected():
    manifest = make_manifest()
    del manifest["profiles"]["event.schema.v1"]
    with pytest.raises(fr.FrontierSchemaError) as exc:
        fr.validate_manifest(manifest)
    assert "missing required profile" in str(exc.value)


def test_unknown_top_level_field_is_rejected(manifest):
    manifest["extra_note"] = "hello"
    with pytest.raises(fr.FrontierSchemaError) as exc:
        fr.validate_manifest(manifest)
    assert "unknown field" in str(exc.value)


def test_wrong_format_tag_is_rejected(manifest):
    manifest["format"] = "coretex.memory-frontier.v2"
    with pytest.raises(fr.FrontierSchemaError):
        fr.validate_manifest(manifest)


# --------------------------------------------------------------------------- #
# NUMBERS: integer form only; no floats, no NaN/Inf, no bool-as-int
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", [7.0, 0.5, float("nan"), float("inf"), float("-inf")])
def test_float_epoch_is_rejected(bad):
    with pytest.raises(fr.FrontierTypeError):
        fr.validate_manifest(make_manifest(epoch=bad))


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), 1.0])
def test_floats_are_not_canonical_values(bad):
    with pytest.raises(fr.CanonicalizationError) as exc:
        fr.canonical_bytes({"n": bad})
    assert "floats are not canonical" in str(exc.value)


def test_stdlib_json_would_have_emitted_non_json_nan():
    """Why floats are refused outright rather than range-checked."""
    assert json.dumps({"n": float("nan")}) == '{"n": NaN}'


def test_bool_epoch_is_rejected():
    with pytest.raises(fr.FrontierTypeError) as exc:
        fr.validate_manifest(make_manifest(epoch=True))
    assert "bool" in str(exc.value)


def test_string_epoch_is_rejected():
    with pytest.raises(fr.FrontierTypeError):
        fr.validate_manifest(make_manifest(epoch="7"))


@pytest.mark.parametrize("bad", [-1, fr.MAX_EPOCH + 1])
def test_out_of_range_epoch_is_rejected(bad):
    with pytest.raises(fr.FrontierValueError):
        fr.validate_manifest(make_manifest(epoch=bad))


def test_integers_serialize_in_integer_form():
    assert fr.canonical_bytes({"epoch": 0}) == b'{"epoch":0}'
    assert fr.canonical_bytes({"epoch": 10 ** 20}) == b'{"epoch":100000000000000000000}'


# --------------------------------------------------------------------------- #
# Misc canonicalizer fail-closed behaviour
# --------------------------------------------------------------------------- #
def test_non_string_object_key_is_rejected():
    with pytest.raises(fr.CanonicalizationError) as exc:
        fr.canonical_bytes({1: "a"})
    assert "not a string" in str(exc.value)


def test_unsupported_type_is_rejected():
    with pytest.raises(fr.CanonicalizationError):
        fr.canonical_bytes({"a": {1, 2}})


def test_cyclic_structure_is_rejected_rather_than_hanging():
    node = {}
    node["self"] = node
    with pytest.raises(fr.CanonicalizationError) as exc:
        fr.canonical_bytes(node)
    assert "deeper than" in str(exc.value)


def test_arrays_keep_their_order():
    assert fr.canonical_bytes({"xs": ["b", "a"]}) == b'{"xs":["b","a"]}'
    assert fr.canonical_bytes({"xs": ["b", "a"]}) != fr.canonical_bytes({"xs": ["a", "b"]})


def test_non_ascii_is_escaped_identically_everywhere():
    assert fr.canonical_bytes({"s": "é"}) == b'{"s":"\\u00e9"}'


def test_canonical_bytes_requires_an_object():
    with pytest.raises(fr.CanonicalizationError):
        fr.canonical_bytes(["not", "an", "object"])


def test_parse_json_rejects_non_json():
    with pytest.raises(fr.FrontierSchemaError):
        fr.parse_json("{not json")
