import copy
import hashlib
import json
import pytest
from coretex_validator import release as validator


def origin():
    source = "def make_hooks(context):\n    dispatch.set_override(abi2.M6, m6_pack)\n"
    document = {"module_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "deployment_profile": "doc.tool.v1"}
    root = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    document["manifest_self_sha256"] = root
    record = {"parent": {"release_root": root, "manifest": document, "module_source": source}}
    new = source.replace("def make_hooks(context):\n", "def make_hooks(context):\n"
        "    def m5_rank(question, candidates):\n"
        "        return context.ref_m5_rank(question, candidates)\n\n")
    new = new.replace("    dispatch.set_override(abi2.M6, m6_pack)",
                      "    dispatch.set_override(abi2.M5, m5_rank)\n    dispatch.set_override(abi2.M6, m6_pack)")
    return record, new.encode(), root


def test_exact_m5_extension_is_a_prospective_edge():
    record, source, root = origin()
    validator._verify_m5_extension_origin(record, source, "doc.tool.v1", root)


@pytest.mark.parametrize("change", ["source", "parent", "old_source", "profile"])
def test_m5_extension_cannot_hide_another_change(change):
    record, source, root = origin()
    profile = "doc.tool.v1"
    if change == "source": source += b"# unrelated code\n"
    if change == "parent": root = "00" * 32
    if change == "old_source": record["parent"]["module_source"] += "# tamper\n"
    if change == "profile": profile = "conv.pref.v1"
    with pytest.raises(validator.ReleaseError):
        validator._verify_m5_extension_origin(record, source, profile, root)
