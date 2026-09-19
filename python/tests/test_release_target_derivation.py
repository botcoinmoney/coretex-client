"""The build target is derived, and the embedded law inputs are the coordinator's own bytes.

Two separate refusals are exercised here.  The first is about IDENTITY: the wheel's version and
filenames come from ``pyproject.toml`` and nowhere else, so a caller can assert the version it
expects but can never mint one.  The second is about CONTENT: five package data members are
copies of a coordinator tree's law sources, and a copy that has gone stale must be named, not
shipped.  Everything that could write runs against a copy of the package in ``tmp_path``; the
checked-in package is only ever read.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

import build_release


PYTHON_ROOT = Path(build_release.__file__).resolve().parent
PACKAGE_DIR = PYTHON_ROOT / "coretex_validator"

#: Deliberately not the real law text: short, unique, and obviously synthetic, so a byte that
#: moves in this fixture cannot be confused with a byte that moved in the real law.
COORDINATOR_BYTES = {
    "CANONICAL-SUITE.v1.json": b'{"format": "canonical-suite/v1", "cases": []}\n',
    "COUNTER_RESOURCE_LAW.v1.json": b'{"format": "counter-resource-law/v1"}\n',
    "LAW.md": b"# Synthetic law\n\nOne paragraph of fixture law text.\n",
    "RIG-CONTRACT-AUTHORITY.base-mainnet.json": b'{"chain_id": 8453}\n',
    "RIG-WIRE-BINDING.v1.json": b'{"format": "coretex.rig-wire-binding/v1"}\n',
}
#: The identity the checked-in RELEASE-CONTRACT.v1.json already carries, expressed the way a
#: coordinator manifest expresses it (product.version + release.sequence/predecessor).
MANIFEST_PRODUCT = {"name": "coretex", "version": build_release.VERSION}
MANIFEST_RELEASE = {
    "predecessor": "4782fe5d293c678a20e943b6acfce9e09682ab7aa06e2373348f96d45d2e19e5",
    "sequence": 2,
}
MANIFEST_LAW_IDENTITY = {
    "decision_engine_id": "dominance.componentwise.v2",
    "family": "benchmark-v2-law/dominance-fixed-suite",
    "revision": "v2",
}


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def make_coordinator(root: Path, *, version: str | None = None, **overrides) -> Path:
    """A minimal coordinator tree: the five law sources plus one release manifest."""
    version = build_release.VERSION if version is None else version
    sources = {
        "CANONICAL-SUITE.v1.json": "benchmark-v2/validator/CANONICAL-SUITE.v1.json",
        "COUNTER_RESOURCE_LAW.v1.json": "v5/COUNTER_RESOURCE_LAW.v1.json",
        "LAW.md": "benchmark-v2/LAW.md",
        "RIG-CONTRACT-AUTHORITY.base-mainnet.json":
            "v5/RIG-CONTRACT-AUTHORITY.base-mainnet.json",
        "RIG-WIRE-BINDING.v1.json": build_release.RIG_WIRE_BINDING_SOURCE,
    }
    for member, relative in sources.items():
        _write(root / relative, COORDINATOR_BYTES[member])
    law = dict(MANIFEST_LAW_IDENTITY)
    law.update({
        "canonical_suite_path": sources["CANONICAL-SUITE.v1.json"],
        "counter_resource_law_path": sources["COUNTER_RESOURCE_LAW.v1.json"],
        "law_md_path": sources["LAW.md"],
    })
    manifest = {
        "law": law,
        "product": dict(MANIFEST_PRODUCT),
        "release": dict(MANIFEST_RELEASE),
        "rig_contract_authority": {
            "path": sources["RIG-CONTRACT-AUTHORITY.base-mainnet.json"]},
    }
    for key, value in overrides.items():
        manifest[key] = value
    _write(root / build_release.manifest_relative_path(version),
           json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
    return root


def make_package_copy(root: Path, *, law_bytes=None) -> Path:
    """A copy of the package's data members, never the checked-in package itself."""
    package = root / build_release.PACKAGE
    package.mkdir(parents=True, exist_ok=True)
    law_bytes = COORDINATOR_BYTES if law_bytes is None else law_bytes
    for member in build_release.LAW_INPUT_MEMBERS:
        _write(package / member, law_bytes[member])
    shutil.copyfile(PACKAGE_DIR / build_release.RELEASE_CONTRACT_MEMBER,
                    package / build_release.RELEASE_CONTRACT_MEMBER)
    return root


@pytest.fixture()
def coordinator(tmp_path):
    return make_coordinator(tmp_path / "coordinator")


@pytest.fixture()
def package_copy(tmp_path):
    return make_package_copy(tmp_path / "package")


# --------------------------------------------------------------------------- target derivation


def test_version_is_read_from_pyproject_not_restated():
    text = (PYTHON_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'(?ms)^\[project\]$.*?^version = "([^"]+)"$', text)
    assert declared is not None, "pyproject.toml [project] declares no version"
    assert build_release.VERSION == declared.group(1)
    assert build_release.declared_version(PYTHON_ROOT) == build_release.VERSION


def test_archive_names_are_derived_from_the_declared_version():
    version = build_release.VERSION
    assert build_release.WHEEL_NAME == f"{build_release.DIST}-{version}-py3-none-any.whl"
    assert build_release.SDIST_NAME == f"{build_release.DIST}-{version}.tar.gz"
    assert build_release.DIST_INFO == f"{build_release.DIST}-{version}.dist-info"
    assert build_release.SDIST_ROOT == f"{build_release.DIST}-{version}"
    # Nothing in the builder restates the version as a literal.
    source = (PYTHON_ROOT / "build_release.py").read_text(encoding="utf-8")
    assert f'"{version}"' not in source


def test_declared_version_reads_only_the_project_table(tmp_path):
    _write(tmp_path / "pyproject.toml", (
        '[build-system]\n'
        'version = "9.9.9"\n'
        '\n'
        '[project]\n'
        'name = "coretex-validator"\n'
        'version = "2.4.7"\n'
        '\n'
        '[project.urls]\n'
        'version = "8.8.8"\n').encode("utf-8"))
    assert build_release.declared_version(tmp_path) == "2.4.7"


def test_declared_version_refuses_a_second_project_version(tmp_path):
    _write(tmp_path / "pyproject.toml",
           b'[project]\nversion = "1.1.0"\nversion = "1.2.0"\n')
    with pytest.raises(build_release.BuildError) as excinfo:
        build_release.declared_version(tmp_path)
    assert "exactly one" in str(excinfo.value)


def test_declared_version_refuses_a_non_release_version(tmp_path):
    _write(tmp_path / "pyproject.toml", b'[project]\nversion = "1.1.0.dev3"\n')
    with pytest.raises(build_release.BuildError) as excinfo:
        build_release.declared_version(tmp_path)
    assert "MAJOR.MINOR.PATCH" in str(excinfo.value)


def test_version_flag_accepts_the_declared_version(tmp_path, capsys):
    out_dir = tmp_path / "unused"
    assert build_release.main(
        ["--version", build_release.VERSION, "--print-target", "--out-dir", str(out_dir)]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == build_release.VERSION


def test_version_flag_refuses_a_forged_version_and_names_both():
    with pytest.raises(build_release.BuildError) as excinfo:
        build_release.main(["--version", "9.9.9", "--print-target"])
    message = str(excinfo.value)
    assert "9.9.9" in message and build_release.VERSION in message


def test_print_target_emits_the_documented_json_and_builds_nothing(tmp_path, capsys):
    out_dir = tmp_path / "dist"
    assert build_release.main(["--print-target", "--out-dir", str(out_dir)]) == 0
    raw = capsys.readouterr().out
    assert raw.count("\n") == 1, "--print-target must emit exactly one line"
    printed = json.loads(raw)
    assert set(printed) == {"distribution", "version", "wheel_name", "sdist_name", "out_dir"}
    assert printed == {
        "distribution": build_release.DIST,
        "out_dir": str(out_dir.resolve()),
        "sdist_name": build_release.SDIST_NAME,
        "version": build_release.VERSION,
        "wheel_name": build_release.WHEEL_NAME,
    }
    assert not out_dir.exists()


def test_print_target_out_dir_defaults_next_to_the_builder(capsys):
    assert build_release.main(["--print-target"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["out_dir"] == str(PYTHON_ROOT / "dist")


# ------------------------------------------------------------------------- law input verification


def test_law_sources_come_from_the_manifest_not_from_this_builder(coordinator):
    manifest = build_release.load_coordinator_manifest(coordinator)
    sources = build_release.coordinator_law_sources(manifest)
    assert set(sources) == set(build_release.LAW_INPUT_MEMBERS)
    assert sources["LAW.md"] == manifest["law"]["law_md_path"]
    assert sources["CANONICAL-SUITE.v1.json"] == manifest["law"]["canonical_suite_path"]
    assert sources["RIG-CONTRACT-AUTHORITY.base-mainnet.json"] == \
        manifest["rig_contract_authority"]["path"]
    assert sources["RIG-WIRE-BINDING.v1.json"] == build_release.RIG_WIRE_BINDING_SOURCE


def test_verification_passes_when_every_law_input_matches(coordinator, package_copy):
    result = build_release.verify_law_inputs(package_copy, coordinator)
    assert result["ok"] is True
    assert result["failures"] == []
    assert [entry["member"] for entry in result["entries"]] == list(
        build_release.LAW_INPUT_MEMBERS) + [
            f"{build_release.RELEASE_CONTRACT_MEMBER}:product",
            f"{build_release.RELEASE_CONTRACT_MEMBER}:law"]


@pytest.mark.parametrize("member", build_release.LAW_INPUT_MEMBERS)
def test_one_changed_byte_fails_and_names_that_member(coordinator, package_copy, member):
    stale = package_copy / build_release.PACKAGE / member
    stale.write_bytes(COORDINATOR_BYTES[member].replace(b"\n", b" \n", 1))
    result = build_release.verify_law_inputs(package_copy, coordinator)
    assert result["ok"] is False
    assert result["failures"] == [member]
    entry = next(item for item in result["entries"] if item["member"] == member)
    assert entry["package_sha256"] != entry["coordinator_sha256"]
    rendered = build_release.render_law_inputs(result)
    assert member in rendered and "DRIFTED" in rendered


def test_every_drifted_member_is_named_in_one_run(coordinator, package_copy):
    for member in ("LAW.md", "CANONICAL-SUITE.v1.json"):
        (package_copy / build_release.PACKAGE / member).write_bytes(b"stale\n")
    result = build_release.verify_law_inputs(package_copy, coordinator)
    assert sorted(result["failures"]) == ["CANONICAL-SUITE.v1.json", "LAW.md"]


def test_a_missing_coordinator_source_is_a_named_failure_not_a_crash(
        coordinator, package_copy, tmp_path):
    # An absent source cannot prove agreement, so it reports drift with no coordinator hash.
    (coordinator / "benchmark-v2" / "LAW.md").rename(tmp_path / "LAW.md.moved")
    result = build_release.verify_law_inputs(package_copy, coordinator)
    assert result["failures"] == ["LAW.md"]
    entry = next(item for item in result["entries"] if item["member"] == "LAW.md")
    assert entry["coordinator_sha256"] is None and entry["detail"]


def test_a_missing_manifest_is_refused(tmp_path, package_copy):
    empty = tmp_path / "empty-coordinator"
    empty.mkdir()
    with pytest.raises(build_release.BuildError) as excinfo:
        build_release.verify_law_inputs(package_copy, empty)
    assert build_release.manifest_relative_path() in str(excinfo.value)


def test_the_real_package_is_verified_against_a_real_coordinator_shape(tmp_path):
    # The checked-in package, read only, against a coordinator carrying its exact current bytes:
    # this is the shape a release cut invokes, and it must come back clean.
    coordinator = make_coordinator(tmp_path / "mirror")
    for member, relative in build_release.coordinator_law_sources(
            build_release.load_coordinator_manifest(tmp_path / "mirror")).items():
        _write(coordinator / relative, (PACKAGE_DIR / member).read_bytes())
    result = build_release.verify_law_inputs(PYTHON_ROOT, coordinator)
    assert result["ok"] is True, result["failures"]


# ------------------------------------------------------------------------------ law input sync


def test_sync_rewrites_only_what_differs_and_is_idempotent(coordinator, tmp_path):
    stale = make_package_copy(tmp_path / "stale", law_bytes={
        member: (data if member == "LAW.md" else b"stale " + data)
        for member, data in COORDINATOR_BYTES.items()})
    changed = build_release.sync_law_inputs(stale, coordinator)
    assert sorted(entry["member"] for entry in changed) == sorted(
        member for member in build_release.LAW_INPUT_MEMBERS if member != "LAW.md")
    assert build_release.verify_law_inputs(stale, coordinator)["ok"] is True
    # Idempotent: a second sync has nothing to do and still verifies.
    assert build_release.sync_law_inputs(stale, coordinator) == []
    assert build_release.verify_law_inputs(stale, coordinator)["ok"] is True


def test_sync_reports_the_before_and_after_hash_of_each_rewrite(coordinator, tmp_path):
    stale = make_package_copy(tmp_path / "stale", law_bytes=dict(
        COORDINATOR_BYTES, **{"LAW.md": b"# Stale law\n"}))
    changed = build_release.sync_law_inputs(stale, coordinator)
    assert len(changed) == 1
    entry = changed[0]
    assert entry["member"] == "LAW.md"
    assert entry["before"] == build_release.sha256(b"# Stale law\n")
    assert entry["after"] == build_release.sha256(COORDINATOR_BYTES["LAW.md"])


def test_law_inputs_are_never_synced_implicitly():
    with pytest.raises(build_release.BuildError) as excinfo:
        build_release.main(["--coordinator-repo", "/nonexistent"])
    assert "never synced implicitly" in str(excinfo.value)


def test_sync_flags_require_a_coordinator_repo():
    for flag in ("--verify-law-inputs", "--sync-law-inputs", "--sync-release-contract"):
        with pytest.raises(build_release.BuildError) as excinfo:
            build_release.main([flag])
        assert "--coordinator-repo" in str(excinfo.value)


# -------------------------------------------------------------------------- release contract


def test_release_contract_identity_matches_a_matching_manifest(coordinator, package_copy):
    result = build_release.verify_law_inputs(package_copy, coordinator)
    identity = build_release.contract_identity(
        build_release.load_coordinator_manifest(coordinator))
    contract = json.loads(
        (package_copy / build_release.PACKAGE
         / build_release.RELEASE_CONTRACT_MEMBER).read_text(encoding="utf-8"))
    assert contract["product"] == identity["product"]
    assert identity["law"]["id"] == "%s.%s" % (
        identity["law"]["family"], identity["law"]["revision"])
    assert [entry["ok"] for entry in result["entries"] if entry["kind"] == "identity"] == \
        [True, True]


def test_release_contract_product_mismatch_is_named(tmp_path, package_copy):
    coordinator = make_coordinator(tmp_path / "moved-on",
                                   release=dict(MANIFEST_RELEASE, sequence=3))
    result = build_release.verify_law_inputs(package_copy, coordinator)
    assert result["failures"] == [f"{build_release.RELEASE_CONTRACT_MEMBER}:product"]
    entry = result["entries"][-2]
    assert entry["expected"]["sequence"] == 3 and entry["observed"]["sequence"] == 2


def test_release_contract_law_mismatch_is_named(tmp_path, package_copy):
    coordinator = make_coordinator(tmp_path / "new-law")
    manifest_path = coordinator / build_release.manifest_relative_path()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["law"]["revision"] = "v3"
    manifest_path.write_bytes(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
    result = build_release.verify_law_inputs(package_copy, coordinator)
    assert result["failures"] == [f"{build_release.RELEASE_CONTRACT_MEMBER}:law"]
    entry = result["entries"][-1]
    assert entry["expected"]["id"].endswith(".v3")


def test_sync_release_contract_rewrites_only_product_and_law(tmp_path, package_copy):
    coordinator = make_coordinator(tmp_path / "moved-on",
                                   release=dict(MANIFEST_RELEASE, sequence=3))
    contract_path = (package_copy / build_release.PACKAGE
                     / build_release.RELEASE_CONTRACT_MEMBER)
    before = json.loads(contract_path.read_text(encoding="utf-8"))
    rewritten = build_release.sync_release_contract(package_copy, coordinator)
    assert rewritten is not None and rewritten["after"]["product"]["sequence"] == 3
    after = json.loads(contract_path.read_text(encoding="utf-8"))
    assert set(after) == set(before)
    assert {key: value for key, value in after.items() if key not in ("product", "law")} == \
        {key: value for key, value in before.items() if key not in ("product", "law")}
    assert build_release.verify_law_inputs(package_copy, coordinator)["ok"] is True
    # Idempotent, and the file keeps its own serialization convention byte for byte.
    assert build_release.sync_release_contract(package_copy, coordinator) is None
    assert contract_path.read_bytes() == \
        (json.dumps(after, indent=2, sort_keys=True) + "\n").encode("utf-8")


def test_sync_release_contract_refuses_a_reformatted_contract(tmp_path, package_copy):
    coordinator = make_coordinator(tmp_path / "coord")
    contract_path = (package_copy / build_release.PACKAGE
                     / build_release.RELEASE_CONTRACT_MEMBER)
    contract_path.write_text(
        json.dumps(json.loads(contract_path.read_text(encoding="utf-8"))), encoding="utf-8")
    with pytest.raises(build_release.BuildError) as excinfo:
        build_release.sync_release_contract(package_copy, coordinator)
    assert "own convention" in str(excinfo.value)
