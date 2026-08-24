# SPDX-License-Identifier: Apache-2.0
"""D-1: ``setup`` must be enough to run ``preview-current-parent``.

THE DEFECT THESE TESTS PIN. The law publication seals exactly six code roots — five
``benchmark-v2`` subtrees plus ``coretex-memory``. The scoring child also needs
``benchmark-v2/kit`` (``self_check``/``dev_instances``) and ``benchmark-v2/integration``
(``portability_matrix``), and NEITHER is a sealed code root, so no law publication can ever carry
them. The shipped command gated on ``<CACHE>/benchmark-v2/kit/self_check.py`` and, when it was
absent, printed ``run sync-law`` — a remedy the user had already followed and that could never
work. The trees a stranger CAN reach are in the miner-kit tar ``setup`` already downloads and
hash-verifies, so that is where the two unsealed support trees come from.

The composition is PATH LAYERING with the sealed trees FIRST. That ordering is the whole safety
argument: the kit tar also ships older copies of ``frontier``/``scoring``/``miner_abi``, and a
preview that scored inside those would be a number the adjudicator never computes. The sealed
directory wins every name it defines; the kit tar only ever supplies names the seal does not.
"""
from __future__ import annotations

import json
import hashlib
import os
import tarfile
import textwrap

import pytest

from coretex_validator import preview as pv


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(textwrap.dedent(text))


def sealed_law_cache(tmp_path, *, marker="sealed"):
    """A law cache holding exactly what a real publication holds: the six sealed trees."""
    root = tmp_path / "law" / ("a" * 64)
    bench = root / "benchmark-v2"
    for subtree in pv.SEALED_BENCH_SUBTREES:
        _write(str(bench / subtree / "__init__.py"),
               f'SOURCE = "{marker}"\nGENERATOR_PROFILE_IDS = ["doc.tool.v1"]\n')
    _write(str(root / "coretex-memory" / "coretex_memory" / "__init__.py"), "\n")
    return {"root": str(root), "bench": str(bench),
            "coretex": str(root / "coretex-memory")}


def extracted_kit(tmp_path, *, with_integration=True, marker="kit-tar"):
    """The miner-kit tar as ``setup`` leaves it: extracted beside its ``.extracted`` marker."""
    packages = tmp_path / "packages"
    tree = packages / (".payload-" + marker)
    bench = tree / "benchmark-v2"
    _write(str(bench / "kit" / "__init__.py"), "\n")
    _write(str(bench / "kit" / "self_check.py"), "def _aggregate(rows, profile):\n    return {}\n")
    _write(str(bench / "kit" / "dev_instances.py"),
           'DEV_SEEDS = [11, 12]\nDEV_SCALES = ["small"]\n')
    if with_integration:
        _write(str(bench / "integration" / "__init__.py"), "\n")
        _write(str(bench / "integration" / "portability_matrix.py"),
               "def not_executed(reason, breadth=None):\n"
               "    return {'executed': False, 'ok': False, 'reason': reason}\n")
    # the kit tar ALSO ships older copies of the sealed trees — the layering must not pick them up
    for subtree in pv.SEALED_BENCH_SUBTREES:
        _write(str(bench / subtree / "__init__.py"),
               f'SOURCE = "{marker}"\nGENERATOR_PROFILE_IDS = ["stale.profile.v1"]\n')
    os.makedirs(packages, exist_ok=True)
    candidate = packages / ("candidate-" + marker + ".tar")
    with tarfile.open(candidate, "w") as archive:
        archive.add(bench, arcname="benchmark-v2")
    archive_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    final_tree = packages / (pv.KIT_TAR_PREFIX + archive_sha)
    final_archive = packages / (pv.KIT_TAR_PREFIX + archive_sha + ".tar")
    os.replace(tree, final_tree)
    os.replace(candidate, final_archive)
    tree_sha = pv.extraction_tree_sha256(str(final_tree))
    _write(str(final_tree / ".extracted"), json.dumps({
        "format": "coretex-validator.kit-extraction/v1",
        "archive_sha256": archive_sha, "tree_sha256": tree_sha,
    }))
    return {
        "packages_dir": str(packages), "bench": str(final_tree / "benchmark-v2"),
        "tree": str(final_tree), "archive": str(final_archive), "sha": archive_sha,
        "active": {
            "format": "coretex-validator.active-install/v1",
            "kit_manifest_hash": "1" * 64, "law_publication_root": "a" * 64,
            "miner_kit": {"filename": final_archive.name, "sha256": archive_sha,
                          "tree_sha256": tree_sha},
        },
    }


# --------------------------------------------------------------------------- #
# 1. law cache + kit tar composes into a runnable scorer
# --------------------------------------------------------------------------- #
def test_the_two_unsealed_support_trees_are_resolved_from_the_miner_kit_tar(tmp_path):
    law = sealed_law_cache(tmp_path)
    kit = extracted_kit(tmp_path)

    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
        packages_dir=kit["packages_dir"], active_install=kit["active"])

    assert resolution.ok is True
    assert resolution.missing_required == ()
    # kit + integration come from the TAR; the five sealed subtrees come from the CACHE
    assert resolution.sources["kit"] == kit["bench"]
    assert resolution.sources["integration"] == kit["bench"]
    for subtree in pv.SEALED_BENCH_SUBTREES:
        assert resolution.sources[subtree] == law["bench"]
    assert resolution.support_dirs == (kit["bench"],)
    assert resolution.kit_tars == (kit["sha"],)

    child = pv.LawTreeChild(bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
                            support_dirs=resolution.support_dirs)
    assert child.available() is True


def test_preview_uses_only_the_active_kit_not_a_lexically_first_old_cache(tmp_path):
    law = sealed_law_cache(tmp_path)
    old = extracted_kit(tmp_path, marker="old")
    current = extracted_kit(tmp_path, marker="current")
    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
        packages_dir=old["packages_dir"], active_install=current["active"])
    assert resolution.sources["kit"] == current["bench"]
    assert resolution.kit_tars == (current["sha"],)


def test_preview_refuses_a_mutated_active_extraction(tmp_path):
    law = sealed_law_cache(tmp_path)
    kit = extracted_kit(tmp_path)
    _write(os.path.join(kit["bench"], "kit", "self_check.py"), "MUTATED = True\n")
    with pytest.raises(pv.PreviewError, match="no longer match") as excinfo:
        pv.resolve_scoring_trees(
            bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
            packages_dir=kit["packages_dir"], active_install=kit["active"])
    assert excinfo.value.code == "KIT_BINDING_INVALID"


def test_a_law_cache_alone_cannot_provision_the_scorer_and_says_so_achievably(tmp_path):
    """The shipped refusal told the reader to run `sync-law`, which they had already done and
    which can never install `kit`. The achievable remedy names the miner-kit TAR."""
    law = sealed_law_cache(tmp_path)
    empty_packages = tmp_path / "packages"
    empty_packages.mkdir()

    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
        packages_dir=str(empty_packages))

    assert resolution.ok is False
    assert "kit" in resolution.missing_required
    child = pv.LawTreeChild(bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
                            support_dirs=resolution.support_dirs)
    assert child.available() is False

    with pytest.raises(pv.PreviewError) as excinfo:
        pv.require_scoring_trees(resolution)
    remedy = excinfo.value.remedy or ""
    assert "setup" in remedy and "miner-kit" in remedy
    # the unachievable remedy must be GONE: sync-law can never publish an unsealed tree
    assert "sync-law" not in remedy
    assert "sealed" in str(excinfo.value)


def test_the_canonical_current_kit_requires_the_integration_support_tree(tmp_path):
    law = sealed_law_cache(tmp_path)
    kit = extracted_kit(tmp_path, with_integration=False)
    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
        packages_dir=kit["packages_dir"], active_install=kit["active"])
    assert resolution.ok is False
    assert "integration" in resolution.missing_required
    with pytest.raises(pv.PreviewError, match="integration"):
        pv.require_scoring_trees(resolution)


def test_the_refusal_report_does_not_claim_the_law_is_used_and_missing_at_once(tmp_path):
    """D-1's second half: the shipped report said `law.used: true` with six trees listed while
    refusing "the pinned law trees are not provisioned". Both halves have to be sayable at once."""
    law = sealed_law_cache(tmp_path)
    empty_packages = tmp_path / "packages"
    empty_packages.mkdir()
    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
        packages_dir=str(empty_packages))

    report = resolution.as_dict()
    assert report["sealed_trees_present"] is True
    assert report["sufficient_for_scoring"] is False
    assert "kit" in report["missing_required"]
    assert report["unsealed_support_trees"] == list(pv.SUPPORT_BENCH_SUBTREES)


# --------------------------------------------------------------------------- #
# 2. the layering itself, proved by running the real child
# --------------------------------------------------------------------------- #
def test_the_sealed_trees_win_every_name_the_kit_tar_also_defines(tmp_path):
    """The kit tar carries an OLDER `generators`. Probe mode imports `generators` and
    `kit.dev_instances`; the profile ids must come from the SEALED tree and the dev seeds from
    the tar. Anything else is a mixed-tree score."""
    law = sealed_law_cache(tmp_path)
    kit = extracted_kit(tmp_path)
    resolution = pv.resolve_scoring_trees(
        bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
        packages_dir=kit["packages_dir"], active_install=kit["active"])
    child = pv.LawTreeChild(bench_v2_dir=law["bench"], coretex_dir=law["coretex"],
                            support_dirs=resolution.support_dirs, timeout=120)

    probe = child({"mode": "probe"})
    assert probe["profiles"] == ["doc.tool.v1"]          # sealed, not the tar's stale.profile.v1
    assert probe["dev_seeds"] == [11, 12]                # from the tar's kit/dev_instances.py
    assert probe["dev_scales"] == ["small"]


# --------------------------------------------------------------------------- #
# 3. the `integration` shim, mirroring kit/self_check.py's documented one
# --------------------------------------------------------------------------- #
def _run_portability_shim(tmp_path, *, breadth, with_integration):
    """Execute the child's portability source in a namespace whose sys.path we control."""
    import subprocess
    import sys

    stage = tmp_path / ("shim-" + ("with" if with_integration else "without"))
    if with_integration:
        _write(str(stage / "integration" / "__init__.py"), "\n")
        _write(str(stage / "integration" / "portability_matrix.py"),
               "def not_executed(reason, breadth=None):\n"
               "    return {'executed': False, 'ok': False, 'reason': reason,\n"
               "            'from': 'portability_matrix'}\n"
               "def run_matrix(breadth=None):\n"
               "    return {'executed': True, 'ok': True, 'breadth': breadth}\n")
    else:
        os.makedirs(str(stage), exist_ok=True)
    source = ("import sys, json\n"
              f"sys.path[:] = [{str(stage)!r}]\n"
              + pv.PORTABILITY_SHIM_SOURCE
              + f"\nprint(json.dumps(_local_portability({breadth!r})))\n")
    proc = subprocess.run([sys.executable, "-c", source], capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip())


def test_a_missing_integration_tree_is_not_executed_evidence_not_a_crash(tmp_path):
    """Defensive noncanonical seam: absence is never fabricated into portability success."""
    evidence = _run_portability_shim(tmp_path, breadth=None, with_integration=False)
    assert evidence["executed"] is False
    assert evidence["ok"] is False                       # FAIL CLOSED, never an assumed pass
    assert evidence["missing_module"] == "integration"
    assert evidence["reason_code"] == "portability_prerequisite_not_executed_locally"


def test_asking_for_portability_without_the_tree_still_refuses_rather_than_passing(tmp_path):
    evidence = _run_portability_shim(tmp_path, breadth="full", with_integration=False)
    assert (evidence["executed"], evidence["ok"]) == (False, False)
    assert evidence["breadth"] == "full"


def test_with_the_tree_present_the_pinned_matrix_is_the_authority(tmp_path):
    not_run = _run_portability_shim(tmp_path, breadth=None, with_integration=True)
    assert not_run["from"] == "portability_matrix"
    executed = _run_portability_shim(tmp_path, breadth="full", with_integration=True)
    assert executed == {"executed": True, "ok": True, "breadth": "full"}


# --------------------------------------------------------------------------- #
# 4. the command a stranger actually runs
# --------------------------------------------------------------------------- #
def test_the_cli_refuses_a_law_cache_only_host_with_the_achievable_remedy(tmp_path, capsys):
    """The clean-box command, end to end: sealed trees installed, no miner-kit tar."""
    from coretex_validator import cli

    law = sealed_law_cache(tmp_path)
    empty_packages = tmp_path / "packages"
    empty_packages.mkdir()
    module = tmp_path / "candidate.py"
    module.write_text("def make_hooks(context):\n    return None\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"capabilities": [], "objectives_targeted": []}))

    code = cli.main(["preview-current-parent", str(module), "--manifest", str(manifest),
                     "--profile", "doc.tool.v1", "--parent-root", "e" * 64,
                     "--artifact-dir", str(tmp_path / "cas"),
                     "--repo-root", law["root"], "--packages-dir", str(empty_packages),
                     "--law-cache", str(tmp_path / "empty-law-cache")])
    payload = json.loads(capsys.readouterr().out)

    assert code == 2
    assert payload["code"] == "SUPPORT_TREES_UNAVAILABLE"
    assert "setup" in payload["remedy"] and "miner-kit" in payload["remedy"]
    assert "sync-law" not in payload["remedy"]
    # THE INTERNAL CONSISTENCY D-1 asked for: the report says which half is present and which
    # half is missing, instead of refusing "the law trees" while listing them as installed.
    trees = payload["law"]["scoring_trees"]
    assert trees["sealed_trees_present"] is True
    assert trees["sufficient_for_scoring"] is False
    assert trees["missing_required"] == ["kit", "integration"]
