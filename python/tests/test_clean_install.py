# SPDX-License-Identifier: Apache-2.0
"""What a CLEAN INSTALLATION must be true of, asserted rather than claimed.

The package's headline property is that it needs nothing but the standard library. That claim is
worth exactly as much as the test that enforces it, because it decays silently: one convenience
import of ``requests`` in a helper and a validator's verdict starts depending on a wheel nobody
audited. So:

* :func:`test_declares_no_runtime_dependencies` reads ``pyproject.toml``;
* :func:`test_imports_nothing_outside_the_stdlib` walks every shipped module's imports and
  compares them against the standard library — a real check, not a grep for known names;
* :func:`test_a_fresh_interpreter_can_import_everything` proves the package is importable with
  the repo NOT on ``sys.path``, which is the actual clean-install condition.

The heavier proof — building a wheel, installing it into a fresh venv OUTSIDE the source tree and
replaying against a chain — lives in ``reproduce.sh``, because it needs a network and a chain and
must not be something ``pytest`` silently skips.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import sysconfig
import pathlib

import pytest

#: Resolved from the IMPORTED package, not from a path relative to this file. That is the whole
#: point: when `reproduce.sh` runs these tests they sit next to a throwaway venv and the package
#: under test is the one in site-packages. A path-relative constant would quietly re-target the
#: assertions at the checkout and the clean-install proof would prove nothing.
import coretex_validator as _pkg                                       # noqa: E402

PACKAGE_DIR = pathlib.Path(_pkg.__file__).resolve().parent
#: Source-tree only. An installed wheel has no pyproject, so the test that reads it SKIPS rather
#: than failing — "I could not check the manifest" is not "the manifest is wrong".
PYPROJECT = PACKAGE_DIR.parent / "pyproject.toml"

#: Modules this package is allowed to import. Everything here ships with CPython.
#: ``sys.stdlib_module_names`` is authoritative on 3.10+; the explicit set keeps the test
#: meaningful on 3.9, where that attribute does not exist.
_STDLIB_FALLBACK = {
    "abc", "argparse", "ast", "base64", "binascii", "collections", "copy", "dataclasses",
    "datetime", "decimal", "difflib", "enum", "functools", "hashlib", "hmac", "importlib", "io",
    "itertools", "json", "logging", "math", "os", "pathlib", "platform", "random", "re", "shutil",
    "signal", "socket", "string", "struct", "subprocess", "sys", "sysconfig", "tempfile",
    "textwrap", "threading", "time", "types", "typing", "unicodedata", "urllib", "uuid",
    "warnings", "zlib", "ctypes", "errno", "fcntl", "select", "traceback", "secrets",
    "tarfile",
}


def _stdlib_names() -> frozenset:
    names = getattr(sys, "stdlib_module_names", None)
    return frozenset(names) if names else frozenset(_STDLIB_FALLBACK)


def _shipped_modules():
    return sorted(p for p in PACKAGE_DIR.glob("*.py"))


def test_declares_no_runtime_dependencies():
    if not PYPROJECT.is_file():
        pytest.skip("no pyproject.toml beside an installed package; the equivalent property is "
                    "enforced at install time by `pip install --no-deps` in reproduce.sh")
    text = PYPROJECT.read_text(encoding="utf-8")
    assert "dependencies = []" in text, (
        "pyproject.toml must declare zero runtime dependencies; a validator whose verdict "
        "depends on a downloaded wheel has a supply-chain root it did not choose")


def test_the_wheel_build_backend_is_an_exact_recorded_toolchain():
    if not PYPROJECT.is_file():
        pytest.skip("the installed wheel contains products, not its source build manifest")
    text = PYPROJECT.read_text(encoding="utf-8")
    assert 'requires = ["setuptools==75.3.0", "wheel==0.44.0"]' in text
    assert 'license = {text = "Apache-2.0"}' in text
    assert "setuptools>=" not in text


@pytest.mark.parametrize("args", [["--law-mirror", "https://law.example"],
                                   ["--law-root", "a" * 64]])
def test_reproduce_refuses_half_of_a_law_source_tuple_before_building(args):
    if not PYPROJECT.is_file():
        pytest.skip("reproduce.sh is a source-tree qualification command")
    script = PYPROJECT.parent / "reproduce.sh"
    result = subprocess.run(["bash", str(script), *args], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 2
    assert "must be supplied together" in result.stderr
    assert "build a wheel" not in result.stdout


def test_reproduce_normalizes_archive_modes_and_compares_two_independent_builds():
    if not PYPROJECT.is_file():
        pytest.skip("reproduce.sh is a source-tree qualification command")
    text = (PYPROJECT.parent / "reproduce.sh").read_text(encoding="utf-8")
    assert "tar.umask=0022" in text
    assert "chmod -R u=rwX,go=rX" in text
    assert 'CANONICAL_SOURCE_B="$WORK/source-b"' in text
    assert 'cmp "$WHEEL" "$WHEEL_B"' in text


@pytest.mark.parametrize("module_path", _shipped_modules(), ids=lambda p: p.name)
def test_imports_nothing_outside_the_stdlib(module_path):
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    stdlib = _stdlib_names()
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:                                # relative: our own package
                continue
            roots = [(node.module or "").split(".")[0]]
        else:
            continue
        for root in roots:
            if root and root not in stdlib and root != "coretex_validator":
                offenders.append(root)
    assert not offenders, (
        f"{module_path.name} imports non-stdlib module(s) {sorted(set(offenders))}. If this is "
        "genuinely needed, it is a change to what the package PROMISES, not a detail")


def test_the_curve_module_is_only_reachable_from_a_signature_check():
    """secp256k1 must never be a module-scope import of the reproduction path.

    ``keccak256`` exists so a validator needs no third-party crypto; ``secp256k1`` was added for
    ONE purpose — recovering a signer to authenticate transport and to re-check the coordinator's
    EIP-712 signature. Reproduction of the unsigned snapshot payload must not require it, so no
    module may import it at top level except through a deferred import inside the function that
    actually recovers a key.
    """
    stdlib = _stdlib_names()
    for module_path in _shipped_modules():
        if module_path.name in ("secp256k1.py", "__init__.py"):
            continue
        tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
        for node in ast.iter_child_nodes(tree):           # MODULE SCOPE only
            if isinstance(node, ast.ImportFrom) and node.level:
                names = [alias.name for alias in node.names]
                assert "secp256k1" not in names, (
                    f"{module_path.name} imports secp256k1 at module scope; import it inside the "
                    "function that recovers a signer so the reproduction path stays curve-free")
    del stdlib


def test_a_fresh_interpreter_can_import_everything_from_outside_the_repo():
    """Importable with the repo NOT on sys.path — the actual clean-install condition."""
    package_root = str(PACKAGE_DIR.parent)
    modules = [p.stem for p in _shipped_modules() if p.stem != "__init__"]
    script = (
        "import importlib, sys\n"
        f"sys.path.insert(0, {package_root!r})\n"
        f"for name in {modules!r}:\n"
        "    importlib.import_module('coretex_validator.' + name)\n"
        "print('imported', len(sys.modules))\n")
    # cwd is deliberately OUTSIDE the source tree: a package that only imports from its own
    # directory is not installed, it is merely nearby.
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                            cwd=os.path.dirname(sysconfig.get_paths()["stdlib"]))
    assert result.returncode == 0, result.stderr
    assert "imported" in result.stdout


def test_the_cli_entry_point_resolves():
    from coretex_validator import cli

    parser = cli.build_parser()
    args = parser.parse_args(["topics"])
    assert callable(args.func)
    # `reproduce` is the command the external agent runs; its required arguments are part of the
    # published interface and must not drift silently.
    reproduce = parser.parse_args(["reproduce", "--release", "r.json", "--rpc", "http://x"])
    assert reproduce.release == "r.json" and reproduce.rpc == "http://x"
    production = parser.parse_args(["reproduce", "--rpc", "http://x"])
    from coretex_validator.release import DEFAULT_PRODUCTION_RELEASE_URL
    assert production.release == DEFAULT_PRODUCTION_RELEASE_URL


def test_the_counter_resource_law_ships_with_the_package():
    """It is DATA a validator cannot re-derive, so it must be inside the wheel.

    A validator that had to be handed the law could be handed a different one, and the resource
    half of the Pareto rule would then be whatever the person running it wanted.
    """
    from coretex_validator import eval_artifact as ea

    # Loading it IS the check — it resolves relative to the installed module, so a wheel that
    # omitted the data file fails here. The path assertion is only a nicer error message.
    law = ea.load_counter_resource_law()
    assert law["format"] == "coretex.counter-resource-law.v1"
    assert (PACKAGE_DIR / "COUNTER_RESOURCE_LAW.v1.json").is_file(), (
        f"the law did load, but not from {PACKAGE_DIR} — the package under test is not the one "
        "this test located")


def test_the_exact_parent_authority_ships_with_the_package():
    """Historical replay authority is data and must not depend on a sibling source checkout."""
    from coretex_validator import parent_execution as pe

    assert pe.PRODUCTION_REFERENCE_RELEASE_ROOTS
    assert pe.PRE_EXACT_PARENT_CODE_ROOT_SETS
    assert (PACKAGE_DIR / "EXACT-PARENT-AUTHORITY.production.json").is_file()
