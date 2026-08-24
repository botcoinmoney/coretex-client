# SPDX-License-Identifier: Apache-2.0
"""D-4: ``verify-receipt`` must be able to verify an EXACT-PARENT receipt.

WHAT WAS BROKEN. With every object present and the law cache complete, ``verify-receipt`` on the
live epoch-184 receipt refused with ``code: incumbent_execution_required``, ``stage: evaluate``,
``outcome: FAIL``, exit 1.

``benchmark-v2/validator/replay.py`` requires ``payload["incumbent_execution"]`` whenever the
report's ``incumbent`` is the EXACT five-field identity, and refuses without it. The CLI called
``sandbox.execute(receipt_wrapper=…, artifact=…)`` and never passed a third argument; no flag
could supply one. The only caller that ever resolved it was ``replay.replay_advance``, reachable
only through the discovery lane D-2 shows could not see the chain. Exact-parent receipts are
0.4.3's headline feature, so on the shipped release there was no command-line route to verifying
one at all.

TWO FIXES, ONE COMMAND. The CLI now resolves the incumbent itself —
``parent_execution.fetch_parent_execution`` over the artifact store, following
frontier -> composition -> release -> module and re-hashing every hop, the same public resolution
``replay_advance`` and ``preview-current-parent`` use — and it classifies an object it cannot
fetch as BACKLOG rather than FAIL. In this client's own vocabulary FAIL/exit-1 means A RECEIPT DID
NOT REPRODUCE; a CI wired to the documented contract would have raised a refutation alarm against
a healthy production receipt because an object was not published.
"""
from __future__ import annotations

import json
import os
import shutil

import pytest

from coretex_validator import cli
from coretex_validator import eval_artifact as ea
from coretex_validator import law as law_mod
from coretex_validator import replay as rp


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
CAS = os.path.join(FIXTURES, "e184-cas")
REPORT_ROOT = "8471202b8a272a1326170d3a7299ec418a03c2b57a0229a562e97ffbf908d83c"
ARTIFACT_ROOT = "5ba4435ff46e73e4ff1dc568e96c11bed44369e0db98a3fe21e6cba7a63ed60a"
PARENT_ROOT = "79da014ab4153c1331657f4a5c04bbc69384bf2626d509ac83e71aa578f5a2f6"
#: The parent's own release root, from the epoch-184 report's exact incumbent identity.
PARENT_RELEASE_ROOT = "bc0f0597a2f446c922ec5615318d47ed32b497598e73a5c1279eee3106a27466"
#: The parent's own module bytes — the leaf of the resolution, and the object dropped below to
#: produce a genuine availability gap.
PARENT_MODULE_ROOT = "233350acd949807c9c1a30ca15247fdbfe57ae96a71d1829027dccd6bcdf4f75"


def report_body():
    with open(os.path.join(CAS, REPORT_ROOT), "r", encoding="utf-8") as handle:
        return json.load(handle)


def run(argv, capsys):
    code = cli.main(argv)
    return code, json.loads(capsys.readouterr().out)


def verify_receipt(capsys, *extra, cache="/tmp/coretex-no-such-law-cache"):
    return run(["verify-receipt", os.path.join(CAS, REPORT_ROOT),
                "--artifact", os.path.join(CAS, ARTIFACT_ROOT),
                "--law-cache", cache, *extra], capsys)


# --------------------------------------------------------------------------- #
# 0. the fixture really is an exact-parent receipt
# --------------------------------------------------------------------------- #
def test_the_epoch_184_report_carries_an_exact_parent_incumbent():
    """If this ever stops being true the rest of the file is testing nothing."""
    body = report_body()
    assert body["format"] == ea.EVAL_REPORT_FORMAT
    assert frozenset(body["incumbent"]) == frozenset(ea.INCUMBENT_EXACT_FIELDS)
    assert body["incumbent"]["exec"] == "candidate_module"
    assert body["incumbent"]["release_root"] == PARENT_RELEASE_ROOT


# --------------------------------------------------------------------------- #
# 1. the CLI resolves the incumbent instead of demanding it
# --------------------------------------------------------------------------- #
class _CapturingSandbox(rp.CandidateSandbox):
    """Stands in for the pinned child so the resolution can be observed without a law cache."""

    name = "capturing-sandbox(TEST DOUBLE)"
    consensus_grade = False

    def __init__(self):
        self.calls = []

    def available(self):
        return True

    def execute(self, *, receipt_wrapper, artifact, incumbent_execution=None):
        self.calls.append(incumbent_execution)
        return {"reproduced": True, "code": None, "reason": "stub", "receipt_hash": "ab" * 32,
                "body": None, "sandbox": self.name, "networkless": True, "stage": "done"}


def test_the_cli_resolves_the_exact_parent_execution_from_the_store(monkeypatch, capsys):
    """The whole defect: this third argument was never passed and no flag could supply it.

    Resolved for real, from the twelve REAL published objects of the epoch-184 advance and its
    parent — frontier -> composition -> release -> module, every hop re-hashed by
    `parent_execution`. Only the pinned child is stubbed, because running it needs a law cache and
    wasmtime; the resolution under test is the part that did not exist.
    """
    sandbox = _CapturingSandbox()
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)

    code, payload = verify_receipt(capsys, "--artifacts", CAS)

    assert payload["incumbent"]["resolved"] is True
    assert payload["incumbent"]["kind"] == "exact_parent"
    assert payload["incumbent"]["parent_frontier_root"] == PARENT_ROOT
    assert payload["incumbent"]["release_root"] == PARENT_RELEASE_ROOT
    assert payload["incumbent"]["target_profile"] == "doc.tool.v1"

    # the argument the shipped CLI never passed, carrying the REAL parent module
    assert len(sandbox.calls) == 1
    execution = sandbox.calls[0]
    assert execution["exec"] == "candidate_module"
    assert execution["release_root"] == PARENT_RELEASE_ROOT
    assert execution["module"]["sha256"] == report_body()["incumbent"]["module_sha256"]
    assert payload["outcome"] == "PASS"
    assert code == 0


def test_a_reference_arm_receipt_keeps_todays_path(tmp_path, monkeypatch, capsys):
    """A historical (three-field) incumbent must NOT be handed an execution: the frozen replayer
    refuses one with `incumbent_execution_unexpected`."""
    from coretex_validator import parent_execution as pe

    historical = dict(report_body())
    historical["incumbent"] = {k: historical["incumbent"][k] for k in ea.INCUMBENT_FIELDS}
    path = tmp_path / "historical-report.json"
    path.write_text(json.dumps(historical))

    sandbox = _CapturingSandbox()
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)
    monkeypatch.setattr(pe, "fetch_parent_execution", lambda **kwargs: pytest.fail(
        "a historical receipt must not resolve an exact parent"))

    code, payload = run(["verify-receipt", str(path), "--artifact",
                         os.path.join(CAS, ARTIFACT_ROOT), "--artifacts", CAS,
                         "--law-cache", "/tmp/coretex-no-such-law-cache"], capsys)
    assert sandbox.calls == [None]
    assert payload["incumbent"]["resolved"] is False
    assert payload["incumbent"]["kind"] == "reference_or_historical"
    assert code == 0


# --------------------------------------------------------------------------- #
# 2. an object that is not published is a BACKLOG, never a refutation
# --------------------------------------------------------------------------- #
@pytest.fixture()
def cas_without_the_parent_module(tmp_path):
    """The REAL publication surface minus ONE object — the shape an incomplete mirror has."""
    partial = tmp_path / "partial-cas"
    shutil.copytree(CAS, str(partial))
    os.remove(os.path.join(str(partial), PARENT_MODULE_ROOT))
    return str(partial)


def test_an_unresolvable_incumbent_backlogs_rather_than_refuting(cas_without_the_parent_module,
                                                                 monkeypatch, capsys):
    """One object of the parent graph is not served. That is unresolved work, not "the chain is
    lying" — and the shipped command printed exactly this situation as FAIL / exit 1."""
    sandbox = _CapturingSandbox()
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)

    code, payload = verify_receipt(capsys, "--artifacts", cas_without_the_parent_module)

    assert payload["outcome"] == "BACKLOG"
    assert payload["code"] == "PARENT_EXECUTION_UNAVAILABLE"
    assert payload["incumbent"]["parent_frontier_root"] == PARENT_ROOT
    assert sandbox.calls == []                       # nothing was executed against a guess
    assert code == 0
    assert "not published" in payload["reason"]


def test_require_complete_turns_that_backlog_into_exit_one(cas_without_the_parent_module,
                                                           monkeypatch, capsys):
    sandbox = _CapturingSandbox()
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)
    code, payload = verify_receipt(capsys, "--artifacts", cas_without_the_parent_module,
                                   "--require-complete")
    assert payload["outcome"] == "BACKLOG"
    assert code == 1


def test_a_resolved_parent_that_is_not_the_reports_incumbent_is_a_refutation(monkeypatch,
                                                                             capsys):
    """A refutation is what exit 1 is FOR. The resolved parent identity disagreeing with the one
    the signed report binds is exactly that, and it must not be softened into a backlog."""
    from coretex_validator import parent_execution as pe

    sandbox = _CapturingSandbox()
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)
    monkeypatch.setattr(pe, "fetch_parent_execution", lambda **kwargs: {
        "exec": "candidate_module", "id": "ab" * 32, "candidate_hash": "cd" * 32,
        "release_root": "ab" * 32, "release_manifest": {},
        "module": {"source": "x = 1\n", "sha256": "ef" * 32}})
    code, payload = verify_receipt(capsys, "--artifacts", CAS)
    assert payload["outcome"] == "FAIL"
    assert payload["code"] == "PARENT_EXECUTION_MISMATCH"
    assert sandbox.calls == []
    assert code == 1


# --------------------------------------------------------------------------- #
# 3. availability codes coming back FROM the sandbox
# --------------------------------------------------------------------------- #
class _RefusingSandbox(_CapturingSandbox):
    def __init__(self, code, stage):
        super().__init__()
        self._code = code
        self._stage = stage

    def execute(self, *, receipt_wrapper, artifact, incumbent_execution=None):
        self.calls.append(incumbent_execution)
        return {"reproduced": False, "code": self._code, "reason": "stub refusal",
                "receipt_hash": None, "body": None, "sandbox": self.name, "networkless": True,
                "stage": self._stage}


@pytest.mark.parametrize("code,stage", [("code_root_unavailable", "code_roots"),
                                        ("incumbent_execution_required", "evaluate")])
def test_a_missing_input_is_a_backlog_not_the_documented_refutation_code(code, stage, monkeypatch,
                                                                        capsys):
    """D-3/D-4's shared reporting fault. `verify-receipt` printed `outcome: FAIL`, exit 1 — which
    this client's own vocabulary defines as "a receipt did not reproduce" — because a law FILE was
    never published. BACKLOG/exit-0 is the outcome that means "I could not check that", and the
    sibling `SandboxUnavailable` branch already used it."""
    from coretex_validator import parent_execution as pe

    sandbox = _RefusingSandbox(code, stage)
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)
    monkeypatch.setattr(pe, "fetch_parent_execution", lambda **kwargs: {
        "exec": "candidate_module", "id": PARENT_RELEASE_ROOT, "candidate_hash": "cd" * 32,
        "release_root": PARENT_RELEASE_ROOT, "release_manifest": {},
        "module": {"source": "x = 1\n", "sha256": "ef" * 32}})
    monkeypatch.setattr(pe, "compact_identity", lambda execution: report_body()["incumbent"])

    exit_code, payload = verify_receipt(capsys, "--artifacts", CAS)
    assert payload["outcome"] == "BACKLOG"
    assert payload["replay"]["code"] == code
    assert exit_code == 0
    assert code in rp.AVAILABILITY_REPLAY_CODES


def test_a_real_divergence_is_still_a_refutation(monkeypatch, capsys):
    from coretex_validator import parent_execution as pe

    sandbox = _RefusingSandbox("eval_report_root_divergence", "rebuild")
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)
    monkeypatch.setattr(pe, "fetch_parent_execution", lambda **kwargs: {
        "exec": "candidate_module", "id": PARENT_RELEASE_ROOT, "candidate_hash": "cd" * 32,
        "release_root": PARENT_RELEASE_ROOT, "release_manifest": {},
        "module": {"source": "x = 1\n", "sha256": "ef" * 32}})
    monkeypatch.setattr(pe, "compact_identity", lambda execution: report_body()["incumbent"])
    exit_code, payload = verify_receipt(capsys, "--artifacts", CAS)
    assert payload["outcome"] == "FAIL"
    assert exit_code == 1


# --------------------------------------------------------------------------- #
# 4. the store, and the D-3 posture file coming from a synced cache
# --------------------------------------------------------------------------- #
def test_the_artifact_store_defaults_to_the_directory_holding_the_receipt(monkeypatch, capsys):
    """The documented invocation names the receipt by its path inside the CAS. Requiring a
    separate --artifacts for a directory the command was already pointed into would be a second
    way to say the same thing."""
    sandbox = _CapturingSandbox()
    monkeypatch.setattr(rp, "BenchmarkV2Sandbox", lambda **kwargs: sandbox)
    code, payload = verify_receipt(capsys)                    # no --artifacts at all
    assert payload["artifacts"]["source"] == CAS
    assert payload["incumbent"]["resolved"] is True
    assert code == 0


def test_the_posture_file_is_taken_from_a_SYNCED_law_cache(tmp_path):
    """D-3 and D-4 meet here: the seventh sealed root arrives through `sync-law`, and the run that
    replays a receipt is pinned to the cache that carries it — no loose fixture on the side.

    Run in a SUBPROCESS on purpose. `law.activate` refuses pins applied after
    `coretex_validator.replay` has been imported (they are read at import time and setting them
    later is a no-op that looks like it worked), so an in-process assertion here would be testing
    a code path the real CLI never takes.
    """
    import subprocess
    import sys

    from test_law_sync import build_publication, write_set

    publication_root, manifest_bytes, objects = build_publication()
    mirror = write_set(str(tmp_path / "mirror"), publication_root, manifest_bytes, objects,
                       layout="flat-cas")
    cache_dir = str(tmp_path / "law-cache")
    cache = law_mod.sync_law(publication_root, mirror=mirror, cache_dir=cache_dir)

    env = {k: v for k, v in os.environ.items() if k not in law_mod.ENV_PINS}
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-m", "coretex_validator.cli", "verify-receipt",
         os.path.join(CAS, REPORT_ROOT), "--artifact", os.path.join(CAS, ARTIFACT_ROOT),
         "--artifacts", CAS, "--law-cache", cache_dir],
        capture_output=True, text=True, env=env, timeout=300)
    payload = json.loads(proc.stdout)

    assert payload["law"]["used"] is True
    assert payload["law"]["files"] == {law_mod.POSTURE_RELPATH: cache.files[
        law_mod.POSTURE_RELPATH]}
    # the path `receipt.py::code_roots` will open is inside the cache the run activated, and the
    # run's own repo-root pin is that cache
    posture = os.path.join(payload["law"]["env"][law_mod.ENV_REPO_ROOT],
                           *law_mod.POSTURE_RELPATH.split("/"))
    assert os.path.isfile(posture)
    # the synthetic trees are not a real benchmark-v2, so this stops at the sandbox — as a
    # BACKLOG, exit 0, which is the point: an environment gap is never a refutation
    assert payload["outcome"] == "BACKLOG"
    assert proc.returncode == 0
