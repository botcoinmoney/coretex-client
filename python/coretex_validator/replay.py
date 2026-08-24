# SPDX-License-Identifier: Apache-2.0
"""The CONSENSUS-CRITICAL public replay of a V5 memory-frontier advance (Cut V5-E, §17.236).

No secret corpus. No coordinator key. No hosted-model API. §17.236 states the walk verbatim and
this module executes it, in this order, fail-closed at every step:

    read confirmed event -> fetch parent frontier manifest + verify its root -> apply
    transitionBytes -> reproduce newFrontierRoot and compare -> fetch the eval artifact by the
    event's evalReportHash -> rehash -> verify EVERY binding -> re-derive the fresh selection from
    the committed entropy -> execute the candidate in the pinned networkless sandbox -> recompute
    utility / safety / rendered cost / fuel / storage -> confirm it beat the EXACT parent
    incumbent under the frozen law.

THREE OUTCOMES. Every stage resolves to PASS, FAIL or BACKLOG (``backlog.Outcome``). A binding
that was reproduced and DISAGREED is a FAIL. A binding that could not be REACHED — the artifact is
unpublished, a manifest is unfetchable, the pinned sandbox is not on this host, the oracle screen
needs the frozen generators — is a BACKLOG entry, which is neither a pass nor a fail. There is no
flag anywhere in this module that converts an unreachable binding into a pass.

>>> THE V4 DEAD-PATH DEFECT THIS CUT REGISTERS AND DOES NOT REPEAT <<<

    ``replayCoreTexFromLogs`` (``packages/coretex/src/replay/coretex-registry.ts``) declares an
    ``expectedHiddenSeedCommit`` option and a ``HIDDEN_SEED_COMMIT_MISMATCH`` result code, and
    NEVER READS EITHER. Verified in BOTH the source and the shipped ``dist`` build: the option is
    in the ``opts`` type (src line 173, dist ``.d.ts`` line 74), the code is in the result union
    (src line 148, dist ``.d.ts`` line 55), ``resolveEpochPins`` does not carry the field, and no
    statement in the function body references ``opts.expectedHiddenSeedCommit`` or returns that
    code. Two live callers PASS the value in good faith — ``validator-sync-cli.ts:1831``
    (``expectedHiddenSeedCommit: chain.hiddenSeedCommit``) and ``replay-cli.ts:174``. The net
    effect is a binding that every caller believes is enforced and that nothing enforces: a
    replay whose epoch entropy commitment disagreed with the chain would report ``ok: true``.

    V5's replay ACTUALLY CHECKS its epoch commit binding. ``EpochPins.entropy_commitment`` is
    REQUIRED (it is read from the confirmed ``EpochCommitSet`` log), it is passed to
    ``eval_artifact.verify_artifact`` as ``expected_entropy_commitment``, the artifact's commitment
    must equal it, and the revealed secret must OPEN it under
    ``keccak256(abi.encodePacked(bytes32 secret))``. Production artifacts intentionally omit that
    opening during the live epoch; replay rehashes them and records a BACKLOG until the confirmed
    ``EpochSecretRevealed`` supplies it. Historical artifacts that embed ``revealed_secret`` keep
    working, and when both forms are available they must be byte-identical. A missing commitment
    pin or unavailable opening is a BACKLOG entry, never a skipped check.

    The V4 defect is registered as data in :data:`V4_DEAD_PATH_DEFECT` so it lands in the PRE_V5_ARM
    packet rather than living only in a comment. Fixing V4 is a canonical-``/root/coretex`` change
    and is explicitly OUT of this cut's scope (offline V5 lane only).

WHAT THIS MODULE ADDS OVER V5-C. V5-C's ``verify_selection_walk`` proves every recorded case sits
at its claimed walk index, and says plainly that it cannot prove no legitimate index was SKIPPED,
because a skip is legitimate only for a burned instance or one that fails the G6b
oracle-cleanliness screen, and that screen is not a pure function. :func:`verify_selection_complete`
closes it: for every index strictly between two recorded steps it re-derives ``(seed, scale)`` and
demands a REASON the walk stepped past it — burned, already chosen, held by the gate walk, or
oracle-dirty per the screen. An index with no such reason is a cherry-picked walk and FAILS. The
screen needs the frozen generators + runtime, so it runs in a CHILD INTERPRETER (the
``build_genesis.materialize_signed_composition`` pattern: ``benchmark-v2`` ships its own package
named ``frontier`` and this lane's module is also called ``frontier``; the two must never sit on
one ``sys.path``). No screen -> BACKLOG, never a pass.

HAIKU / EXTERNAL-MODEL EVIDENCE IS REPORTED SEPARATELY. :func:`canary_evidence` returns an
auxiliary block with ``consensus_critical: false`` and ``external_model_attestation: true``. It is
computed AFTER the deterministic verdict, is carried in ``ReplayResult.auxiliary``, and is
structurally incapable of changing ``outcome``/``code``: :func:`replay_advance` asserts that the
deterministic verdict derived from the canary-free artifact equals the one derived from the
artifact as given, and every deterministic stage reads ``eval_artifact.strip_canary`` inputs where
a canary could otherwise be observed. A canary that is absent, that fails, or whose bindings are
wrong yields the identical deterministic verdict — which is exactly §17.236's rule that an
external model "creates no promotion eligibility and MUST NOT silently deny a deterministically
earned promotion".

SEAM (ledger §17.238)
---------------------
SEAM:            NOT the coordinator. This module runs in a PUBLIC VALIDATOR process, and its
                 attach point is the pair of default constructors an operator supplies to
                 :func:`replay_advance` (:718): :func:`default_oracle_screen` (:297 ->
                 :class:`ChildInterpreterOracleScreen`, :230) and :func:`default_sandbox` (:553
                 -> :class:`BenchmarkV2Sandbox`, :493). Everything else it touches is already a
                 port: ``publication.ContentStore``, ``dispatch.PinResolver``, ``Screen``,
                 ``CandidateSandbox``, ``signature_verifier``, ``sealed_transcript``.
HOST PREREQUISITE (discover it HERE, not at the first BACKLOG): both defaults shell a CHILD
                 interpreter over the frozen ``benchmark-v2`` and ``coretex-memory`` trees that
                 sit beside ``v5/`` in this repo. A process that has ``v5/`` alone can call this
                 module, and every stage that needs them will honestly report BACKLOG.
MINIMAL DIFF:    ``replay_advance(event, store=…, pins=…, screen=default_oracle_screen(),
                 sandbox=default_sandbox())``. No internals are edited, and there is no flag that
                 turns an unreachable binding into a pass — ``allow_test_doubles`` (default
                 False) only decides whether a self-declared non-consensus-grade double produces
                 a BACKLOG or is allowed to drive downstream stages in a test.
REVENDOR NEEDED: NO. Nothing here imports ``@botcoin/coretex``, ``/root/coretex``, ``vendor/`` or
                 ``node_modules/``; the V4 dead-path defect this module registers
                 (:data:`V4_DEAD_PATH_DEFECT`) is recorded as DATA for the packet precisely so
                 that fixing it stays a separate, canonical decision.
ARM:             none of its own — a validator is not the coordinator, and off-by-default is
                 structural rather than env-gated: no screen and no sandbox means BACKLOG.
REMOVE:          stop calling it. The only thing it can leave behind is the backlog journal
                 (``backlog.FileBacklog``), a directory the caller names.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections import abc
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple


from . import authority_law as al
from . import eval_artifact as ea
from . import frontier as fr
from . import parent_execution as parent_exec
from . import publication as pub

from . import backlog as bl
from . import dispatch as dp
from . import sync as sy

REPLAY_RESULT_FORMAT = "coretex.memory-frontier.v1/replay-result/v1"

# --------------------------------------------------------------------------- #
# The registered V4 defect (evidence, not a comment)
# --------------------------------------------------------------------------- #
V4_DEAD_PATH_DEFECT: Dict[str, Any] = {
    "id": "V4-REPLAY-DEAD-HIDDEN-SEED-COMMIT",
    "component": "packages/coretex/src/replay/coretex-registry.ts::replayCoreTexFromLogs",
    "severity": "unenforced-binding",
    "finding": "replayCoreTexFromLogs accepts expectedHiddenSeedCommit and declares "
               "HIDDEN_SEED_COMMIT_MISMATCH but never reads the option and never returns the "
               "code; resolveEpochPins does not carry the field either. Callers pass it in good "
               "faith, so an epoch-commit divergence replays as ok:true.",
    "verified_in": ["src/replay/coretex-registry.ts (opts line 173, code union line 148)",
                    "dist/replay/coretex-registry.d.ts (opts line 74, code union line 55)",
                    "dist/replay/coretex-registry.js (no reference in the emitted body)"],
    "live_callers_passing_it": ["src/validator-sync-cli.ts:1831", "src/replay-cli.ts:174"],
    "v5_disposition": "V5 replay REQUIRES EpochPins.entropy_commitment, passes it to "
                      "verify_artifact as expected_entropy_commitment, requires the revealed "
                      "secret to open it under keccak256(abi.encodePacked(bytes32 secret)), and "
                      "cross-checks the chain-revealed secret when EpochSecretRevealed is in the "
                      "window. A missing commitment pin is a BACKLOG entry, never a skip.",
    "out_of_scope_here": "Repairing V4 is a canonical /root/coretex change; this cut is the "
                         "offline V5 lane only (§17.236 AUTHORIZED scope).",
}

# --------------------------------------------------------------------------- #
# V5-C entropy expansion, re-implemented and CROSS-CHECKED (hard cross-cut requirement)
# --------------------------------------------------------------------------- #
#: The V5 entropy expansion domain. Declared here INDEPENDENTLY of ``eval_artifact`` so that the
#: two implementations can be compared rather than sharing one constant by accident.
ENTROPY_DOMAIN = "coretex.memory-frontier/entropy/v1"
ENTROPY_LABELS: Tuple[str, ...] = ("gate", "confirm")

if ENTROPY_DOMAIN != ea.ENTROPY_DOMAIN:                        # pragma: no cover - fail closed
    raise RuntimeError(
        f"entropy domain drift: validator uses {ENTROPY_DOMAIN!r}, V5-C uses "
        f"{ea.ENTROPY_DOMAIN!r}. §17.236 requires V5-D and V5-E to implement the expansion "
        "IDENTICALLY; a change is a NEW domain, never a silent reinterpretation.")
if ENTROPY_LABELS != tuple(ea.SELECTION_LABELS):               # pragma: no cover - fail closed
    raise RuntimeError(
        f"selection label drift: {ENTROPY_LABELS} vs V5-C {tuple(ea.SELECTION_LABELS)}")


class EntropyDomainDriftError(Exception):
    """The validator's expansion and V5-C's disagree. Nothing may proceed on divergent entropy."""


def expand_entropy(*, revealed_secret: str, epoch: int, parent_frontier_root: str,
                   label: str) -> str:
    """``sha256(DOMAIN | label | secret | epoch | parent_frontier_root)`` — V5 spec §7.2.

    Written out here rather than delegated, because §17.236 makes the identity of this derivation
    a cross-cut requirement between V5-C, V5-D and V5-E. The result is then compared BYTE FOR BYTE
    against :func:`eval_artifact.derive_entropy_value`; a divergence raises
    :class:`EntropyDomainDriftError` instead of quietly preferring one implementation. Two
    implementations that must agree, and an assertion that they do, is the only version of
    "implement it identically" that can fail loudly.
    """
    fr.check_root(revealed_secret, "revealed_secret")
    fr.check_root(parent_frontier_root, "parent_frontier_root")
    fr.check_epoch(epoch)
    if label not in ENTROPY_LABELS:
        raise EntropyDomainDriftError(
            f"entropy label must be one of {ENTROPY_LABELS}, got {label!r}")
    preimage = "|".join((ENTROPY_DOMAIN, label, revealed_secret, str(epoch),
                         parent_frontier_root)).encode("utf-8")
    value = hashlib.sha256(preimage).hexdigest()
    reference = ea.derive_entropy_value(revealed_secret=revealed_secret, epoch=epoch,
                                        parent_frontier_root=parent_frontier_root, label=label)
    if value != reference:
        raise EntropyDomainDriftError(
            f"the validator's {ENTROPY_DOMAIN} expansion derives {value} for label {label!r}, "
            f"V5-C derives {reference}. The two MUST be byte-identical (§17.236 cross-cut); "
            "replay stops rather than choosing one.")
    return value


# --------------------------------------------------------------------------- #
# The oracle-cleanliness screen (G6b) — what completes the selection check
# --------------------------------------------------------------------------- #
class OracleScreenUnavailable(Exception):
    """The screen could not run. Always a BACKLOG entry, never a pass and never a fail."""


#: ``screen(profile_id, seed, scale) -> bool``. Must be PURE and deterministic (select.py §G6b).
Screen = Callable[[str, int, str], bool]

#: WHERE THE DETERMINISTIC-ADMISSION TREES COME FROM IN A PUBLIC INSTALLATION.
#:
#: In the coordinator tree these were sibling directories of ``v5/``. A public validator has no
#: such sibling: ``benchmark-v2`` and ``coretex-memory`` live inside the PRIVATE
#: ``botcoin-coordinator`` repository and are not published anywhere a clean machine can fetch
#: them from. That is a FINDING, not a packaging inconvenience — see
#: ``docs/V5-RIG-VALIDATOR.md`` "Non-public dependencies". It is surfaced honestly rather than
#: papered over: with no trees configured, :class:`BenchmarkV2Sandbox` and
#: :class:`ChildInterpreterOracleScreen` report themselves UNAVAILABLE and every replay that
#: reaches them records a BACKLOG entry. A backlog is the correct outcome for "this host cannot
#: check that yet"; a PASS would be a lie and a FAIL would be a slander.
#:
#: An operator who DOES hold the trees points at them explicitly, and then the very same code
#: path runs the real pinned admission.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_PARENT = os.path.dirname(_PKG_DIR)


def _tree(env_name: str) -> str:
    """A configured admission tree, or ``""`` when the host does not have it."""
    return os.environ.get(env_name, "").strip()


_REPO = _tree("CORETEX_ADMISSION_REPO_ROOT")
_BENCH_V2_TREE = _tree("CORETEX_BENCHMARK_V2_DIR") or (
    os.path.join(_REPO, "benchmark-v2") if _REPO else "")
_CORETEX_MEMORY_TREE = _tree("CORETEX_MEMORY_RUNTIME_DIR") or (
    os.path.join(_REPO, "coretex-memory") if _REPO else "")

#: The screen runs in a CHILD INTERPRETER. ``benchmark-v2`` ships a package named ``frontier`` and
#: this lane's module is also called ``frontier``; giving the child a ``sys.path`` with only the
#: runtime trees on it lets each resolve unambiguously, exactly as
#: ``build_genesis.materialize_signed_composition`` does. It is also a hard isolation boundary: no
#: benchmark/product import ever lands in the process that computes frontier roots.
_SCREEN_CHILD = r'''
import json, sys
# ── IMPORT ISOLATION: AN EXPLICIT ALLOW-LIST, NOT A SCRUB ────────────────────────────────
#
# Two classes of path, separated STRUCTURALLY so a future change cannot silently re-admit a
# repository import:
#
#   ALLOWED   the pinned admission trees, plus the stdlib and site-packages OF THE VERIFIED
#             INTERPRETER — i.e. what `pip install` put there. That is where `wasmtime` and every
#             other pinned wheel dependency lives, and the sandbox must be able to import them.
#   REFUSED   everything else: the source tree, repository-relative entries, the working
#             directory (`''`), `PYTHONPATH` injections, and the user site directory. All of
#             those are AMBIENT — they depend on where the command was run from and what the host
#             happens to have lying around, which is precisely what must not influence a
#             deterministic replay.
#
# Building the list from scratch is the point. The previous version FILTERED the inherited path,
# which is a blocklist: it can only remove what somebody remembered to name, and it removed the
# wrong thing (in a wheel install the package's parent IS site-packages, so the filter deleted
# every third-party dependency and `wasmtime` vanished). An allow-list fails the other way —
# toward refusing an import — which is the correct direction for a sandbox.
import os as _os, site as _site, sysconfig as _sysconfig
_allowed = [{bench!r}, {coretex!r}]
for _key in ("stdlib", "platstdlib"):
    _p = _sysconfig.get_path(_key)
    if _p:
        _allowed.append(_p)
        _allowed.append(_os.path.join(_p, "lib-dynload"))
try:
    _allowed.extend(_site.getsitepackages())          # the VERIFIED environment's wheels
except AttributeError:                                # pragma: no cover - virtualenv shim
    pass
# The USER site directory is deliberately excluded: ~/.local is ambient host state,
# present on some machines and absent on others, so it must not influence a replay.
_seen = set()
sys.path[:] = [p for p in _allowed
               if p and p not in _seen and not _seen.add(p) and _os.path.isdir(p)]

from scoring.oracle_screen import is_oracle_clean
requests = json.loads(sys.stdin.read())
out = {{}}
for profile_id, seed, scale in requests:
    out["%s|%d|%s" % (profile_id, seed, scale)] = bool(
        is_oracle_clean(profile_id, int(seed), scale, bench_v2_dir={bench!r}))
print("<<<JSON>>>" + json.dumps(out, sort_keys=True))
'''


class ChildInterpreterOracleScreen:
    """The REAL G6b screen, isolated in a child interpreter and memoised.

    ``available()`` is honest: it reports False when either frozen tree is missing, and the caller
    then records ``ORACLE_SCREEN_UNAVAILABLE`` rather than pretending the walk was checked.
    """

    name = "scoring.oracle_screen(child-interpreter)"

    def __init__(self, *, bench_v2_dir: str = _BENCH_V2_TREE,
                 coretex_dir: str = _CORETEX_MEMORY_TREE, timeout: int = 3600) -> None:
        self.bench_v2_dir = bench_v2_dir
        self.coretex_dir = coretex_dir
        self.timeout = timeout
        self._cache: Dict[Tuple[str, int, str], bool] = {}
        self.child_calls = 0

    def available(self) -> bool:
        # `bool(dir)` FIRST: an unconfigured tree is the empty string, and `os.path.join("", x)`
        # is the RELATIVE path `x`, which a stray working directory could make exist. An
        # unconfigured host must report unavailable, never "found it in the cwd".
        return (bool(self.bench_v2_dir) and bool(self.coretex_dir)
                and os.path.isdir(os.path.join(self.bench_v2_dir, "scoring"))
                and os.path.isfile(os.path.join(self.bench_v2_dir, "scoring",
                                                "oracle_screen.py"))
                and os.path.isdir(self.coretex_dir))

    def prefetch(self, requests: Sequence[Tuple[str, int, str]]) -> None:
        """Screen a batch in ONE child. The screen is deterministic, so batching is free."""
        pending = [r for r in requests if tuple(r) not in self._cache]
        if not pending:
            return
        if not self.available():
            raise OracleScreenUnavailable(
                f"the frozen generators/runtime are not on this host "
                f"({self.bench_v2_dir}, {self.coretex_dir})")
        src = _SCREEN_CHILD.format(v5=_PKG_PARENT, validator=_PKG_DIR,
                                   coretex=self.coretex_dir, bench=self.bench_v2_dir)
        env = dict(os.environ)
        # The screen runs FROZEN TRUSTED code (the generators + oracle screen), not candidate code,
        # so "it never dials out" is a property of that code, NOT an enforcement — this scrubbing is
        # only so an inherited proxy cannot make an accidental egress look like a working screen. The
        # enforced+proven networkless boundary is on the CANDIDATE path (BenchmarkV2Sandbox below).
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(key, None)
        env["NO_PROXY"] = "*"
        try:
            proc = subprocess.run([sys.executable, "-c", src],
                                  input=json.dumps([list(r) for r in pending]),
                                  cwd=(self.bench_v2_dir or None), capture_output=True,
                                  text=True, env=env,
                                  timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise OracleScreenUnavailable(f"oracle screen child failed to start: {exc}") from exc
        self.child_calls += 1
        if proc.returncode != 0 or "<<<JSON>>>" not in proc.stdout:
            raise OracleScreenUnavailable(
                f"oracle screen child exited {proc.returncode}: {proc.stderr[-2000:] or proc.stdout[-2000:]}")
        payload = json.loads(proc.stdout.split("<<<JSON>>>", 1)[1].strip())
        for key, clean in payload.items():
            profile_id, seed, scale = key.rsplit("|", 2) if key.count("|") == 2 else (None,) * 3
            if profile_id is None:                             # pragma: no cover - defensive
                raise OracleScreenUnavailable(f"oracle screen returned a malformed key {key!r}")
            self._cache[(profile_id, int(seed), scale)] = bool(clean)

    def __call__(self, profile_id: str, seed: int, scale: str) -> bool:
        key = (profile_id, int(seed), scale)
        if key not in self._cache:
            self.prefetch([key])
        if key not in self._cache:                             # pragma: no cover - defensive
            raise OracleScreenUnavailable(f"oracle screen returned no verdict for {key}")
        return self._cache[key]


def default_oracle_screen() -> ChildInterpreterOracleScreen:
    """The screen an operator wires in. NOT a default argument anywhere — see :func:`replay_advance`."""
    return ChildInterpreterOracleScreen()


class AcceptAllScreen:
    """A screen that accepts every seed. STRICTLY a test double.

    It is a named class rather than a lambda so that a report can say which screen produced a
    verdict, and so that "an accept-all screen was used" can never be mistaken for the real one.
    """

    name = "accept-all(TEST DOUBLE — proves nothing about oracle cleanliness)"
    consensus_grade = False

    def available(self) -> bool:
        return True

    def __call__(self, profile_id: str, seed: int, scale: str) -> bool:
        return True


#: Hard cap on how many indices one label's completeness walk may screen. Exceeding it is
#: UNRESOLVED work (a BACKLOG entry), not a pass: the walk might be legitimate and simply long.
MAX_COMPLETENESS_STEPS = 4096


def verify_selection_complete(selection: Mapping[str, Any], *, entropy: Mapping[str, Any],
                              candidate_hash: str, screen: Screen,
                              burned: Optional[Sequence[str]] = None,
                              max_steps: int = MAX_COMPLETENESS_STEPS) -> Dict[str, Any]:
    """Prove NO LEGITIMATE INDEX WAS SKIPPED — the check V5-C left explicitly partial.

    ``benchmark-v2/validator/select.py`` walks forward from index 0 and steps past a derived
    instance only when it is (a) burned, (b) already chosen by this walk, (c) — for the
    confirmation walk — already chosen by the gate walk, or (d) not oracle-clean under the G6b
    screen. Any other index it reaches is TAKEN. So for every index strictly between two recorded
    steps there must exist one of those four reasons; an index with no reason means the walk
    skipped a legitimate instance, i.e. the selection was cherry-picked.

    Raises :class:`eval_artifact.SelectionMismatchError` on a cherry-picked walk (a FAIL) and
    :class:`OracleScreenUnavailable` when the screen cannot answer (a BACKLOG). Returns a report
    of what was screened, so "completeness verified" is a claim with a count behind it.
    """
    burned_ids = set(burned or ())
    profile_id = selection["profile_id"]
    scales = list(selection["scales"])
    report: Dict[str, Any] = {"labels": {}, "screened_indices": 0, "skips_justified": 0}
    gate_ids: set = set()

    for label in ENTROPY_LABELS:
        value = entropy["gate_value"] if label == "gate" else entropy["confirm_value"]
        base = ea.selection_base(label=label, entropy_value=value, candidate_hash=candidate_hash,
                                 season_root=selection["season_root"], profile_id=profile_id,
                                 round_id=selection["round_id"])
        chosen: set = set()
        cursor = 0
        justified = {"burned": 0, "already_chosen": 0, "held_by_gate": 0, "oracle_dirty": 0}
        screened = 0
        cases = sorted(selection["cases"][label], key=lambda c: c["derivation_index"])
        for case in cases:
            target = case["derivation_index"]
            if target - cursor > max_steps:
                raise OracleScreenUnavailable(
                    f"selection {label!r} skips {target - cursor} indices before step {target}; "
                    f"the completeness screen budget is {max_steps}. This is UNRESOLVED work "
                    "(the walk may be legitimate and merely long), not a verdict.")
            for index in range(cursor, target):
                seed, scale = ea.derive_step(base, index, scales)
                iid = ea.instance_id(profile_id, seed, scale)
                if iid in burned_ids:
                    justified["burned"] += 1
                    continue
                if iid in chosen:
                    justified["already_chosen"] += 1
                    continue
                if label == "confirm" and iid in gate_ids:
                    justified["held_by_gate"] += 1
                    continue
                screened += 1
                if not screen(profile_id, seed, scale):
                    justified["oracle_dirty"] += 1
                    continue
                raise ea.SelectionMismatchError(
                    f"selection {label!r} skipped index {index} ({iid}), which is unburned, "
                    f"unchosen and ORACLE-CLEAN, and jumped to index {target}. The forward walk "
                    "takes every such instance, so this selection was cherry-picked. (V5-C proves "
                    "each recorded case sits at its claimed index; THIS is the completeness half.)")
            seed, scale = ea.derive_step(base, target, scales)
            if case["seed"] != seed or case["scale"] != scale:
                raise ea.SelectionMismatchError(
                    f"selection {label!r} step {target} derives seed={seed} scale={scale!r}, the "
                    f"artifact records seed={case['seed']} scale={case['scale']!r}")
            iid = ea.instance_id(profile_id, seed, scale)
            if iid in burned_ids:
                raise ea.SelectionMismatchError(
                    f"selection {label!r} SCORED burned instance {iid} at index {target}")
            if iid in chosen or (label == "confirm" and iid in gate_ids):
                raise ea.SelectionMismatchError(
                    f"selection {label!r} SCORED duplicate instance {iid} at index {target}")
            screened += 1
            if not screen(profile_id, seed, scale):
                raise ea.SelectionMismatchError(
                    f"selection {label!r} SCORED index {target} ({iid}), which the G6b oracle "
                    "screen rejects: an oracle-inconsistent instance fails the validity hard gate "
                    "for EVERY candidate including the reference incumbent, so scoring it is not "
                    "a legitimate measurement")
            chosen.add(iid)
            cursor = target + 1
        if label == "gate":
            gate_ids = set(chosen)
        report["labels"][label] = {"cases": len(cases), "screened": screened,
                                   "justified_skips": dict(justified),
                                   "last_index": cursor - 1 if cases else -1}
        report["screened_indices"] += screened
        report["skips_justified"] += sum(justified.values())
    report["screen"] = getattr(screen, "name", type(screen).__name__)
    report["consensus_grade"] = bool(getattr(screen, "consensus_grade", True))
    return report


# --------------------------------------------------------------------------- #
# The pinned networkless candidate sandbox
# --------------------------------------------------------------------------- #
class SandboxDependencyError(Exception):
    """A required dependency of the pinned runtime is MISSING FROM THE VERIFIED ENVIRONMENT.

    DELIBERATELY NOT A SUBCLASS OF :class:`SandboxUnavailable`, because the two mean opposite
    things to whoever is reading the report:

    * ``SandboxUnavailable`` -> BACKLOG -> "this host is not configured to check that". The reader
      concludes our instructions were incomplete and goes looking for more of them.
    * ``SandboxDependencyError`` -> FAIL -> "your environment is wrong, and here is which
      dependency and how to fix it". The reader concludes the ball is in their court.

    Collapsing the second into the first is the single most misleading thing this module could do
    to an external agent: they would spend their time re-reading our documentation while the
    actual fix is one ``pip install`` on their side.
    """

    def __init__(self, dependency: str, detail: str, *, remedy: str = "") -> None:
        self.dependency = dependency
        self.detail = detail
        self.remedy = remedy or f"install {dependency} into the environment running the validator"
        super().__init__(
            f"MISSING_DEPENDENCY[{dependency}]: {detail}. This is an ENVIRONMENT fault, not a "
            f"missing configuration and not something the validator can check around. Remedy: "
            f"{self.remedy}")


#: What the pinned runtime trees need that is not in the standard library, and the range the
#: publication lane's closure analysis recorded. The validator itself still declares no runtime
#: dependencies; this one belongs to the runtime tree it executes.
PINNED_RUNTIME_DEPENDENCIES = {"wasmtime": ">=46.0.1,<47"}


class SandboxUnavailable(Exception):
    """The pinned sandbox cannot run here. Always a BACKLOG entry, never a pass."""


class CandidateSandbox:
    """Executes the candidate against the re-derived selection and rebuilds the receipt body.

    Interface, not an implementation. ``execute`` returns
    ``{"reproduced": bool, "code": str|None, "reason": str, "receipt_hash": str|None,
    "body": dict|None, "sandbox": str, "networkless": bool,
    "networkless_evidence": dict|None}``. Raise
    :class:`SandboxUnavailable` when the sandbox could not RUN; return ``reproduced: False`` when
    it ran and DIVERGED. The two are different outcomes and must not be conflated.

    ``networkless`` must be DERIVED from an observation, never hard-coded, and a consensus-grade
    implementation must supply ``networkless_evidence`` — the concrete demonstration it derived the
    flag from (``worker.isolation.prove_networkless``'s block: a real ``socket(2)`` per IP family,
    with ``enforced`` and any ``unenforced_families``). :func:`replay_advance` FAILS a consensus-
    grade sandbox that supplies no evidence, and FAILS any sandbox whose evidence shows an IP socket
    was creatable — "networkless" as a constant compared against a constant is exactly the vacuous
    assertion ruling §9 W2 removed.

    ``consensus_grade`` declares whether this implementation actually executes the candidate under
    the pinned networkless law. A stub sets it False and is then treated exactly like an absent
    sandbox (see :func:`replay_advance`'s ``allow_test_doubles``); only such a declared test double
    may assert ``networkless`` without evidence.
    """

    name = "abstract"
    consensus_grade = True
    #: What to tell the backlog when :meth:`available` is False. Subclasses override it so the
    #: persisted entry says what is actually missing rather than "unavailable".
    unavailable_reason = "the sandbox reports itself unavailable on this host"

    def available(self) -> bool:
        return False

    def execute(self, *, receipt_wrapper: Mapping[str, Any],
                artifact: Mapping[str, Any],
                incumbent_execution: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        raise SandboxUnavailable(f"{self.name}: no sandbox implementation")


class NullSandbox(CandidateSandbox):
    """The honest default: no sandbox on this host, so every replay BACKLOGS at that stage.

    Deliberately not "skip the sandbox and pass" — the candidate's measurements are the substance
    of the mine, and a validator that never ran them has verified bindings, not a result.
    """

    name = "none"
    unavailable_reason = (
        "no pinned networkless sandbox was supplied to this validator; the candidate was not "
        "executed and its utility/safety/rendered-cost/fuel/storage are UNVERIFIED")

    def execute(self, *, receipt_wrapper: Mapping[str, Any],
                artifact: Mapping[str, Any],
                incumbent_execution: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        raise SandboxUnavailable(self.unavailable_reason)


#: Reuses ``benchmark-v2/validator/replay.py::replay_receipt`` — the frozen, self-contained
#: receipt replay that re-derives the selections, regenerates instances, re-runs scoring against
#: the pinned runtime and rebuilds the receipt body byte-identically. That IS the pinned
#: networkless execution; V5 does not mint a second scoring path.
_SANDBOX_CHILD = r'''
import importlib.util, json, shutil, sys, tempfile
# The same explicit ALLOW-LIST the sandbox child uses — see its comment. Allowed: the pinned
# trees plus the verified interpreter's stdlib and site-packages. Refused: source tree,
# repository-relative paths, the working directory and PYTHONPATH injections.
import os as _os, site as _site, sysconfig as _sysconfig
_allowed = [{bench!r}, {coretex!r}]
for _key in ("stdlib", "platstdlib"):
    _p = _sysconfig.get_path(_key)
    if _p:
        _allowed.append(_p)
        _allowed.append(_os.path.join(_p, "lib-dynload"))
try:
    _allowed.extend(_site.getsitepackages())
except AttributeError:                                # pragma: no cover - virtualenv shim
    pass
_seen = set()
sys.path[:] = [p for p in _allowed
               if p and p not in _seen and not _seen.add(p) and _os.path.isdir(p)]
# DEPENDENCY PREFLIGHT — fail CLOSED with a NAMED error, never a backlog. Without this a missing
# `wasmtime` surfaces as "sandbox unavailable", which reads as "not configured" and sends the
# reader back to our documentation instead of to their own environment.
for _dependency in ("wasmtime",):
    try:
        __import__(_dependency)
    except ImportError as _exc:
        print("<<<MISSING_DEPENDENCY>>>" + json.dumps(
            {{"dependency": _dependency, "detail": str(_exc),
              "sys_path": list(sys.path)}}))
        raise SystemExit(97)
# NETWORKLESS: enforce, then PROVE, before a single line of candidate code runs (ruling §9 W2).
# `worker/isolation.py` is loaded by ABSOLUTE PATH so the v5 lane stays off sys.path (the whole
# reason this is a child interpreter); it imports nothing but the stdlib.
_spec = importlib.util.spec_from_file_location("v5_worker_isolation", {isolation!r})
_iso = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_iso)
# Fail CLOSED: if the filter cannot be installed, this raises IsolationUnavailable and the child
# exits non-zero -> SandboxUnavailable -> BACKLOG. The candidate is never run unconfined.
_install = _iso.apply_networkless()
_proof = _iso.prove_networkless(install=_install)
# `validator` resolves to benchmark-v2's package here, never this lane's: {v5!r} is off the path.
from validator import replay as bench_replay, signing as bench_signing
payload = json.loads(sys.stdin.read())
pin = bench_signing.load_pin(payload["pin_path"])
work = tempfile.mkdtemp(prefix="v5e-sandbox-")
try:
    out = bench_replay.replay_receipt(payload["wrapper"], repo_root={repo!r}, pin=pin,
                                      workroot=work)
finally:
    shutil.rmtree(work, ignore_errors=True)
if "networkless_proof" in out:                 # defensive: never shadow a frozen-law field
    raise SystemExit("benchmark-v2 replay_receipt already returns 'networkless_proof'")
out["networkless_proof"] = _proof
print("<<<JSON>>>" + json.dumps(out, sort_keys=True, default=str))
'''

# A v2 eval artifact addresses the bare deterministic report and deliberately has no signed
# wrapper. Re-run the same frozen signature-free functions used by benchmark-v2's historical
# replay entry point and compare the rebuilt report to the artifact-bound content root.
_SANDBOX_CHILD_V2 = r'''
import importlib.util, json, shutil, sys, tempfile
import os as _os, site as _site, sysconfig as _sysconfig
_allowed = [{bench!r}, {coretex!r}]
for _key in ("stdlib", "platstdlib"):
    _p = _sysconfig.get_path(_key)
    if _p:
        _allowed.append(_p)
        _allowed.append(_os.path.join(_p, "lib-dynload"))
try:
    _allowed.extend(_site.getsitepackages())
except AttributeError:
    pass
_seen = set()
sys.path[:] = [p for p in _allowed
               if p and p not in _seen and not _seen.add(p) and _os.path.isdir(p)]
for _dependency in ("wasmtime",):
    try:
        __import__(_dependency)
    except ImportError as _exc:
        print("<<<MISSING_DEPENDENCY>>>" + json.dumps(
            {{"dependency": _dependency, "detail": str(_exc),
              "sys_path": list(sys.path)}}))
        raise SystemExit(97)
_spec = importlib.util.spec_from_file_location("v5_worker_isolation", {isolation!r})
_iso = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_iso)
_install = _iso.apply_networkless()
_proof = _iso.prove_networkless(install=_install)
from validator import evaluate as bench_evaluate, receipt as bench_receipt, select as bench_select
from validator.replay import _burned_set, _minimal_round_rec, _res
from validator._rt import hash_obj

payload = json.loads(sys.stdin.read())
body = payload["eval_report"]
bound_root = payload["bound_eval_report_root"]


def _run():
    try:
        roots = bench_receipt.code_roots({repo!r})
    except bench_receipt.ReceiptError as exc:
        return _res(False, "code_root_unavailable", "code_roots", str(exc))
    for tree, digest in body["code_roots"].items():
        if roots.get(tree) != digest:
            reason = (str(tree) + " tree hash " + str(roots.get(tree))
                      + " != receipt-bound " + str(digest))
            return _res(False, "code_root_mismatch", "code_roots", reason, tree=tree)

    burned, err = _burned_set(body, None)
    if err is not None:
        return err

    ch = body["candidate"]["candidate_hash"]
    round_rec = _minimal_round_rec(body)
    compact_incumbent = (
        body["incumbent"]
        if bench_receipt.is_exact_incumbent_execution(body.get("incumbent"))
        else None)
    incumbent_execution = payload.get("incumbent_execution")
    if compact_incumbent is not None:
        if incumbent_execution is None:
            return _res(False, "incumbent_execution_required", "evaluate",
                        "exact-parent replay requires the resolved full incumbent execution")
        try:
            incumbent_execution = bench_receipt.validate_full_incumbent_execution(
                body["profile_id"], incumbent_execution)
            projected = bench_receipt.project_incumbent_execution(
                body["profile_id"], incumbent_execution)
        except bench_receipt.ReceiptError as exc:
            return _res(False, "incumbent_execution_invalid", "evaluate", str(exc))
        if projected != compact_incumbent:
            return _res(False, "incumbent_execution_mismatch", "evaluate",
                        "resolved parent execution differs from the report-bound identity")
        round_rec["parent_release_root"] = compact_incumbent["release_root"]
    elif incumbent_execution is not None:
        return _res(False, "incumbent_execution_unexpected", "evaluate",
                    "a historical report does not accept an exact-parent descriptor")
    try:
        re_sel = bench_select.select_for_candidate(round_rec, ch, burned)
    except bench_select.SelectionError as exc:
        return _res(False, "selection_error", "selection", str(exc))
    fields = ("instance_id", "profile_id", "seed", "scale", "derivation_index")
    for branch in ("gate", "confirm"):
        got = [dict((k, c[k]) for k in fields) for c in re_sel[branch]]
        want = [dict((k, c[k]) for k in fields) for c in body["selection"][branch]]
        if got != want:
            reason = str(branch) + " re-derivation differs from the eval report"
            return _res(False, "selection_divergence", "selection", reason, branch=branch,
                        derived=got, receipt=want)

    work = tempfile.mkdtemp(prefix="v5e-sandbox-v2-")
    try:
        ev = bench_evaluate.evaluate_candidate(
            round_rec, ch, re_sel, work, pool=bench_evaluate.POOL_MAX,
            bench_v2_dir={bench!r}, portability=body.get("portability"),
            runtime_config=body.get("runtime_config"),
            incumbent_execution=incumbent_execution,
            pre_exact_report=(body if incumbent_execution is None else None))
        recomputed_incumbent = (
            bench_receipt.expected_incumbent_block(body["profile_id"])
            if incumbent_execution is None else None)
        rebuilt = bench_receipt.build_receipt_body(
            round_rec=round_rec, round_hash=body["round_hash"], candidate_hash=ch,
            incumbent=recomputed_incumbent, selection=re_sel, case_hashes=ev["case_hashes"],
            evaluation=ev, roots=roots, burned_head=body["burned_head"],
            incumbent_execution=incumbent_execution,
            pre_exact_report=(body if incumbent_execution is None else None))
    except Exception as exc:
        return _res(False, "reexecution_failed", "evaluate",
                    type(exc).__name__ + ": " + str(exc))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    rebuilt_hash = hash_obj(rebuilt)
    if rebuilt_hash == bound_root:
        return _res(True, None, "done",
                    "eval report reproduced byte-identically through frozen Benchmark-v2",
                    receipt_hash=rebuilt_hash, body=rebuilt)
    diverged = [k for k in (
        "selection", "outputs_hash", "scores", "verdicts", "decision", "code_roots",
        "replay_check", "incumbent", "entropy", "confirm_entropy", "portability",
        "evaluation_law") if rebuilt.get(k) != body.get(k)]
    reason = ("rebuilt report hash " + rebuilt_hash
              + " != artifact-bound eval_report_root " + str(bound_root)
              + "; diverging fields: " + str(diverged or ["identity-only"]))
    return _res(False, "eval_report_root_divergence", "rebuild", reason, diverged=diverged)


out = _run()
if "networkless_proof" in out:
    raise SystemExit("v2 reconstruction already returns 'networkless_proof'")
out["networkless_proof"] = _proof
print("<<<JSON>>>" + json.dumps(out, sort_keys=True, default=str))
'''


#: Sandbox result codes that mean "an INPUT was missing", not "the receipt did not reproduce".
#:
#: The frozen replayer returns one refusal shape for both facts, and the CLI used to print every
#: one of them as ``outcome: FAIL``, exit 1 — the code this client's own documentation defines as
#: A REFUTATION. So a never-published law file (``code_root_unavailable``: the seventh sealed root,
#: D-3) or an unresolved exact parent (``incumbent_execution_required``, D-4) made a CI wired to
#: the documented contract raise a refutation alarm against a healthy production receipt.
#:
#: BACKLOG is the outcome that means "I could not check that", and the sibling
#: :class:`SandboxUnavailable` branch already used it. Deliberately NARROW: ``code_root_mismatch``
#: is not here, because two pinned things disagreeing IS a determination, and neither is
#: ``reexecution_failed``, which may be a genuine divergence.
AVAILABILITY_REPLAY_CODES = frozenset({
    "code_root_unavailable",
    "incumbent_execution_required",
})


class BenchmarkV2Sandbox(CandidateSandbox):
    """The pinned networkless sandbox: benchmark-v2's own receipt replay, in a child interpreter.

    Child, not import, for the same reason the oracle screen uses one: ``benchmark-v2`` ships a
    package named ``frontier`` and so does this lane. The child's environment is scrubbed of every
    proxy variable and ``NO_PROXY=*`` is set, so an accidental egress cannot make a networked run
    look like a networkless one.

    NETWORKLESS IS ENFORCED AND PROVEN, NOT ASSERTED (ruling §9 W2). Before the frozen replay runs,
    the child installs ``v5/worker/isolation.py``'s seccomp-BPF filter (``socket(2)`` -> EPERM for
    AF_INET/AF_INET6/AF_PACKET, irrevocable, inherited by all three nested benchmark-v2 children and
    by the CPython ``exec`` of the candidate module at the bottom of that chain) and then PROVES it
    by attempting a real ``AF_INET`` and ``AF_INET6`` socket. The returned ``networkless`` field is
    DERIVED from that observation and the full proof is returned alongside it as
    ``networkless_evidence``; it was previously a hard-coded ``True``. If the filter cannot be
    installed at all, the child exits non-zero and this raises :class:`SandboxUnavailable` — the
    candidate is never executed unconfined, and an un-provable host BACKLOGs instead of passing.

    ``available()`` requires the benchmark tree, the runtime tree, the validator key pin AND the
    isolation module the child needs to enforce+prove networklessness. It does NOT check for the
    candidate bundle — that is per-candidate and surfaces as a run failure, which is still a
    BACKLOG (the sandbox could not run THIS candidate), never a pass.
    """

    name = "benchmark-v2/validator/replay.replay_receipt(child-interpreter)"

    def __init__(self, *, repo_root: str = _REPO, bench_v2_dir: str = _BENCH_V2_TREE,
                 coretex_dir: str = _CORETEX_MEMORY_TREE, pin_path: Optional[str] = None,
                 timeout: int = 7200, isolation_path: Optional[str] = None) -> None:
        self.repo_root = repo_root
        self.bench_v2_dir = bench_v2_dir
        self.coretex_dir = coretex_dir
        self.pin_path = pin_path or (os.path.join(bench_v2_dir, "validator", "keys",
                                                  "validator_pin.json") if bench_v2_dir else "")
        self.timeout = timeout
        #: The networkless enforcement+proof the child loads by absolute path. Not on its sys.path.
        self.isolation_path = isolation_path or os.path.join(_PKG_DIR, "isolation.py")

    def available(self) -> bool:
        # See ChildInterpreterOracleScreen.available: an unconfigured tree is "" and must never
        # be allowed to resolve relative to the working directory.
        return (bool(self.bench_v2_dir) and bool(self.coretex_dir) and bool(self.pin_path)
                and os.path.isfile(os.path.join(self.bench_v2_dir, "validator", "replay.py"))
                and os.path.isdir(self.coretex_dir) and os.path.isfile(self.pin_path)
                and os.path.isfile(self.isolation_path))

    @property
    def unavailable_reason(self) -> str:
        return (f"the pinned sandbox is not provisioned on this host (need "
                f"{self.bench_v2_dir}/validator/replay.py, {self.coretex_dir}, {self.pin_path} and "
                f"{self.isolation_path} — the last one is what enforces AND proves networkless "
                f"execution, so without it the candidate would run unconfined)")

    def execute(self, *, receipt_wrapper: Mapping[str, Any],
                artifact: Mapping[str, Any],
                incumbent_execution: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        if not self.available():
            raise SandboxUnavailable(self.unavailable_reason)
        # The interface name is retained for historical test doubles. Under v2 the value is the
        # bare evaluation report; its shape selects the signature-free reconstruction child.
        if (isinstance(receipt_wrapper, abc.Mapping)
                and receipt_wrapper.get("format") == ea.EVAL_REPORT_FORMAT):
            bound_root = (artifact.get("receipt") or {}).get("eval_report_root")
            if not isinstance(bound_root, str) or not bound_root:
                raise SandboxUnavailable(
                    "a v2 report has no artifact.receipt.eval_report_root binding")
            src = _SANDBOX_CHILD_V2.format(
                v5=_PKG_PARENT, validator=_PKG_DIR,
                coretex=self.coretex_dir, bench=self.bench_v2_dir, repo=self.repo_root,
                isolation=self.isolation_path)
            child_payload = {
                "eval_report": receipt_wrapper,
                "bound_eval_report_root": bound_root,
                "incumbent_execution": incumbent_execution,
            }
        else:
            src = _SANDBOX_CHILD.format(
                v5=_PKG_PARENT, validator=_PKG_DIR,
                coretex=self.coretex_dir, bench=self.bench_v2_dir, repo=self.repo_root,
                isolation=self.isolation_path)
            child_payload = {"wrapper": receipt_wrapper, "pin_path": self.pin_path}
        env = dict(os.environ)
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(key, None)
        env["NO_PROXY"] = "*"
        payload = json.dumps(child_payload)
        try:
            proc = subprocess.run([sys.executable, "-c", src], input=payload,
                                  cwd=(self.repo_root or None), capture_output=True, text=True,
                                  env=env, timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxUnavailable(f"sandbox child failed to start: {exc}") from exc
        if "<<<MISSING_DEPENDENCY>>>" in proc.stdout:
            payload = json.loads(proc.stdout.split("<<<MISSING_DEPENDENCY>>>", 1)[1]
                                 .splitlines()[0])
            name = str(payload.get("dependency", "?"))
            pin = PINNED_RUNTIME_DEPENDENCIES.get(name, "")
            raise SandboxDependencyError(
                name, f"the pinned runtime could not import it in the sandbox child "
                      f"({payload.get('detail')})",
                remedy=(f"pip install '{name}{pin}' into the environment running the validator"
                        if pin else f"pip install {name}"))
        if proc.returncode != 0 or "<<<JSON>>>" not in proc.stdout:
            raise SandboxUnavailable(
                f"sandbox child exited {proc.returncode}: "
                f"{proc.stderr[-2000:] or proc.stdout[-2000:]}")
        raw = json.loads(proc.stdout.split("<<<JSON>>>", 1)[1].strip())
        # `networkless` is DERIVED from the child's real socket(2) probe — never a literal. A child
        # that returned no proof at all is reported as NOT networkless (the honest reading of "no
        # demonstration"), and the parent gate below refuses it.
        proof = raw.get("networkless_proof")
        proven = isinstance(proof, abc.Mapping) and proof.get("enforced") is True
        return {"reproduced": bool(raw.get("reproduced")), "code": raw.get("code"),
                "reason": raw.get("reason", ""), "receipt_hash": raw.get("receipt_hash"),
                "body": raw.get("body"), "sandbox": self.name, "networkless": proven,
                "networkless_evidence": proof if isinstance(proof, abc.Mapping) else None,
                "stage": raw.get("stage")}


def default_sandbox() -> BenchmarkV2Sandbox:
    """The sandbox an operator wires in. NOT a default argument — see :func:`replay_advance`."""
    return BenchmarkV2Sandbox()


#: The hard safety gates the reproduced candidate side must satisfy (benchmark-v2 ``hard`` block).
SAFETY_ZERO_GATES = ("canonical_event_integrity_violations", "provenance_violations",
                     "stale_or_retracted_disclosures", "validity_violations")


# --------------------------------------------------------------------------- #
# Result types
# --------------------------------------------------------------------------- #
@dataclass
class ReplayResult:
    """One advance, replayed. ``outcome`` is PASS, FAIL or BACKLOG — never a bare bool."""

    outcome: bl.Outcome
    stage: str
    reason: str
    code: Optional[str] = None
    epoch: Optional[int] = None
    transition_index: Optional[int] = None
    miner: Optional[str] = None
    parent_frontier_root: Optional[str] = None
    new_frontier_root: Optional[str] = None
    eval_report_hash: Optional[str] = None
    checks: List[str] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)
    backlog_entry: Optional[bl.BacklogEntry] = None
    #: EVERYTHING external-model. ``consensus_critical: false``, always. Never read by any check.
    auxiliary: Dict[str, Any] = field(default_factory=dict)
    #: The reproduced child manifest, when the frontier replay got that far.
    new_manifest: Optional[Dict[str, Any]] = None

    @property
    def ok(self) -> bool:
        return self.outcome.is_pass

    @property
    def is_backlog(self) -> bool:
        return self.outcome.is_backlog

    @property
    def is_fail(self) -> bool:
        return self.outcome.is_fail

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "format": REPLAY_RESULT_FORMAT, "outcome": str(self.outcome), "stage": self.stage,
            "reason": self.reason, "checks": list(self.checks),
            "consensus_critical": True,
        }
        for name in ("code", "epoch", "transition_index", "miner", "parent_frontier_root",
                     "new_frontier_root", "eval_report_hash"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        if self.detail:
            out["detail"] = self.detail
        if self.backlog_entry is not None:
            out["backlog"] = self.backlog_entry.as_dict()
        if self.auxiliary:
            out["auxiliary"] = self.auxiliary
        return out

    def verdict_fingerprint(self) -> str:
        """The deterministic identity of the DECISION, for the canary-isolation assertion.

        Covers exactly what consensus turns on: the outcome, its code and stage, the deterministic
        Benchmark-v2 verdict, and the recomputed ppm accounting. Two replays that differ only in
        external-model evidence MUST fingerprint identically.

        Deliberately EXCLUDED, and why:

        * ``auxiliary`` — the whole point of the separation;
        * ``checks`` — an artifact that CARRIES a canary legitimately gains one extra evidence
          step (``artifact:canary_isolation``, V5-C re-asserting that the verdict is unchanged
          with and without it). That is a record of extra verification performed, not a different
          decision, and folding it in here would make the isolation property untestable;
        * ``eval_report_hash`` — the canary block sits INSIDE the artifact's canonical bytes, so
          it legitimately moves the artifact's address while leaving the verdict alone.
        """
        return fr.sha256_hex(fr.canonical_bytes({
            "code": self.code or "", "outcome": str(self.outcome), "stage": self.stage,
            "resource_accounting": self.detail.get("resource_accounting", {}),
            "verdict": self.detail.get("verdict", {}),
        }))


def _pass(stage: str, reason: str, **kw) -> ReplayResult:
    return ReplayResult(outcome=bl.PASS, stage=stage, reason=reason, **kw)


def _fail(stage: str, code: str, reason: str, **kw) -> ReplayResult:
    return ReplayResult(outcome=bl.FAIL, stage=stage, code=code, reason=reason, **kw)


def _backlog(stage: str, entry: bl.BacklogEntry, **kw) -> ReplayResult:
    return ReplayResult(outcome=bl.BACKLOG, stage=stage, code=entry.reason,
                        reason=entry.detail, backlog_entry=entry, **kw)


def _ident(event: dp.FrontierAdvanced) -> Dict[str, Any]:
    return {"epoch": event.epoch, "transition_index": event.transition_index,
            "miner": event.miner, "parent_frontier_root": event.parent_frontier_root,
            "new_frontier_root": event.new_frontier_root,
            "eval_report_hash": event.eval_report_hash}


# --------------------------------------------------------------------------- #
# The auxiliary (Haiku / external-model) evidence path
# --------------------------------------------------------------------------- #
def canary_evidence(artifact: Mapping[str, Any], *, store: Optional[pub.ContentStore] = None,
                    sealed_transcript: Optional[Mapping[str, Any]] = None,
                    expected_code_identity: Optional[Mapping[str, Any]] = None,
                    revealed_entropy_secret: Optional[str] = None,
                    event: Optional[dp.FrontierAdvanced] = None) -> Dict[str, Any]:
    """The auxiliary external-model block. ``consensus_critical: false``, structurally.

    It verifies what CAN be verified without regenerating a token: the sealed transcript's own
    hash (``canary_transcript_root``), the policy hash, the scorer/questions code identity, and
    the candidate / incumbent / epoch / entropy / selection-base bindings — via
    :func:`eval_artifact.verify_canary_block`, which re-derives each rather than importing an
    opaque root.

    It NEVER raises for a canary failure and never returns anything a caller could mistake for a
    verdict: the deterministic verdict travels in the block only as a copy, and
    :func:`replay_advance` asserts the deterministic verdict is unchanged with and without the
    canary before this block is attached.
    """
    block: Dict[str, Any] = {
        "consensus_critical": False,
        "external_model_attestation": True,
        "may_change_verdict": False,
        "authority": "AUXILIARY coordinator sanity evidence (§17.236). Creates no promotion "
                     "eligibility; cannot deny a deterministically earned promotion. A serious "
                     "failure escalates to an operator alert or an explicitly governed GLOBAL "
                     "safety pause — never an opaque candidate-specific consensus gate.",
        "present": "canary" in artifact,
    }
    if event is not None:
        block["epoch"] = event.epoch
        block["transition_index"] = event.transition_index
    try:
        report = ea.verify_canary_block(artifact, sealed_transcript, store=store,
                                        expected_code_identity=expected_code_identity,
                                        revealed_entropy_secret=revealed_entropy_secret)
    except ea.CanaryConsensusError as exc:
        # The ONE canary condition that is a real violation: a block claiming consensus authority.
        # It is surfaced here as evidence AND rejected by verify_artifact, so it can never pass.
        block.update({"ok": False, "code": "claims_consensus_authority", "reason": str(exc)})
        return block
    except (ea.EvalArtifactError, fr.FrontierError, pub.PublicationError) as exc:
        block.update({"ok": False, "code": "canary_verification_error", "reason": str(exc)})
        return block
    for key in ("ok", "code", "reason", "canary_verdict", "differences"):
        if key in report:
            block[key] = report[key]
    block["deterministic_verdict"] = report["deterministic_verdict"]
    block["verdict_authority"] = report["verdict_authority"]
    return block


# --------------------------------------------------------------------------- #
# The replay
# --------------------------------------------------------------------------- #
def replay_advance(event: dp.FrontierAdvanced, *, store: pub.ContentStore,
                   pins: Optional[dp.PinResolver] = None,
                   screen: Optional[Screen] = None,
                   sandbox: Optional[CandidateSandbox] = None,
                   credit_event: Optional[dp.CreditAccepted] = None,
                   burned: Optional[Sequence[str]] = None,
                   signature_verifier: Optional[Callable[[Mapping[str, Any]], bool]] = None,
                   sealed_transcript: Optional[Mapping[str, Any]] = None,
                   expected_canary_code_identity: Optional[Mapping[str, Any]] = None,
                   observed_at: Optional[int] = None,
                   live_root: Optional[str] = None,
                   allow_test_doubles: bool = False) -> ReplayResult:
    """Replay ONE confirmed advance in §17.236's order. Returns PASS, FAIL or BACKLOG.

    ``pins`` is a PER-EPOCH resolver (``dispatch.PinResolver``); each advance is checked against
    ITS OWN epoch's pins and there is no global fallback. ``screen`` and ``sandbox`` default to
    *absent*, which yields a BACKLOG at their stages — an unwired validator reports unverified
    work, it never reports a pass. ``live_root``, when given, is the running confirmed root the
    event must build on (the off-chain twin of the registry's parent-root CAS).

    ``allow_test_doubles`` (default **False**) is the one visible opt-out in this module. A screen
    or sandbox that declares ``consensus_grade = False`` — :class:`AcceptAllScreen`, a stub — does
    not actually prove what its stage claims, so by default it produces a BACKLOG entry exactly
    like an absent one. Tests that need to exercise the downstream stages pass this explicitly,
    which leaves the opt-out visible in the test source instead of hidden in a default.
    """
    ident = _ident(event)
    checks: List[str] = []

    def done(name: str) -> None:
        checks.append(name)

    # ---- 0. the confirmed event itself -----------------------------------------------------
    if event.provenance.removed:
        return _fail("event", "reorged_log",
                     f"epoch {event.epoch} index {event.transition_index} is flagged removed by "
                     "the feed; a reorged-out log is not confirmed chain truth",
                     checks=checks, **ident)
    for name in ("parent_frontier_root", "new_frontier_root", "candidate_release_root",
                 "composition_root", "eval_report_hash", "benchmark_law_root",
                 "runtime_abi_root"):
        value = getattr(event, name)
        try:
            fr.check_root(value, name)
        except fr.FrontierError as exc:
            return _fail("event", "malformed_event", str(exc), checks=checks, **ident)
        if value == fr.ZERO_ROOT:
            return _fail("event", "zero_root",
                         f"{name} is the zero sentinel; the registry refuses a zero root on an "
                         "advance, so this is not an event that contract emitted",
                         checks=checks, **ident)
    if event.new_frontier_root == event.parent_frontier_root:
        return _fail("event", "no_op_advance",
                     "newFrontierRoot equals parentFrontierRoot; the registry reverts a no-op "
                     "advance, so this event cannot have been confirmed by it",
                     checks=checks, **ident)
    if live_root is not None and event.parent_frontier_root != live_root:
        return _fail("event", "live_root_mismatch",
                     f"advance builds on {event.parent_frontier_root} but the confirmed live root "
                     f"is {live_root}; the registry's parent-root CAS admits exactly one candidate "
                     "per parent and this is not it", checks=checks, **ident)
    done("event")

    # ---- 1. this event's OWN epoch pins -----------------------------------------------------
    try:
        epoch_pins = dp.resolve_pins(pins, event.epoch)
    except dp.MissingEpochPinsError as exc:
        return _backlog("epoch_pins", bl.epoch_pins_unavailable(
            str(exc), event=event, subject=f"epoch:{event.epoch}", observed_at=observed_at),
            checks=checks, **ident)
    except dp.DispatchError as exc:
        return _fail("epoch_pins", "bad_pin_resolver", str(exc), checks=checks, **ident)
    if event.benchmark_law_root != epoch_pins.benchmark_law_root:
        return _fail("epoch_pins", "benchmark_law_root_mismatch",
                     f"event benchmarkRoot {event.benchmark_law_root} != epoch {event.epoch} pin "
                     f"{epoch_pins.benchmark_law_root}", checks=checks, **ident)
    if event.runtime_abi_root != epoch_pins.runtime_abi_root:
        return _fail("epoch_pins", "runtime_abi_root_mismatch",
                     f"event runtimeAbiRoot {event.runtime_abi_root} != epoch {event.epoch} pin "
                     f"{epoch_pins.runtime_abi_root}", checks=checks, **ident)
    done("epoch_pins")

    # ---- 2. fetch the parent frontier manifest and VERIFY ITS ROOT ---------------------------
    try:
        parent_manifest = pub.fetch_json(event.parent_frontier_root,
                                         hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        return _backlog("parent_manifest", bl.unfetchable_manifest(
            f"parent frontier manifest {event.parent_frontier_root} is not on the publication "
            f"surface: {exc}", event=event, subject=event.parent_frontier_root,
            observed_at=observed_at), checks=checks, **ident)
    except pub.PublicationError as exc:
        return _fail("parent_manifest", "parent_manifest_corrupt", str(exc), checks=checks,
                     **ident)
    try:
        computed_parent = fr.frontier_root(parent_manifest)
    except fr.FrontierError as exc:
        return _fail("parent_manifest", "parent_manifest_invalid", str(exc), checks=checks,
                     **ident)
    if computed_parent != event.parent_frontier_root:
        return _fail("parent_manifest", "parent_root_mismatch",
                     f"the fetched parent manifest hashes to {computed_parent}, the event names "
                     f"{event.parent_frontier_root}", checks=checks, **ident)
    # The parent's epoch and the event's epoch agree for an ordinary within-epoch advance. They
    # DIFFER for the first transition of an epoch, which lazily inherits the head of an EARLIER
    # epoch (ruling §17.237). Both are legitimate; the pair (transition_index, epoch relation) is
    # what tells them apart, and every other pairing is refused.
    parent_epoch = parent_manifest["epoch"]
    if parent_epoch > event.epoch:
        return _fail("parent_manifest", "parent_epoch_regression",
                     f"parent manifest epoch {parent_epoch} is LATER than event epoch "
                     f"{event.epoch}; epochs never move backwards and a closed epoch's head is "
                     "immutable once a later epoch inherited from it", checks=checks, **ident)
    if parent_epoch != event.epoch and event.transition_index != 0:
        return _fail("parent_manifest", "parent_epoch_mismatch",
                     f"advance {event.transition_index} of epoch {event.epoch} builds on an epoch "
                     f"{parent_epoch} manifest; only an epoch's FIRST transition (index 0) may "
                     "inherit a parent from an earlier epoch", checks=checks, **ident)
    inherited = parent_epoch != event.epoch
    done("parent_manifest")

    # ---- 3./4. apply transitionBytes and reproduce newFrontierRoot ---------------------------
    try:
        transition = fr.parse_transition_bytes(event.transition_bytes)
    except fr.FrontierError as exc:
        return _fail("transition", "transition_bytes_invalid", str(exc), checks=checks, **ident)
    try:
        # The epoch comes from the CONFIRMED EVENT's own topic — the contract's mapping key —
        # never from the transition payload, which is epoch-neutral by construction (spec §6.3).
        replayed = fr.verify_transition(
            parent_manifest, transition, event.new_frontier_root,
            epoch=event.epoch,
            epoch_pins={
                "benchmark_law_root": epoch_pins.benchmark_law_root,
                "runtime_abi_root": epoch_pins.runtime_abi_root,
            })
    except fr.RootMismatchError as exc:
        return _fail("frontier_replay", "new_root_mismatch", str(exc), checks=checks, **ident)
    except fr.FrontierError as exc:
        return _fail("frontier_replay", "transition_rejected", str(exc), checks=checks, **ident)
    target_profile = transition["target_profile"]
    if transition["new_release_root"] != event.candidate_release_root:
        return _fail("frontier_replay", "candidate_release_root_mismatch",
                     f"transitionBytes advances {target_profile!r} to "
                     f"{transition['new_release_root']} but the event names "
                     f"{event.candidate_release_root}", checks=checks, **ident)
    if transition["resulting_composition_root"] != event.composition_root:
        return _fail("frontier_replay", "composition_root_mismatch",
                     f"transitionBytes resulting composition {transition['resulting_composition_root']} "
                     f"!= event compositionRoot {event.composition_root}", checks=checks, **ident)
    new_manifest = replayed["new_manifest"]
    done("frontier_replay")

    # ---- miner / credit cross-check (targetProfileId lives ONLY in the credit event) ---------
    if credit_event is not None:
        mismatch = _credit_mismatch(event, credit_event, target_profile)
        if mismatch is not None:
            return _fail("miner_binding", "credit_binding_mismatch", mismatch, checks=checks,
                         **ident)
        done("miner_binding")

    # ---- 5./6. fetch the eval artifact by evalReportHash, and REHASH it ----------------------
    try:
        artifact = pub.fetch_json(event.eval_report_hash,
                                  hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        return _backlog("artifact", bl.missing_artifact(
            f"eval artifact {event.eval_report_hash} is not published: {exc}", event=event,
            observed_at=observed_at), checks=checks, new_manifest=new_manifest, **ident)
    except pub.PublicationError as exc:
        return _fail("artifact", "artifact_corrupt", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    try:
        ea.validate_artifact(artifact)
        rehashed = ea.eval_report_hash(artifact)
    except (ea.EvalArtifactError, fr.FrontierError) as exc:
        return _fail("artifact", "artifact_invalid", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    if rehashed != event.eval_report_hash:
        return _fail("artifact", "eval_report_hash_mismatch",
                     f"the fetched artifact rehashes to {rehashed}, the event names "
                     f"{event.eval_report_hash}", checks=checks, new_manifest=new_manifest,
                     **ident)
    done("artifact_rehash")

    # The deterministic verdict is taken from the CANARY-FREE artifact, here, before any
    # auxiliary evidence is even looked at. Everything downstream reads THIS.
    deterministic = ea.deterministic_verdict(ea.strip_canary(artifact))
    signed_era = ea.artifact_law(artifact) == al.LAW_OFF_CHAIN_SIGNATURE_V1

    # The opening is not needed to check that the published artifact binds the commitment from
    # this event's own confirmed epoch. Refuse a mismatched commitment immediately instead of
    # misclassifying an already-provable binding failure as work waiting on the future reveal.
    if artifact["entropy"]["commitment"] != epoch_pins.entropy_commitment:
        return _fail(
            "bindings", "EntropyMismatchError",
            f"artifact entropy commitment {artifact['entropy']['commitment']} != the on-chain "
            f"commitment {epoch_pins.entropy_commitment}",
            checks=checks, new_manifest=new_manifest, **ident)

    # A production artifact is intentionally hash-verifiable while its selection entropy remains
    # sealed. Deterministic replay cannot begin until the chain publishes the opening. This is
    # unresolved work, not a failed transition and never a pass inferred from the artifact's
    # carried verdict. Historical artifacts embed their opening and continue through unchanged.
    if "revealed_secret" not in artifact["entropy"] and epoch_pins.revealed_secret is None:
        return _backlog("entropy_opening", bl.entropy_opening_unavailable(
            f"eval artifact {event.eval_report_hash} rehashed successfully, but epoch "
            f"{event.epoch} has no confirmed EpochSecretRevealed opening yet",
            event=event, subject=f"epoch:{event.epoch}", observed_at=observed_at),
            checks=checks, new_manifest=new_manifest, **ident)
    embedded_opening = artifact["entropy"].get("revealed_secret")
    if epoch_pins.revealed_secret is not None and embedded_opening is not None \
            and embedded_opening != epoch_pins.revealed_secret:
        return _fail("bindings", "revealed_secret_mismatch",
                     f"the artifact opens the epoch commitment with {embedded_opening}, but "
                     f"EpochSecretRevealed put {epoch_pins.revealed_secret} on chain",
                     checks=checks, new_manifest=new_manifest, **ident)

    # ---- fetch the two objects verification must not be allowed to "skip" --------------------
    receipt_root = (artifact["receipt"]["wrapper_root"] if signed_era
                    else artifact["receipt"]["eval_report_root"])
    try:
        receipt_or_report = pub.fetch_json(
            receipt_root, hash_rule=pub.HASH_RULE_BENCHMARK_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        return _backlog("receipt", bl.receipt_unavailable(
            f"{'signed receipt' if signed_era else 'evaluation report'} {receipt_root} is not "
            f"published: {exc}", event=event, subject=receipt_root, observed_at=observed_at),
            checks=checks, new_manifest=new_manifest, **ident)
    except pub.PublicationError as exc:
        return _fail("receipt", "receipt_corrupt", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    try:
        counter_law = pub.fetch_json(artifact["counter_resource_law_root"],
                                     hash_rule=pub.HASH_RULE_FRONTIER_JSON, store=store)
    except pub.ObjectNotFoundError as exc:
        return _backlog("counter_resource_law", bl.counter_law_unavailable(
            f"counter-resource law {artifact['counter_resource_law_root']} is not published: "
            f"{exc}", event=event, subject=artifact["counter_resource_law_root"],
            observed_at=observed_at), checks=checks, new_manifest=new_manifest, **ident)
    except pub.PublicationError as exc:
        return _fail("counter_resource_law", "counter_law_corrupt", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)

    # Resolve exact-parent reports from public CAS bytes. The coordinator's worker objects are
    # transport only; replay independently follows frontier -> composition -> release -> module.
    eval_report = receipt_or_report["receipt"] if signed_era else receipt_or_report
    reported_incumbent = eval_report.get("incumbent")
    exact_parent_report = (
        isinstance(reported_incumbent, abc.Mapping)
        and frozenset(reported_incumbent) == frozenset(ea.INCUMBENT_EXACT_FIELDS))
    resolved_parent_execution = None
    if exact_parent_report:
        try:
            resolved_parent_execution = parent_exec.fetch_parent_execution(
                store=store, parent_manifest=parent_manifest,
                target_profile=target_profile)
        except pub.ObjectNotFoundError as exc:
            return _backlog(
                "parent_execution",
                bl.missing_artifact(
                    f"exact parent release/composition/module bytes are not published: {exc}",
                    event=event, subject=parent_manifest["profiles"][target_profile],
                    observed_at=observed_at),
                checks=checks, new_manifest=new_manifest, **ident)
        except (pub.PublicationError, parent_exec.ParentExecutionError,
                fr.FrontierError, RuntimeError, ValueError) as exc:
            return _fail("parent_execution", "parent_execution_invalid", str(exc),
                         checks=checks, new_manifest=new_manifest, **ident)
        try:
            resolved_identity = parent_exec.compact_identity(resolved_parent_execution)
        except parent_exec.ParentExecutionError as exc:
            return _fail("parent_execution", "parent_execution_invalid", str(exc),
                         checks=checks, new_manifest=new_manifest, **ident)
        if dict(reported_incumbent) != resolved_identity:
            return _fail(
                "parent_execution", "parent_execution_mismatch",
                "the evaluation report incumbent is not the parent release independently "
                "resolved from confirmed public bytes", checks=checks,
                new_manifest=new_manifest, **ident)
        try:
            projected_parent = ea.project_incumbent(resolved_identity)
        except (ea.EvalArtifactError, fr.FrontierError) as exc:
            return _fail("parent_execution", "parent_execution_invalid", str(exc),
                         checks=checks, new_manifest=new_manifest, **ident)
        if artifact["replay_inputs"]["incumbent"] != projected_parent:
            return _fail(
                "parent_execution", "parent_execution_projection_mismatch",
                "the artifact incumbent does not bind the publicly resolved parent release "
                "and module roots", checks=checks, new_manifest=new_manifest, **ident)
        done("parent_execution")

    # ---- 7. EVERY binding, against values the CHAIN asserts ----------------------------------
    try:
        verification_evidence = ({"receipt_wrapper": receipt_or_report,
                                  "signature_verifier": signature_verifier}
                                 if signed_era else {"eval_report": receipt_or_report})
        report = ea.verify_artifact(
            artifact,
            expected_parent_root=event.parent_frontier_root,
            expected_new_root=event.new_frontier_root,
            expected_release_root=event.candidate_release_root,
            expected_composition_root=event.composition_root,
            expected_runtime_abi_root=epoch_pins.runtime_abi_root,
            expected_benchmark_law_root=epoch_pins.benchmark_law_root,
            expected_counter_resource_law_root=epoch_pins.counter_resource_law_root,
            expected_entropy_commitment=epoch_pins.entropy_commitment,
            expected_epoch=event.epoch,
            expected_target_profile=target_profile,
            counter_resource_law=counter_law,
            store=store,
            epoch_pins={
                "benchmark_law_root": epoch_pins.benchmark_law_root,
                "runtime_abi_root": epoch_pins.runtime_abi_root,
            },
            revealed_entropy_secret=epoch_pins.revealed_secret,
            **verification_evidence)
    except (ea.EvalArtifactError, fr.FrontierError) as exc:
        return _fail("bindings", type(exc).__name__, str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    # namespaced, so V5-C's stage names never collide with this module's (both have a
    # ``frontier_replay``, and a reader must be able to tell which layer asserted what)
    checks.extend(f"artifact:{name}" for name in report["checks"])
    done("bindings")

    # The epoch commit binding V4 declares and never reads (see V4_DEAD_PATH_DEFECT) — checked
    # above via expected_entropy_commitment, and here against the CHAIN-REVEALED secret when the
    # reveal is in the synced window.
    if epoch_pins.revealed_secret is not None:
        done("chain_revealed_secret")

    # ---- 8. the fresh selection, re-derived from the COMMITTED entropy ------------------------
    opening = epoch_pins.revealed_secret or embedded_opening
    if opening is None:
        # Defensive reachability guard: sealed artifacts without a chain opening return above.
        return _backlog("entropy_opening", bl.entropy_opening_unavailable(
            f"epoch {event.epoch} has no entropy opening for deterministic replay",
            event=event, subject=f"epoch:{event.epoch}", observed_at=observed_at),
            checks=checks, new_manifest=new_manifest, **ident)
    entropy = dict(artifact["entropy"])
    try:
        recomputed = {label: expand_entropy(revealed_secret=opening,
                                            epoch=event.epoch,
                                            parent_frontier_root=event.parent_frontier_root,
                                            label=label) for label in ENTROPY_LABELS}
    except EntropyDomainDriftError as exc:
        return _fail("entropy_expansion", "entropy_domain_drift", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    except fr.FrontierError as exc:
        return _fail("entropy_expansion", "entropy_invalid", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    for label in ENTROPY_LABELS:
        if f"{label}_value" in entropy and entropy[f"{label}_value"] != recomputed[label]:
            return _fail("entropy_expansion", "entropy_value_mismatch",
                         f"entropy.{label}_value {entropy[f'{label}_value']} is not the "
                         f"chain-committed secret expanded under {ENTROPY_DOMAIN}|{label} "
                         f"({recomputed[label]})", checks=checks, new_manifest=new_manifest,
                         **ident)
        entropy[f"{label}_value"] = recomputed[label]
    done("entropy_expansion")

    # ---- 9. COMPLETE the selection check V5-C left partial ------------------------------------
    if screen is None:
        return _backlog("selection_completeness", bl.oracle_screen_unavailable(
            "no G6b oracle-cleanliness screen was supplied, so it is UNDETERMINED whether the "
            "selection walk skipped a legitimate index. V5-C proves every recorded case sits at "
            "its claimed index; completeness is this stage's job and it did not run.",
            event=event, subject="scoring.oracle_screen", observed_at=observed_at),
            checks=checks, new_manifest=new_manifest, **ident)
    available = getattr(screen, "available", None)
    if callable(available) and not available():
        return _backlog("selection_completeness", bl.oracle_screen_unavailable(
            f"the oracle screen {getattr(screen, 'name', type(screen).__name__)!r} reports itself "
            "unavailable on this host (frozen generators/runtime absent)", event=event,
            subject=getattr(screen, "name", "oracle_screen"), observed_at=observed_at),
            checks=checks, new_manifest=new_manifest, **ident)
    if not allow_test_doubles and getattr(screen, "consensus_grade", True) is False:
        return _backlog("selection_completeness", bl.oracle_screen_unavailable(
            f"the supplied screen {getattr(screen, 'name', type(screen).__name__)!r} declares "
            "itself NOT consensus-grade, so it cannot establish selection-skip completeness; the "
            "result is unresolved work, not a pass", event=event,
            subject=getattr(screen, "name", "oracle_screen"), observed_at=observed_at),
            checks=checks, new_manifest=new_manifest, **ident)
    try:
        completeness = verify_selection_complete(
            artifact["selection"], entropy=entropy,
            candidate_hash=artifact["candidate"]["candidate_hash"], screen=screen, burned=burned)
    except OracleScreenUnavailable as exc:
        return _backlog("selection_completeness", bl.oracle_screen_unavailable(
            str(exc), event=event, subject=getattr(screen, "name", "oracle_screen"),
            observed_at=observed_at), checks=checks, new_manifest=new_manifest, **ident)
    except (ea.EvalArtifactError, fr.FrontierError) as exc:
        return _fail("selection_completeness", "selection_incomplete", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    done("selection_completeness")

    # ---- 10. execute the candidate in the pinned sandbox, networkless PROVEN ------------------
    runner = sandbox if sandbox is not None else NullSandbox()
    try:
        if not allow_test_doubles and getattr(runner, "consensus_grade", True) is False:
            raise SandboxUnavailable(
                f"the supplied sandbox {getattr(runner, 'name', type(runner).__name__)!r} "
                "declares itself NOT consensus-grade; it did not execute the candidate under the "
                "pinned networkless law, so its result is unresolved work, not a pass")
        if not runner.available():
            raise SandboxUnavailable(
                f"sandbox {getattr(runner, 'name', type(runner).__name__)!r}: "
                + getattr(runner, "unavailable_reason",
                          "reports itself unavailable on this host"))
        execution = runner.execute(
            receipt_wrapper=receipt_or_report, artifact=artifact,
            incumbent_execution=resolved_parent_execution)
    except SandboxDependencyError as exc:
        # A DETERMINATION, not a backlog: the environment is wrong and the reader can fix it.
        return _fail("sandbox", "missing_dependency", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    except SandboxUnavailable as exc:
        return _backlog("sandbox", bl.sandbox_unavailable(
            str(exc), event=event, subject=getattr(runner, "name", type(runner).__name__),
            observed_at=observed_at), checks=checks, new_manifest=new_manifest, **ident)
    if not isinstance(execution, abc.Mapping) or "reproduced" not in execution:
        return _fail("sandbox", "sandbox_malformed_result",
                     f"sandbox {getattr(runner, 'name', '?')} returned "
                     f"{type(execution).__name__} without a 'reproduced' verdict", checks=checks,
                     new_manifest=new_manifest, **ident)
    # Networkless is a DEMONSTRATION, not a flag (ruling §9 W2). Three outcomes, no fourth:
    #   * the sandbox proved denial (a real socket(2) was refused in the process that ran the
    #     candidate) -> pass this gate;
    #   * it demonstrably did NOT (an IP socket was creatable) -> FAIL, naming what was observed;
    #   * it is consensus-grade but supplied no demonstration at all -> FAIL, because "networkless"
    #     asserted by a constant is exactly the vacuous evidence this gate exists to reject.
    # A declared TEST DOUBLE (consensus_grade False, only reachable via allow_test_doubles) may
    # still assert the flag without a proof — it is already excluded from consensus by that flag.
    proof = execution.get("networkless_evidence")
    has_proof = isinstance(proof, abc.Mapping)
    if execution.get("networkless") is not True:
        observed = (f"; the sandbox's own probe reports IP sockets STILL CREATABLE for "
                    f"{proof.get('unenforced_families')} — {proof.get('probes')}"
                    if has_proof else
                    "; the sandbox returned no networkless demonstration at all")
        return _fail("sandbox", "sandbox_not_networkless",
                     "the sandbox did not demonstrate networkless execution; a candidate that may "
                     "have reached the network is not a reproducible measurement" + observed,
                     checks=checks, new_manifest=new_manifest, **ident)
    if has_proof and proof.get("enforced") is not True:
        return _fail("sandbox", "sandbox_not_networkless",
                     f"the sandbox claimed networkless execution but its own evidence contradicts "
                     f"it: unenforced families {proof.get('unenforced_families')} — "
                     f"{proof.get('probes')}", checks=checks, new_manifest=new_manifest, **ident)
    if not has_proof and getattr(runner, "consensus_grade", True) is not False:
        return _fail("sandbox", "sandbox_networkless_unproven",
                     f"sandbox {execution.get('sandbox', getattr(runner, 'name', '?'))!r} asserts "
                     "networkless execution but returned no `networkless_evidence`; a constant is "
                     "not a proof, so the assertion is not accepted", checks=checks,
                     new_manifest=new_manifest, **ident)
    if not execution["reproduced"]:
        return _fail("sandbox", "sandbox_divergence",
                     f"the candidate did not reproduce the signed receipt in the pinned sandbox: "
                     f"{execution.get('code')}: {execution.get('reason')}", checks=checks,
                     new_manifest=new_manifest, **ident)
    bound_report_root = (artifact["receipt"]["receipt_hash"] if signed_era
                         else artifact["receipt"]["eval_report_root"])
    if execution.get("receipt_hash") not in (None, bound_report_root):
        return _fail("sandbox", "sandbox_receipt_hash_mismatch",
                     f"the sandbox rebuilt receipt {execution['receipt_hash']}, the artifact binds "
                     f"{bound_report_root}", checks=checks,
                     new_manifest=new_manifest, **ident)
    done("sandbox")

    # ---- 11. recompute utility / safety / rendered cost / fuel / storage ---------------------
    # The sandbox either returns the body it rebuilt, or — as ``benchmark-v2``'s replay does —
    # proves byte-identical reproduction and returns only the hash. In the second case the SIGNED
    # body IS the executed body, because reproducing its hash is what was just demonstrated.
    body = execution.get("body") or (
        receipt_or_report["receipt"] if signed_era else receipt_or_report)
    measured_from = ("sandbox-rebuilt body" if execution.get("body")
                     else "signed body the sandbox reproduced byte-identically")
    try:
        projected = ea.project_measurements(body)
    except (ea.EvalArtifactError, fr.FrontierError) as exc:
        return _fail("recompute", "measurement_projection_failed", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    if projected != artifact["measurements"]:
        differing = _measurement_diff(artifact["measurements"], projected)
        return _fail("recompute", "measurement_mismatch",
                     f"measurements recomputed from the {measured_from} execution do not match "
                     f"the artifact; differing: {differing}", checks=checks,
                     new_manifest=new_manifest, **ident)
    branch = counter_law["branch"]
    safety = _safety_report(body, branch)
    if safety.get("code"):
        return _fail("recompute", safety["code"], safety["reason"], checks=checks,
                     new_manifest=new_manifest, **ident)
    try:
        ppm = ea.evaluate_counter_resource_law(
            counter_law, projected["branches"][branch]["candidate"],
            projected["branches"][branch]["incumbent"])
    except (ea.EvalArtifactError, fr.FrontierError) as exc:
        return _fail("recompute", "counter_law_failed", str(exc), checks=checks,
                     new_manifest=new_manifest, **ident)
    accounting = artifact["resource_accounting"]
    for key, value in ppm.items():
        if accounting[key] != value:
            return _fail("recompute", "resource_accounting_mismatch",
                         f"resource_accounting.{key} is {accounting[key]}; recomputing the pinned "
                         f"counter law over the executed measurements gives {value}",
                         checks=checks, new_manifest=new_manifest, **ident)
    done("recompute")

    # ---- 12. did it beat the EXACT parent incumbent, under the frozen law? -------------------
    beat = _beat_incumbent(
        artifact, parent_manifest, target_profile, ppm, deterministic,
        store=store, resolved_parent_execution=resolved_parent_execution)
    if beat.get("code"):
        return _fail("incumbent_law", beat["code"], beat["reason"], checks=checks,
                     new_manifest=new_manifest, **ident)
    done("incumbent_law")

    # ---- auxiliary: the external-model evidence, AFTER the verdict exists --------------------
    result = _pass("done",
                   "advance replayed from confirmed chain truth: parent manifest verified, "
                   "transition applied, new root reproduced, artifact rehashed, every binding "
                   "checked, selection re-derived AND proven complete, candidate executed in the "
                   "pinned sandbox whose networkless execution was DEMONSTRATED (not asserted) by "
                   "a real socket probe, and the frozen law confirms it beat the exact parent "
                   "incumbent",
                   checks=checks, new_manifest=new_manifest, **ident)
    result.detail = {
        "target_profile": target_profile,
        "resource_accounting": dict(accounting),
        "verdict": dict(deterministic),
        "selection_completeness": completeness,
        "safety": safety["report"],
        "sandbox": {"name": execution.get("sandbox", getattr(runner, "name", "?")),
                    "networkless": True,
                    # WHY the line above is allowed to say True. A demonstration, or an explicit
                    # admission that this run had none (only reachable for a declared test double).
                    "networkless_basis": ("demonstrated: " + str(proof.get("probes"))
                                          if has_proof else
                                          "asserted by a declared TEST-DOUBLE sandbox — NOT "
                                          "demonstrated, and excluded from consensus by "
                                          "consensus_grade=False"),
                    # canonical values are never null: the key is PRESENT with the demonstration,
                    # or ABSENT because there was none (see networkless_basis).
                    **({"networkless_evidence": dict(proof)} if has_proof else {}),
                    "body_source": "sandbox" if execution.get("body") else "signed receipt"},
        "epoch_pins": epoch_pins.as_dict(),
        "incumbent": beat["report"],
        "eval_report_hash": report["eval_report_hash"],
    }
    result.auxiliary = canary_evidence(artifact, store=store, sealed_transcript=sealed_transcript,
                                       expected_code_identity=expected_canary_code_identity,
                                       revealed_entropy_secret=opening,
                                       event=event)
    # DEFENSIVE, and the whole point of the separation: the deterministic verdict must be
    # identical with and without the auxiliary block. If a future edit ever let the canary leak
    # into a check, this fires instead of shipping a canary-influenced consensus decision.
    if ea.deterministic_verdict(ea.strip_canary(artifact)) != deterministic:
        raise ea.CanaryInfluenceError(
            "the deterministic verdict changed once the auxiliary canary path ran; the "
            "consensus/attestation separation has been broken")
    if result.auxiliary.get("consensus_critical") is not False:  # pragma: no cover - defensive
        raise ea.CanaryInfluenceError("an auxiliary block claimed consensus criticality")
    return result


def _credit_mismatch(event: dp.FrontierAdvanced, credit: dp.CreditAccepted,
                     target_profile: str) -> Optional[str]:
    """The advance and its same-transaction credit must agree on every shared field."""
    if credit.epoch != event.epoch:
        return f"credit epoch {credit.epoch} != advance epoch {event.epoch}"
    if credit.miner.lower() != event.miner.lower():
        return (f"credit was minted for {credit.miner} but the advance attributes "
                f"{event.miner}; the miner binding is the one thing a reward depends on")
    for name, a, b in (("parentFrontierRoot", credit.parent_frontier_root,
                        event.parent_frontier_root),
                       ("newFrontierRoot", credit.new_frontier_root, event.new_frontier_root),
                       ("candidateReleaseRoot", credit.candidate_release_root,
                        event.candidate_release_root),
                       ("compositionRoot", credit.composition_root, event.composition_root),
                       ("evalReportHash", credit.eval_report_hash, event.eval_report_hash)):
        if a != b:
            return f"credit {name} {a} != advance {name} {b}"
    expected = dp.PROFILE_ID_HASHES[target_profile]
    if credit.target_profile_id != expected:
        named = credit.target_profile or "an unknown profile"
        return (f"the credit binds targetProfileId {credit.target_profile_id} ({named}) but "
                f"transitionBytes advances {target_profile!r} (keccak {expected}); the signed "
                "receipt was for a different profile than the manifest edit")
    return None


def _measurement_diff(bound: Mapping[str, Any], fresh: Mapping[str, Any]) -> List[str]:
    out: List[str] = []
    for label in ENTROPY_LABELS:
        for side in ("candidate", "incumbent"):
            b = (bound.get("branches", {}).get(label, {}) or {}).get(side, {})
            f = (fresh.get("branches", {}).get(label, {}) or {}).get(side, {})
            out.extend(f"{label}.{side}.{k}" for k in sorted(set(b) | set(f))
                       if b.get(k) != f.get(k))
    if bound.get("policy") != fresh.get("policy"):
        out.append("policy")
    return out


def _safety_report(body: Mapping[str, Any], branch: str) -> Dict[str, Any]:
    """Recompute the HARD safety gates from the executed candidate side."""
    scores = body.get("scores")
    if not isinstance(scores, abc.Mapping) or branch not in scores:
        return {"code": "safety_block_missing",
                "reason": f"the executed receipt body carries no scores[{branch!r}] branch, so "
                          "the hard safety gates cannot be recomputed"}
    candidate = scores[branch].get("candidate")
    if not isinstance(candidate, abc.Mapping):
        return {"code": "safety_block_missing",
                "reason": f"scores[{branch!r}] carries no candidate side"}
    hard = candidate.get("hard")
    if not isinstance(hard, abc.Mapping):
        return {"code": "safety_block_missing",
                "reason": "the executed candidate side carries no `hard` block; safety was not "
                          "measured, and 'not measured' is never 'passed'"}
    observed = {gate: hard.get(gate) for gate in SAFETY_ZERO_GATES}
    failures = [gate for gate, value in observed.items()
                if not isinstance(value, int) or isinstance(value, bool) or value != 0]
    if failures:
        return {"code": "safety_violation",
                "reason": f"the executed candidate violates hard safety gate(s) {failures}; "
                          f"measured {observed}"}
    if hard.get("replay_identical") is not True:
        return {"code": "safety_violation",
                "reason": "the executed candidate is not replay-identical; a non-deterministic "
                          "candidate cannot be admitted under a deterministic law"}
    report = {gate: int(value) for gate, value in observed.items()}
    report["replay_identical"] = True
    return {"code": None, "report": report}


def _beat_incumbent(artifact: Mapping[str, Any], parent_manifest: Mapping[str, Any],
                    target_profile: str, ppm: Mapping[str, int],
                    deterministic: Mapping[str, Any], *,
                    store: Optional[pub.ContentStore] = None,
                    resolved_parent_execution: Optional[Mapping[str, Any]] = None) \
        -> Dict[str, Any]:
    """Confirm the candidate beat THE EXACT PARENT INCUMBENT under the frozen law.

    "Exact" is load-bearing: the incumbent is the release the PARENT frontier serves for the
    target profile at this parent root — not the current champion, not the profile's default, not
    whatever the receipt happened to name. The receipt's incumbent identity is checked against it,
    and the admission floor (utility strictly improves by >= 1 ppm, ppm bounded, resource ppm
    non-zero, incumbent side == exactly 1_000_000 ppm) is enforced here.

    WHERE THAT FLOOR IS ACTUALLY ENFORCED (§10 rig era). NOWHERE ON CHAIN. These refusals used to
    cite ``InvalidUtilityScore`` and ``InvalidResourceScore`` as contract reverts; both are errors
    of the RETIRED ``CoreTexMemoryMining`` (``:414`` and ``:416``) and neither appears anywhere in
    ``BotcoinMiningRigsV1`` or ``RigCoreTexStateRegistry``. The rig mining contract takes
    ``scoreBeforePpm`` / ``scoreAfterPpm`` into the EIP-712 digest (``:73``, ``:895-896``) and
    validates neither: no range check, no improvement check, no zero check, and no ``_validateScores``.

    The behaviour here is unchanged and remains the conservative one — the floor is enforced, so a
    candidate that would fail it is refused. What changes is the CLAIM: an auditor reading this was
    told the chain would reject such a receipt, and it would not. The refusal reasons now say
    "OFF-CHAIN admission rule" because that is what they are, and this validator plus the
    coordinator's pre-sign checks are the ONLY places the floor exists.
    """
    prior = parent_manifest["profiles"][target_profile]
    if artifact["candidate"]["prior_release_root"] != prior:
        return {"code": "wrong_incumbent",
                "reason": f"the candidate was evaluated against prior release "
                          f"{artifact['candidate']['prior_release_root']} but the parent frontier "
                          f"serves {prior} for {target_profile!r}"}
    incumbent = artifact["replay_inputs"]["incumbent"]
    is_initial_reference = (
        parent_exec.PRODUCTION_REFERENCE_RELEASE_ROOTS.get(target_profile) == prior)
    incumbent_fields = frozenset(incumbent)
    historical_fields = frozenset(ea.INCUMBENT_FIELDS)
    exact_fields = frozenset(ea.INCUMBENT_EXACT_FIELDS)
    receipt_roots = (artifact.get("receipt") or {}).get("code_roots")
    legacy_reference_allowed = (
        artifact.get("format") == ea.ARTIFACT_FORMAT_V1_SIGNED_ERA
        or parent_exec.is_pre_exact_parent_code_roots(receipt_roots))
    resolved = None
    if incumbent_fields == exact_fields:
        if store is not None:
            try:
                resolved = parent_exec.fetch_parent_execution(
                    store=store, parent_manifest=parent_manifest,
                    target_profile=target_profile)
            except Exception as exc:
                return {"code": "parent_execution_invalid",
                        "reason": "the exact parent module bytes could not be resolved and "
                                  f"re-hashed: {type(exc).__name__}: {exc}"}
        elif isinstance(resolved_parent_execution, abc.Mapping):
            resolved = dict(resolved_parent_execution)
        if resolved is None:
            return {"code": "parent_execution_unverified",
                    "reason": "the exact incumbent was not resolved from its parent "
                              "composition, release, and module bytes"}
        if resolved.get("exec") != incumbent.get("exec") \
                or resolved.get("release_root") != prior:
            return {"code": "wrong_incumbent_execution",
                    "reason": "the resolved parent release is not the exact execution claimed "
                              "by the evaluation"}
        try:
            projected = ea.project_incumbent(parent_exec.compact_identity(resolved))
        except (ea.EvalArtifactError, parent_exec.ParentExecutionError,
                fr.FrontierError) as exc:
            return {"code": "parent_execution_invalid", "reason": str(exc)}
        if incumbent != projected:
            return {"code": "wrong_incumbent_execution",
                    "reason": "the artifact incumbent does not bind the parent composition "
                              "delegation, release root, and module bytes"}
    elif incumbent_fields != historical_fields:
        return {"code": "wrong_incumbent_execution",
                "reason": "the incumbent identity is neither the historical reference shape "
                          "nor the exact release/module shape"}
    elif not legacy_reference_allowed:
        return {"code": "wrong_incumbent_execution",
                "reason": "admission under this law requires the exact five-field parent "
                          "release/module identity; three fields are closed to frozen pre-cut "
                          "artifacts"}
    if incumbent.get("exec") == "reference":
        if not is_initial_reference:
            return {"code": "wrong_incumbent_execution",
                    "reason": f"the report executed reference for parent release {prior}, but "
                              f"that is not the initial production release for "
                              f"{target_profile!r}"}
        if incumbent.get("id") != "reference-runtime" \
                or incumbent.get("candidate_hash") != fr.ZERO_ROOT:
            return {"code": "wrong_incumbent_execution",
                    "reason": "the initial reference incumbent carries a non-reference identity"}
    elif incumbent.get("exec") == "candidate_module":
        if incumbent_fields != exact_fields:
            return {"code": "wrong_incumbent_execution",
                    "reason": "candidate-module execution requires the exact release and "
                              "module identity"}
    else:
        return {"code": "wrong_incumbent_execution",
                "reason": f"unsupported incumbent execution {incumbent.get('exec')!r}"}
    if not deterministic["admit"]:
        return {"code": "not_admitted",
                "reason": f"the deterministic Benchmark-v2 decision is "
                          f"{deterministic['verdict']!r}; that decision is the SOLE admission law "
                          "and it did not admit this candidate"}
    before = ppm["utility_before_ppm"]
    after = ppm["utility_after_ppm"]
    if after <= before:
        return {"code": "no_utility_improvement",
                "reason": f"utility_after_ppm {after} does not exceed utility_before_ppm "
                          f"{before}; this is an OFF-CHAIN admission rule, not a chain revert"}
    if after - before < 1:
        return {"code": "utility_improvement_too_small",
                "reason": f"utility improvement {after - before} ppm is below the 1 ppm floor"}
    if after > ea.MICRO or before > ea.MICRO:
        return {"code": "utility_out_of_range",
                "reason": f"utility ppm ({before}, {after}) exceeds the {ea.MICRO} ceiling"}
    if ppm["resource_before_ppm"] == 0 or ppm["resource_after_ppm"] == 0:
        return {"code": "resource_ppm_zero",
                "reason": "a zero resource ppm has no ratio; this is an OFF-CHAIN admission rule, "
                          "not a chain revert"}
    if ppm["resource_before_ppm"] != ea.MICRO:
        return {"code": "incumbent_not_unit",
                "reason": f"resource_before_ppm is {ppm['resource_before_ppm']}; the incumbent is "
                          f"the unit of comparison and must evaluate to exactly {ea.MICRO}"}
    return {"code": None,
            "report": {"target_profile": target_profile, "parent_release_root": prior,
                       "incumbent": dict(artifact["replay_inputs"]["incumbent"]),
                       "utility_before_ppm": before, "utility_after_ppm": after,
                       "utility_gain_ppm": after - before,
                       "resource_before_ppm": ppm["resource_before_ppm"],
                       "resource_after_ppm": ppm["resource_after_ppm"],
                       "verdict": deterministic["verdict"]}}


# --------------------------------------------------------------------------- #
# Stream replay
# --------------------------------------------------------------------------- #
@dataclass
class StreamResult:
    """A whole ordered advance stream, replayed with live-root continuity per epoch."""

    results: List[ReplayResult] = field(default_factory=list)
    final_root_by_epoch: Dict[int, str] = field(default_factory=dict)
    #: The DERIVED epoch head of each epoch whose inheritance the stream could determine
    #: (operator ruling §17.237). Absent for an epoch whose first transition was never observed
    #: or was reorged out — such an epoch is left unresolved, never re-derived.
    epoch_parents: Dict[int, sy.EpochInheritance] = field(default_factory=dict)
    #: Why an epoch's inheritance could not be derived, by epoch.
    unresolved_inheritance: Dict[int, str] = field(default_factory=dict)
    stopped_at: Optional[Tuple[int, int]] = None
    stopped_reason: str = ""

    @property
    def outcome(self) -> bl.Outcome:
        """FAIL if anything failed, else BACKLOG if anything is unresolved, else PASS."""
        if any(r.is_fail for r in self.results):
            return bl.FAIL
        if any(r.is_backlog for r in self.results):
            return bl.BACKLOG
        return bl.PASS

    @property
    def passed(self) -> List[ReplayResult]:
        return [r for r in self.results if r.ok]

    @property
    def backlogged(self) -> List[ReplayResult]:
        return [r for r in self.results if r.is_backlog]

    @property
    def failed(self) -> List[ReplayResult]:
        return [r for r in self.results if r.is_fail]

    def as_dict(self) -> Dict[str, Any]:
        return {"format": REPLAY_RESULT_FORMAT + "/stream", "outcome": str(self.outcome),
                "results": [r.as_dict() for r in self.results],
                "final_root_by_epoch": dict(self.final_root_by_epoch),
                "epoch_parents": {str(e): i.as_dict()
                                  for e, i in sorted(self.epoch_parents.items())},
                "unresolved_inheritance": {str(e): why for e, why
                                           in sorted(self.unresolved_inheritance.items())},
                "stopped_at": list(self.stopped_at) if self.stopped_at else None,
                "stopped_reason": self.stopped_reason}


def replay_stream(events: Sequence[dp.FrontierAdvanced], *, store: pub.ContentStore,
                  pins: Optional[dp.PinResolver] = None,
                  backlog_store: Optional[bl.Backlog] = None,
                  credits: Optional[Mapping[Tuple[int, int], dp.CreditAccepted]] = None,
                  genesis_frontier_root: Optional[str] = None,
                  finalizations: Sequence[dp.MemoryEpochFinalized] = (),
                  **replay_kwargs) -> StreamResult:
    """Replay a historical pre-rig frontier stream, threading its root through each epoch.

    This helper is not called by the production descriptor-v3 pipeline. Production epoch
    bootstrap comes from the confirmed verifier context parent and is checked in
    :func:`rig_events.context_parent_continuity`.

    Continuity is the off-chain twin of the registry's CAS: within an epoch, advance *n*'s
    ``parentFrontierRoot`` must be advance *n-1*'s ``newFrontierRoot``. A wrong-parent event stops
    the epoch with ``live_root_mismatch``.

    WHERE AN EPOCH'S FIRST PARENT COMES FROM (operator ruling §17.237). It is DERIVED from
    confirmed history by :func:`sync.derive_epoch_parents` — the confirmed FINAL (i.e. sealed by a
    confirmed ``CoreTexMemoryEpochFinalized``, supplied as ``finalizations``) root of the latest
    preceding epoch that has any transition, or ``genesis_frontier_root`` for the earliest one. It
    is emphatically NOT read out of an epoch-context pin any more: a coordinator-published head
    would make the validator's epoch parent a coordinator input, which rule 6 forbids.

    An epoch whose inheritance cannot be derived — its first transition was never observed, or was
    reorged out — starts with ``live_root=None``. The reason is recorded in
    ``unresolved_inheritance`` and surfaced, and the inheritance is NEVER re-derived from whatever
    transition happens to come first in the remaining feed.

    A BACKLOG does NOT stop the stream: the event's ``newFrontierRoot`` is still confirmed chain
    truth and its transition still applies, so the frontier keeps advancing while the EARNING
    stays unverified. A FAIL does stop it — everything after a broken link is unreplayable.
    """
    out = StreamResult()
    derived, inherit_anomalies = sy.derive_epoch_parents(
        events, genesis_frontier_root=genesis_frontier_root, finalizations=finalizations)
    out.epoch_parents = derived
    for anomaly in inherit_anomalies:
        if anomaly.epoch is not None and anomaly.epoch not in derived:
            out.unresolved_inheritance.setdefault(anomaly.epoch,
                                                  f"{anomaly.code}: {anomaly.detail}")
    live: Dict[int, Optional[str]] = {}
    halted: set = set()
    for event in events:
        if event.epoch in halted:
            continue
        if event.epoch not in live:
            found = derived.get(event.epoch)
            # None means UNVERIFIED, not "anything goes": replay_advance simply cannot apply the
            # first-parent check, and every downstream check still runs.
            live[event.epoch] = None if found is None else found.inherited_parent_root
        result = replay_advance(event, store=store, pins=pins,
                                credit_event=(credits or {}).get(event.key),
                                live_root=live[event.epoch], **replay_kwargs)
        out.results.append(result)
        if backlog_store is not None and result.backlog_entry is not None:
            backlog_store.record(result.backlog_entry)
        if result.is_fail:
            out.stopped_at = event.key
            out.stopped_reason = f"{result.stage}/{result.code}: {result.reason}"
            halted.add(event.epoch)
            continue
        # PASS or BACKLOG: the confirmed new root is chain truth, so the frontier advances.
        live[event.epoch] = event.new_frontier_root
        out.final_root_by_epoch[event.epoch] = event.new_frontier_root
    return out
