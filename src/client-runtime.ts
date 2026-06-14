/**
 * client-runtime — RUNTIME / UX hygiene shared by coretex-client-setup
 * and coretex-client-sync.
 *
 * NOTHING in this module touches scoring semantics, thresholds, packs, or
 * calibration. It is purely about making the standalone client
 * one-command and friendly:
 *
 *   1. Python venv bootstrap (BUILD 1) — make score replay self-contained
 *      given only `python3`. Idempotent (skips a working interpreter / an
 *      already-bootstrapped venv), opt-outable, and safe (no half-built venv
 *      claimed as ready). The resolved interpreter path is recorded into the
 *      client state file so sync reuses it via CORETEX_RERANKER_PYTHON.
 *
 *   2. CPU thread default (BUILD 2) — pick a sane RERANKER_NUM_THREADS when the
 *      user has not set one (cap conservatively to avoid the NUMA/HT
 *      oversubscription collapse). An explicit override ALWAYS wins. This only
 *      affects runtime speed, never scores.
 *
 *   3. Progress / ETA UX (BUILD 3) — lightweight TTY-aware progress to stderr
 *      so the machine-readable JSON on stdout stays clean, plus a final
 *      PASS/FAIL summary block.
 *
 * The pinned dependency versions below MUST match scripts/requirements-frozen.txt
 * (the canonical CPU torch/transformers pin). They are duplicated here as code
 * constants because the standalone installed package ships only its own
 * scripts/ dir — the repo-level scripts/requirements-frozen.txt is NOT present
 * in a node_modules install — so the bootstrap cannot read that file at runtime.
 */
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import * as os from 'node:os';

// ─── BUILD 1: pinned scorer dependencies (mirror of requirements-frozen.txt) ──

/**
 * The PyTorch CPU wheel index. torch==2.6.0+cpu only resolves through this
 * extra index (see scripts/requirements-frozen.txt header + scripts/a100-setup.sh).
 */
export const TORCH_CPU_WHEEL_INDEX = 'https://download.pytorch.org/whl/cpu';

/**
 * Canonical pinned scorer deps for CPU score replay. Byte-for-byte the
 * torch/transformers (and their hard runtime peers) pins in
 * scripts/requirements-frozen.txt. We install the full minimal closure that the
 * Qwen3 reranker_runner.py needs to import + run on CPU; pip resolves the
 * remaining transitive deps. Keep this in sync with requirements-frozen.txt.
 */
export const PINNED_SCORER_DEPS: readonly string[] = [
  'torch==2.6.0+cpu',
  'transformers==4.55.0',
  'tokenizers==0.21.4',
  'safetensors==0.4.5',
  'huggingface_hub==0.36.2',
  'numpy==1.26.4',
] as const;

/** Pinned torch/transformers versions the verify-import probe asserts. */
export const PINNED_TORCH_VERSION = '2.6.0';
export const PINNED_TRANSFORMERS_VERSION = '4.55.0';

/** Bootstrapped venv layout under the client state dir. */
export const SCORER_VENV_DIRNAME = 'scorer-venv';

/** Path of the venv interpreter under a state dir (POSIX layout: bin/python). */
export function scorerVenvPython(stateDir: string): string {
  // Clients run on Linux/CPU hosts (the reranker is CPU-pinned); POSIX
  // venv layout (bin/python) is the only supported target. The Windows
  // Scripts/python.exe layout is intentionally not constructed.
  return join(stateDir, SCORER_VENV_DIRNAME, 'bin', 'python');
}

/** Result of the venv-python `--health` import probe. Mirrors the JSON object
 *  emitted by packages/coretex/scripts/reranker_runner.py:_run_health(). */
export interface ScorerHealth {
  readonly torch?: string | null;
  readonly transformers?: string | null;
  readonly cuda?: boolean;
  readonly python?: string;
  /** Reranker math dtype the runner pins (fp32 on both CPU and GPU paths). */
  readonly dtype?: string;
  /** Whether TF32 matmul is allowed (must be false — fp32-exact contract). */
  readonly tf32?: boolean;
  readonly device?: string;
}

/**
 * Spawn a function shape (injected in unit tests). Mirrors the relevant subset
 * of node:child_process spawnSync's synchronous return so the bootstrap logic
 * is fully testable without ever running a multi-GB torch install.
 */
export type SyncSpawner = (
  command: string,
  argv: readonly string[],
) => Pick<SpawnSyncReturns<string>, 'status' | 'stdout' | 'stderr' | 'error'>;

/** The real spawner (text-mode, inherits nothing): used in production. */
export const realSyncSpawner: SyncSpawner = (command, argv) =>
  spawnSync(command, [...argv], { encoding: 'utf8' });

/**
 * Run a python interpreter's `--health` probe through reranker_runner.py and
 * parse the JSON fingerprint. Returns null when the interpreter is missing,
 * fails, or emits unparseable output (treated as "not a working scorer").
 */
export function probeScorerHealth(
  spawner: SyncSpawner,
  pythonBin: string,
  rerankerScriptPath: string,
): ScorerHealth | null {
  const res = spawner(pythonBin, [rerankerScriptPath, '--health']);
  if (res.error || res.status !== 0 || typeof res.stdout !== 'string') return null;
  try {
    const parsed = JSON.parse(res.stdout.trim()) as ScorerHealth;
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * A scorer health fingerprint is acceptable for CPU score replay iff:
 *   - torch reports the pinned version,
 *   - transformers reports the pinned version,
 *   - CUDA is NOT active (the client scorer is CPU-only by contract).
 */
export function scorerHealthIsAcceptable(health: ScorerHealth | null): { ok: boolean; reason?: string } {
  if (!health) return { ok: false, reason: 'health probe failed (interpreter missing or torch/transformers not importable)' };
  if (health.cuda === true) return { ok: false, reason: 'CUDA is active — the client scorer is CPU-only' };
  if (health.torch == null) return { ok: false, reason: 'torch not importable' };
  if (!String(health.torch).startsWith(PINNED_TORCH_VERSION)) {
    return { ok: false, reason: `torch ${health.torch} != pinned ${PINNED_TORCH_VERSION}` };
  }
  if (health.transformers == null) return { ok: false, reason: 'transformers not importable' };
  if (!String(health.transformers).startsWith(PINNED_TRANSFORMERS_VERSION)) {
    return { ok: false, reason: `transformers ${health.transformers} != pinned ${PINNED_TRANSFORMERS_VERSION}` };
  }
  return { ok: true };
}

// ─── BUILD 1b: bundle-pinned scorer runtime fingerprint assertion ─────────────
//
// The 5-ppm replay tolerance absorbs the CPU↔GPU fp32 numeric drift the keyless
// scorer path is designed around, but it does NOT absorb a wrong torch /
// transformers / model / prompt-template pin — those can shift logits well past
// 5 ppm and silently corrupt a score replay. Before any score replay the
// client therefore asserts that the resolved scorer runtime fingerprint
// matches the bundle manifest's reranker pins. This is a HARD GATE, not a
// runtime-speed nicety: it never changes scores, it refuses to score at all
// when the runtime cannot reproduce the pinned scorer.

/** Bundle-manifest pins the scorer runtime fingerprint is asserted against. */
export interface ScorerRuntimeBundlePins {
  /** Pinned reranker model id (bundle.model.reranker.modelId). */
  readonly modelId: string;
  /** Pinned reranker revision (bundle.model.reranker.revision). */
  readonly revision: string;
  /** Pinned torch version range from the profile runtimePin (e.g. '2.6.*'). */
  readonly torchRange: string;
  /** Pinned transformers version range from the profile runtimePin (e.g. '4.55.*'). */
  readonly transformersRange: string;
  /** runtimePin.buildFlags — when it contains 'cpu-only', CUDA must be off. */
  readonly buildFlags?: readonly string[] | undefined;
  /** Optional pinned prompt-template hash (forward-compat: bundles that record
   *  one bind the resolved template exactly; absent → only structural canonical
   *  check via the resolved hash the caller supplies). */
  readonly promptTemplateHash?: string | undefined;
}

/** The resolved scorer identity the sync is about to construct + score with. */
export interface ResolvedScorerRuntime {
  /** Resolved reranker model id (forced to the bundle pin by createClientReranker). */
  readonly modelId: string;
  /** Resolved reranker revision. */
  readonly revision: string;
  /** Locally computed qwenRerankerPromptTemplateHash() for the resolved instruction. */
  readonly promptTemplateHash: string;
}

/**
 * Match a concrete installed version against a runtimePin range token. Accepts
 * the bundle's `X.Y.*` / `X.*` ranges and an exact `X.Y.Z`, stripping a wheel
 * build/pre suffix (e.g. '2.6.0+cpu') before comparing. Mirrors the bundle
 * module's matchSemverRange; duplicated here because this runtime helper is a
 * standalone module (it ships the pinned-version constants for the same reason).
 */
export function scorerVersionMatchesRange(installed: string, range: string): boolean {
  if (range === installed) return true;
  const core = installed.split(/[+\-]/, 1)[0]!;
  const minorGlob = range.match(/^(\d+)\.(\d+)\.\*$/);
  if (minorGlob) {
    const [, maj, min] = minorGlob;
    return new RegExp(`^${maj}\\.${min}\\.\\d+$`).test(core);
  }
  const majorGlob = range.match(/^(\d+)\.\*$/);
  if (majorGlob) {
    return new RegExp(`^${majorGlob[1]}\\.\\d+\\.\\d+$`).test(core);
  }
  if (/^\d+\.\d+\.\d+$/.test(range)) return core === range;
  return false;
}

/**
 * Assert the resolved scorer runtime fingerprint matches the bundle pins.
 * Returns { ok: true } only when EVERY pinned facet agrees:
 *   - the `--health` probe imports torch/transformers in the pinned ranges,
 *   - the math contract is fp32 with TF32 disabled (logit-exact),
 *   - CUDA is off when the bundle is cpu-only,
 *   - the resolved model id + revision equal the bundle reranker pins,
 *   - the resolved prompt-template hash equals the bundle's (when pinned).
 * Any mismatch returns { ok: false, reason } — the caller hard-errors BEFORE
 * constructing the scorer or replaying any score. Never touches scoring math.
 */
export function scorerRuntimeMatchesBundle(
  health: ScorerHealth | null,
  pins: ScorerRuntimeBundlePins,
  resolved: ResolvedScorerRuntime,
): { ok: boolean; reason?: string } {
  if (!health) {
    return { ok: false, reason: 'scorer --health probe failed (interpreter missing or torch/transformers not importable)' };
  }
  const cpuOnly = (pins.buildFlags ?? []).includes('cpu-only');
  if (cpuOnly && health.cuda === true) {
    return { ok: false, reason: 'CUDA is active but the bundle runtimePin is cpu-only' };
  }
  if (health.torch == null) return { ok: false, reason: 'torch not importable in the scorer runtime' };
  if (!scorerVersionMatchesRange(String(health.torch), pins.torchRange)) {
    return { ok: false, reason: `torch ${health.torch} does not match bundle runtimePin ${pins.torchRange}` };
  }
  if (health.transformers == null) return { ok: false, reason: 'transformers not importable in the scorer runtime' };
  if (!scorerVersionMatchesRange(String(health.transformers), pins.transformersRange)) {
    return { ok: false, reason: `transformers ${health.transformers} does not match bundle runtimePin ${pins.transformersRange}` };
  }
  // The runner reports dtype/tf32 in its fingerprint; the 5-ppm tolerance is
  // only valid for fp32 with TF32 disabled. A bf16/tf32 runtime is rejected.
  if (health.dtype !== undefined && health.dtype !== 'fp32') {
    return { ok: false, reason: `scorer dtype ${health.dtype} != fp32 (logit-exact replay contract)` };
  }
  if (health.tf32 === true) {
    return { ok: false, reason: 'scorer TF32 matmul is enabled — the fp32-exact replay contract requires tf32=false' };
  }
  if (resolved.modelId !== pins.modelId) {
    return { ok: false, reason: `resolved reranker modelId ${resolved.modelId} != bundle pin ${pins.modelId}` };
  }
  if (resolved.revision !== pins.revision) {
    return { ok: false, reason: `resolved reranker revision ${resolved.revision} != bundle pin ${pins.revision}` };
  }
  if (pins.promptTemplateHash !== undefined
    && resolved.promptTemplateHash.toLowerCase() !== pins.promptTemplateHash.toLowerCase()) {
    return {
      ok: false,
      reason: `resolved prompt-template hash ${resolved.promptTemplateHash} != bundle pin ${pins.promptTemplateHash}`,
    };
  }
  return { ok: true };
}

/** The exact `pip install` argv the bootstrap constructs (no host invented). */
export function pinnedPipInstallArgv(): string[] {
  return [
    '-m', 'pip', 'install',
    '--no-input',
    '--extra-index-url', TORCH_CPU_WHEEL_INDEX,
    ...PINNED_SCORER_DEPS,
  ];
}

/** The manual command a failed bootstrap prints so an operator can recover. */
export function manualBootstrapInstructions(venvPython: string): string {
  return [
    'Manual scorer-venv bootstrap:',
    `  python3 -m venv <state-dir>/${SCORER_VENV_DIRNAME}`,
    `  ${venvPython} ${pinnedPipInstallArgv().join(' ')}`,
    `Then verify: ${venvPython} <package>/scripts/reranker_runner.py --health`,
    'or manage your own interpreter and set CORETEX_RERANKER_PYTHON (skip this step with --no-venv-bootstrap / CORETEX_CLIENT_SKIP_VENV=1).',
  ].join('\n');
}

export type VenvBootstrapStatus =
  | 'skipped-opt-out'
  | 'skipped-existing-env'
  | 'skipped-existing-venv'
  | 'created';

export interface VenvBootstrapResult {
  readonly status: VenvBootstrapStatus;
  /** Resolved scorer interpreter path to record + export as CORETEX_RERANKER_PYTHON. */
  readonly scorerPython: string;
  readonly detail: string;
}

export interface VenvBootstrapInputs {
  readonly stateDir: string;
  readonly rerankerScriptPath: string;
  /** CORETEX_RERANKER_PYTHON, if the operator points at their own interpreter. */
  readonly envScorerPython?: string | undefined;
  /** python3 launcher used to CREATE the venv (default 'python3'). */
  readonly python3Bin?: string | undefined;
  /** Opt out: --no-venv-bootstrap / CORETEX_CLIENT_SKIP_VENV=1. */
  readonly optOut: boolean;
}

/**
 * Idempotent, opt-outable, safe Python venv bootstrap for CPU score replay.
 *
 * Decision order (no scoring semantics touched anywhere):
 *   1. opt-out → SKIP, record nothing (caller manages CORETEX_RERANKER_PYTHON).
 *   2. CORETEX_RERANKER_PYTHON already imports torch+transformers at the pinned
 *      versions on CPU → SKIP, record it.
 *   3. a previously-bootstrapped <stateDir>/scorer-venv passes the same probe
 *      → SKIP, record it (incremental setups never reinstall).
 *   4. otherwise CREATE the venv (python3 -m venv), pip-install the PINNED
 *      deps, then VERIFY the same import probe. Any failure throws
 *      VenvBootstrapError with the actionable manual command — a half-built
 *      venv is NEVER returned as ready.
 *
 * The spawner is injected so unit tests drive the whole decision tree (path
 * resolution, idempotency, the exact pinned pip argv, the verify probe, and
 * the clear-error path) WITHOUT a real torch install.
 */
export class VenvBootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VenvBootstrapError';
  }
}

export function bootstrapScorerVenv(
  inputs: VenvBootstrapInputs,
  spawner: SyncSpawner,
): VenvBootstrapResult {
  const venvPython = scorerVenvPython(inputs.stateDir);
  const python3Bin = inputs.python3Bin ?? 'python3';

  if (inputs.optOut) {
    return {
      status: 'skipped-opt-out',
      scorerPython: inputs.envScorerPython ?? python3Bin,
      detail: 'venv bootstrap opted out (--no-venv-bootstrap / CORETEX_CLIENT_SKIP_VENV=1); the operator manages CORETEX_RERANKER_PYTHON',
    };
  }

  // (2) A working operator-provided interpreter wins — never build a venv we
  //     do not need.
  if (inputs.envScorerPython) {
    const health = probeScorerHealth(spawner, inputs.envScorerPython, inputs.rerankerScriptPath);
    const verdict = scorerHealthIsAcceptable(health);
    if (verdict.ok) {
      return {
        status: 'skipped-existing-env',
        scorerPython: inputs.envScorerPython,
        detail: `CORETEX_RERANKER_PYTHON=${inputs.envScorerPython} already imports torch ${health!.torch} + transformers ${health!.transformers} on CPU`,
      };
    }
    // An env interpreter that fails the probe is NOT silently replaced — that
    // would mask a misconfigured host. Fall through to build the managed venv,
    // but the env path is informational only.
  }

  // (3) An already-bootstrapped venv that still passes the probe is reused.
  if (existsSync(venvPython)) {
    const health = probeScorerHealth(spawner, venvPython, inputs.rerankerScriptPath);
    const verdict = scorerHealthIsAcceptable(health);
    if (verdict.ok) {
      return {
        status: 'skipped-existing-venv',
        scorerPython: venvPython,
        detail: `existing scorer venv ${venvPython} imports torch ${health!.torch} + transformers ${health!.transformers} on CPU`,
      };
    }
    // A stale/broken venv falls through to a rebuild over the same dir
    // (python -m venv is happy to re-target; pip --no-input is idempotent).
  }

  // (4) Build the venv → pip install pinned deps → verify.
  const venvCreate = spawner(python3Bin, ['-m', 'venv', join(inputs.stateDir, SCORER_VENV_DIRNAME)]);
  if (venvCreate.error || venvCreate.status !== 0) {
    throw new VenvBootstrapError(
      `python venv creation failed (${python3Bin} -m venv): ${spawnFailureDetail(venvCreate)}\n${manualBootstrapInstructions(venvPython)}`,
    );
  }

  const pipArgv = pinnedPipInstallArgv();
  const pip = spawner(venvPython, pipArgv);
  if (pip.error || pip.status !== 0) {
    throw new VenvBootstrapError(
      `pip install of the pinned scorer deps failed: ${spawnFailureDetail(pip)}\n`
      + `Pinned deps: ${PINNED_SCORER_DEPS.join(' ')} (extra index ${TORCH_CPU_WHEEL_INDEX}).\n`
      + `${manualBootstrapInstructions(venvPython)}`,
    );
  }

  const health = probeScorerHealth(spawner, venvPython, inputs.rerankerScriptPath);
  const verdict = scorerHealthIsAcceptable(health);
  if (!verdict.ok) {
    throw new VenvBootstrapError(
      `scorer venv built but failed the import verify: ${verdict.reason}.\n`
      + `Expected torch ${PINNED_TORCH_VERSION} + transformers ${PINNED_TRANSFORMERS_VERSION}, CPU only.\n`
      + `${manualBootstrapInstructions(venvPython)}`,
    );
  }

  return {
    status: 'created',
    scorerPython: venvPython,
    detail: `bootstrapped scorer venv ${venvPython} with torch ${health!.torch} + transformers ${health!.transformers} (CPU)`,
  };
}

function spawnFailureDetail(
  res: Pick<SpawnSyncReturns<string>, 'status' | 'stdout' | 'stderr' | 'error'>,
): string {
  if (res.error) return res.error.message;
  const stderr = (res.stderr ?? '').toString().trim();
  const stdout = (res.stdout ?? '').toString().trim();
  return `exit ${res.status}: ${stderr || stdout || '(no output)'}`;
}

// ─── BUILD 2: sane CPU thread default ─────────────────────────────────────────

/**
 * Hard cap on the auto-selected reranker thread count. On a 64-logical-core
 * host the streaming Qwen reranker collapsed to 0.74 pairs/s (NUMA + HT
 * oversubscription) versus 4.8 pairs/s at 16 threads — so we never auto-select
 * above this even on very large hosts. This is a RUNTIME-SPEED cap only; the
 * scores are byte-identical regardless of thread count.
 */
export const RERANKER_THREAD_CAP = 16;

export interface ThreadDefaultResult {
  /** Resolved thread count to pass through as RERANKER_NUM_THREADS. */
  readonly threads: number;
  /** 'override' = the operator set it; 'auto' = we chose it. */
  readonly source: 'override' | 'auto';
  /** Human-readable reason for the chosen value (logged, never affects scores). */
  readonly reason: string;
}

/**
 * Estimate physical cores from os.cpus(). Node only exposes logical CPUs, so we
 * conservatively HALVE the logical count when it is even and > 2 (the common
 * 2-way SMT/HyperThreading case) to avoid counting hyperthreads as physical
 * cores. This is a heuristic floor, not an exact topology read — and it is only
 * used to pick a runtime thread count, never to influence scoring.
 */
export function estimatePhysicalCores(logicalCount: number): number {
  if (!Number.isFinite(logicalCount) || logicalCount <= 1) return 1;
  if (logicalCount > 2 && logicalCount % 2 === 0) return logicalCount / 2;
  return logicalCount;
}

/**
 * Resolve RERANKER_NUM_THREADS. An explicit positive-integer override ALWAYS
 * wins. Otherwise pick min(estimatedPhysicalCores, RERANKER_THREAD_CAP) — a
 * conservative value that dodges the NUMA/HT oversubscription collapse. This
 * affects ONLY runtime speed; scores are identical at any thread count.
 */
export function resolveRerankerThreadDefault(inputs: {
  readonly explicit?: string | number | undefined;
  readonly logicalCpuCount: number;
}): ThreadDefaultResult {
  if (inputs.explicit !== undefined && String(inputs.explicit).trim() !== '') {
    const n = Number(inputs.explicit);
    if (Number.isInteger(n) && n > 0) {
      return { threads: n, source: 'override', reason: `RERANKER_NUM_THREADS=${n} set by operator (override honored)` };
    }
    // A malformed override is ignored (fall through to auto) rather than
    // crashing the client — but we say so.
  }
  const physical = estimatePhysicalCores(inputs.logicalCpuCount);
  const threads = Math.max(1, Math.min(RERANKER_THREAD_CAP, physical));
  return {
    threads,
    source: 'auto',
    reason: `auto-selected ${threads} threads = min(estimated physical cores ${physical} from ${inputs.logicalCpuCount} logical, cap ${RERANKER_THREAD_CAP}); runtime speed only, scores unaffected`,
  };
}

/** Read the live logical CPU count (production caller). */
export function logicalCpuCount(): number {
  return os.cpus().length || 1;
}

/**
 * Apply the resolved thread default to an env object for the spawned scorer.
 * NEVER overwrites an explicit RERANKER_NUM_THREADS; returns the result so the
 * caller can log it. Pure on the passed env clone — no scoring path touched.
 */
export function applyRerankerThreadDefault(
  env: NodeJS.ProcessEnv,
  logicalCount: number = logicalCpuCount(),
): ThreadDefaultResult {
  const resolved = resolveRerankerThreadDefault({ explicit: env['RERANKER_NUM_THREADS'], logicalCpuCount: logicalCount });
  env['RERANKER_NUM_THREADS'] = String(resolved.threads);
  return resolved;
}

// ─── BUILD 3: progress / ETA UX ───────────────────────────────────────────────

export interface ProgressOptions {
  /** Phase label (e.g. 'download corpus', 'registry log replay'). */
  readonly label: string;
  /** Total units (bytes, events, block chunks, advances). Optional/streaming. */
  readonly total?: number | undefined;
  /** Unit noun for the human line (default 'units'). */
  readonly unit?: string | undefined;
  /** Force-enable/disable; default decides from TTY/CI/--no-progress. */
  readonly enabled?: boolean | undefined;
  /** Sink (default process.stderr.write) — results NEVER go here. */
  readonly write?: ((chunk: string) => void) | undefined;
  /** Clock injection for deterministic ETA tests. */
  readonly now?: (() => number) | undefined;
}

/**
 * Decide whether progress rendering is on. Progress is purely cosmetic and
 * goes to stderr; it must never be on in a non-interactive / machine-readable
 * context where it could be confused with output. Precedence:
 *   explicit `enabled` → off when --no-progress / CI=1 / not a TTY → else on.
 */
export function progressEnabled(inputs: {
  readonly explicitEnabled?: boolean | undefined;
  readonly noProgressFlag: boolean;
  readonly ci: boolean;
  readonly isTTY: boolean;
}): boolean {
  if (inputs.explicitEnabled !== undefined) return inputs.explicitEnabled;
  if (inputs.noProgressFlag) return false;
  if (inputs.ci) return false;
  return inputs.isTTY;
}

/** Format seconds as a compact `1h02m`, `3m04s`, or `12s` ETA string. */
export function formatEta(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return '?';
  const s = Math.round(seconds);
  if (s >= 3600) return `${Math.floor(s / 3600)}h${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}m`;
  if (s >= 60) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`;
  return `${s}s`;
}

/**
 * Lightweight progress reporter. When enabled it writes throttled progress
 * lines to stderr (carriage-return refresh on a TTY, plain newlines otherwise);
 * when disabled every method is a no-op. It NEVER writes to stdout, so the
 * machine-readable JSON status emitted by the CLIs stays byte-clean.
 */
export class ProgressReporter {
  private readonly label: string;
  private readonly total: number | undefined;
  private readonly unit: string;
  private readonly enabled: boolean;
  private readonly write: (chunk: string) => void;
  private readonly now: () => number;
  private readonly isTTY: boolean;
  private readonly startMs: number;
  private current = 0;
  private lastRenderMs = 0;
  private rendered = false;

  constructor(opts: ProgressOptions, isTTY: boolean) {
    this.label = opts.label;
    this.total = opts.total;
    this.unit = opts.unit ?? 'units';
    this.enabled = opts.enabled ?? true;
    this.write = opts.write ?? ((chunk) => { process.stderr.write(chunk); });
    this.now = opts.now ?? (() => Date.now());
    this.isTTY = isTTY;
    this.startMs = this.now();
  }

  /** Set absolute progress, throttled to ~1 render / 200ms (last render forced). */
  update(current: number): void {
    if (!this.enabled) return;
    this.current = current;
    const ms = this.now();
    if (this.rendered && ms - this.lastRenderMs < 200 && (this.total === undefined || current < this.total)) return;
    this.lastRenderMs = ms;
    this.rendered = true;
    this.write(this.render(current));
  }

  /** Advance by a delta (convenience for chunked loops). */
  advance(delta = 1): void {
    this.update(this.current + delta);
  }

  /** Finish the phase line (newline so the next phase / summary is clean). */
  done(): void {
    if (!this.enabled) return;
    if (this.isTTY && this.rendered) this.write('\n');
    else if (!this.rendered) this.write(this.render(this.current) + (this.isTTY ? '\n' : ''));
  }

  private render(current: number): string {
    const elapsedS = (this.now() - this.startMs) / 1000;
    let body: string;
    if (this.total !== undefined && this.total > 0) {
      const pct = Math.min(100, Math.floor((current / this.total) * 100));
      const rate = elapsedS > 0 ? current / elapsedS : 0;
      const remaining = rate > 0 ? (this.total - current) / rate : NaN;
      body = `[progress] ${this.label}: ${current}/${this.total} ${this.unit} (${pct}%) ETA ${formatEta(remaining)}`;
    } else {
      body = `[progress] ${this.label}: ${current} ${this.unit} (${elapsedS.toFixed(0)}s elapsed)`;
    }
    return this.isTTY ? `\r${body}` : `${body}\n`;
  }
}

/**
 * Build a ProgressReporter wired to the standard enable decision. `write`,
 * `now`, and `isTTY` are injectable for tests; production reads
 * process.stderr.isTTY.
 */
export function makeProgress(
  opts: ProgressOptions & { noProgressFlag?: boolean; ci?: boolean; isTTY?: boolean },
): ProgressReporter {
  const isTTY = opts.isTTY ?? Boolean((process.stderr as { isTTY?: boolean }).isTTY);
  const enabled = progressEnabled({
    explicitEnabled: opts.enabled,
    noProgressFlag: opts.noProgressFlag ?? false,
    ci: opts.ci ?? (process.env['CI'] === '1' || process.env['CI'] === 'true'),
    isTTY,
  });
  return new ProgressReporter({ ...opts, enabled }, isTTY);
}

/**
 * Render a final PASS/FAIL summary block to stderr (never stdout). `ok=true`
 * → PASS, else FAIL. Lines are arbitrary key facts the CLI wants surfaced.
 */
export function renderSummaryBlock(
  command: string,
  ok: boolean,
  lines: readonly string[],
  write: (chunk: string) => void = (chunk) => { process.stderr.write(chunk); },
): void {
  const banner = ok ? 'PASS' : 'FAIL';
  const out = [
    '',
    `── ${command}: ${banner} ──`,
    ...lines.map((l) => `  ${l}`),
    '',
  ].join('\n');
  write(out + '\n');
}
