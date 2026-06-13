/**
 * validator-runtime — RUNTIME / UX hygiene unit tests (BUILD 1/2/3).
 *
 * These exercise the LOGIC only, with an injected fake spawner / fake clock /
 * fake stderr sink. NOTHING here runs a real multi-GB torch install, spawns
 * the real reranker, or touches scoring semantics — a real end-to-end venv
 * build is a manual/CI step. All assertions are about path resolution,
 * idempotency, the exact pinned pip argv, the verify-import probe, the
 * clear-error path, the thread heuristic, and that progress stays off stdout.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

import {
  // BUILD 1
  PINNED_SCORER_DEPS,
  PINNED_TORCH_VERSION,
  PINNED_TRANSFORMERS_VERSION,
  TORCH_CPU_WHEEL_INDEX,
  scorerVenvPython,
  probeScorerHealth,
  scorerHealthIsAcceptable,
  pinnedPipInstallArgv,
  manualBootstrapInstructions,
  bootstrapScorerVenv,
  VenvBootstrapError,
  // BUILD 2
  RERANKER_THREAD_CAP,
  estimatePhysicalCores,
  resolveRerankerThreadDefault,
  applyRerankerThreadDefault,
  // BUILD 3
  progressEnabled,
  formatEta,
  ProgressReporter,
  renderSummaryBlock,
} from '../../dist/validator-runtime.js';

const RERANKER_SCRIPT = '/fake/pkg/scripts/reranker_runner.py';

/**
 * Build a fake SyncSpawner whose behavior is keyed by the leading argv token.
 * Records every call for assertions. `healthJson` controls what the --health
 * probe emits; `venvFails` / `pipFails` flip the create/install steps.
 */
function makeFakeSpawner(opts = {}) {
  const calls = [];
  const healthJson = opts.healthJson ?? { torch: PINNED_TORCH_VERSION, transformers: PINNED_TRANSFORMERS_VERSION, cuda: false };
  const spawner = (command, argv) => {
    calls.push({ command, argv: [...argv] });
    if (argv.includes('--health')) {
      if (opts.healthFails) return { status: 1, stdout: '', stderr: 'boom', error: undefined };
      return { status: 0, stdout: JSON.stringify(healthJson), stderr: '', error: undefined };
    }
    if (argv[0] === '-m' && argv[1] === 'venv') {
      return opts.venvFails
        ? { status: 1, stdout: '', stderr: 'venv: command not found', error: undefined }
        : { status: 0, stdout: '', stderr: '', error: undefined };
    }
    if (argv[0] === '-m' && argv[1] === 'pip') {
      return opts.pipFails
        ? { status: 1, stdout: '', stderr: 'No matching distribution for torch==2.6.0+cpu', error: undefined }
        : { status: 0, stdout: 'Successfully installed torch', stderr: '', error: undefined };
    }
    return { status: 127, stdout: '', stderr: 'unexpected', error: undefined };
  };
  spawner.calls = calls;
  return spawner;
}

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-runtime-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ─── BUILD 1: venv bootstrap ──────────────────────────────────────────────────

describe('BUILD 1 — pinned dep constants mirror requirements-frozen.txt', () => {
  test('the pinned pip argv uses the CPU wheel index and the frozen torch/transformers', () => {
    const argv = pinnedPipInstallArgv();
    assert.deepEqual(argv.slice(0, 5), ['-m', 'pip', 'install', '--no-input', '--extra-index-url']);
    assert.equal(argv[5], TORCH_CPU_WHEEL_INDEX);
    assert.ok(argv.includes('torch==2.6.0+cpu'), 'torch CPU wheel pin present');
    assert.ok(argv.includes('transformers==4.55.0'), 'transformers pin present');
    for (const dep of PINNED_SCORER_DEPS) assert.ok(argv.includes(dep), `${dep} in argv`);
  });

  test('scorerVenvPython lands under <stateDir>/scorer-venv/bin/python', () => {
    assert.equal(scorerVenvPython('/x/state'), join('/x/state', 'scorer-venv', 'bin', 'python'));
  });

  test('manualBootstrapInstructions names the exact recovery command', () => {
    const txt = manualBootstrapInstructions('/v/bin/python');
    assert.match(txt, /python3 -m venv/);
    assert.match(txt, /pip install/);
    assert.match(txt, /--no-venv-bootstrap/);
  });
});

describe('BUILD 1 — scorerHealthIsAcceptable (CPU + pinned versions)', () => {
  test('accepts pinned torch+transformers on CPU', () => {
    assert.deepEqual(
      scorerHealthIsAcceptable({ torch: PINNED_TORCH_VERSION, transformers: PINNED_TRANSFORMERS_VERSION, cuda: false }),
      { ok: true },
    );
    // dev-suffixed torch build (2.6.0+cpu) still matches the pinned prefix.
    assert.equal(scorerHealthIsAcceptable({ torch: '2.6.0+cpu', transformers: '4.55.0', cuda: false }).ok, true);
  });

  test('rejects null health, active CUDA, and version drift with a reason', () => {
    assert.equal(scorerHealthIsAcceptable(null).ok, false);
    assert.match(scorerHealthIsAcceptable({ torch: '2.6.0', transformers: '4.55.0', cuda: true }).reason, /CUDA/);
    assert.match(scorerHealthIsAcceptable({ torch: '2.5.0', transformers: '4.55.0', cuda: false }).reason, /torch 2\.5\.0/);
    assert.match(scorerHealthIsAcceptable({ torch: '2.6.0', transformers: '4.50.0', cuda: false }).reason, /transformers 4\.50\.0/);
    assert.match(scorerHealthIsAcceptable({ transformers: '4.55.0', cuda: false }).reason, /torch not importable/);
  });
});

describe('BUILD 1 — probeScorerHealth parses the runner --health JSON', () => {
  test('parses a healthy fingerprint; null on failure / non-JSON', () => {
    const ok = makeFakeSpawner();
    assert.deepEqual(
      probeScorerHealth(ok, '/v/python', RERANKER_SCRIPT),
      { torch: PINNED_TORCH_VERSION, transformers: PINNED_TRANSFORMERS_VERSION, cuda: false },
    );
    assert.deepEqual(ok.calls[0], { command: '/v/python', argv: [RERANKER_SCRIPT, '--health'] });

    assert.equal(probeScorerHealth(makeFakeSpawner({ healthFails: true }), '/v/python', RERANKER_SCRIPT), null);
    const garbage = () => ({ status: 0, stdout: 'not json', stderr: '', error: undefined });
    assert.equal(probeScorerHealth(garbage, '/v/python', RERANKER_SCRIPT), null);
  });
});

describe('BUILD 1 — bootstrapScorerVenv decision tree', () => {
  test('opt-out skips and records the operator interpreter (no spawn)', () => {
    const spawner = makeFakeSpawner();
    const res = bootstrapScorerVenv(
      { stateDir: '/x/state', rerankerScriptPath: RERANKER_SCRIPT, envScorerPython: '/my/python', optOut: true },
      spawner,
    );
    assert.equal(res.status, 'skipped-opt-out');
    assert.equal(res.scorerPython, '/my/python');
    assert.equal(spawner.calls.length, 0, 'opt-out must not spawn anything');
  });

  test('idempotent: a working CORETEX_RERANKER_PYTHON wins, never builds a venv', () => {
    const spawner = makeFakeSpawner();
    const res = bootstrapScorerVenv(
      { stateDir: '/x/state', rerankerScriptPath: RERANKER_SCRIPT, envScorerPython: '/env/python', optOut: false },
      spawner,
    );
    assert.equal(res.status, 'skipped-existing-env');
    assert.equal(res.scorerPython, '/env/python');
    // Only the --health probe ran — no venv creation, no pip.
    assert.equal(spawner.calls.length, 1);
    assert.ok(spawner.calls[0].argv.includes('--health'));
  });

  test('idempotent: an existing bootstrapped venv that passes the probe is reused', () => withTmpDir((dir) => {
    const venvPython = scorerVenvPython(dir);
    mkdirSync(dirname(venvPython), { recursive: true });
    writeFileSync(venvPython, '#!/bin/sh\n'); // make existsSync(venvPython) true
    const spawner = makeFakeSpawner();
    const res = bootstrapScorerVenv(
      { stateDir: dir, rerankerScriptPath: RERANKER_SCRIPT, optOut: false },
      spawner,
    );
    assert.equal(res.status, 'skipped-existing-venv');
    assert.equal(res.scorerPython, venvPython);
    assert.equal(spawner.calls.length, 1, 'only the reuse probe ran (no create/pip)');
  }));

  test('cold create: venv → exact pinned pip argv → verify; records the venv python', () => withTmpDir((dir) => {
    const spawner = makeFakeSpawner();
    const res = bootstrapScorerVenv(
      { stateDir: dir, rerankerScriptPath: RERANKER_SCRIPT, optOut: false },
      spawner,
    );
    assert.equal(res.status, 'created');
    assert.equal(res.scorerPython, scorerVenvPython(dir));

    const venvCall = spawner.calls.find((c) => c.argv[0] === '-m' && c.argv[1] === 'venv');
    assert.ok(venvCall, 'python3 -m venv was invoked');
    assert.equal(venvCall.argv[2], join(dir, 'scorer-venv'));

    const pipCall = spawner.calls.find((c) => c.argv[0] === '-m' && c.argv[1] === 'pip');
    assert.ok(pipCall, 'pip install was invoked');
    assert.deepEqual(pipCall.argv, pinnedPipInstallArgv(), 'pip argv is exactly the pinned command');
    assert.equal(pipCall.command, scorerVenvPython(dir), 'pip runs through the venv interpreter');

    // A verify --health probe ran AFTER the install.
    assert.ok(spawner.calls.some((c) => c.argv.includes('--health')));
  }));

  test('clear-error path: venv creation failure throws an actionable VenvBootstrapError', () => withTmpDir((dir) => {
    const spawner = makeFakeSpawner({ venvFails: true });
    assert.throws(
      () => bootstrapScorerVenv({ stateDir: dir, rerankerScriptPath: RERANKER_SCRIPT, optOut: false }, spawner),
      (err) => {
        assert.ok(err instanceof VenvBootstrapError);
        assert.match(err.message, /venv creation failed/);
        assert.match(err.message, /Manual scorer-venv bootstrap/);
        return true;
      },
    );
  }));

  test('clear-error path: pip failure names the deps + index and never returns ready', () => withTmpDir((dir) => {
    const spawner = makeFakeSpawner({ pipFails: true });
    assert.throws(
      () => bootstrapScorerVenv({ stateDir: dir, rerankerScriptPath: RERANKER_SCRIPT, optOut: false }, spawner),
      (err) => {
        assert.ok(err instanceof VenvBootstrapError);
        assert.match(err.message, /pip install of the pinned scorer deps failed/);
        assert.match(err.message, /torch==2\.6\.0\+cpu/);
        assert.match(err.message, new RegExp(TORCH_CPU_WHEEL_INDEX.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')));
        return true;
      },
    );
  }));

  test('clear-error path: built but verify-import fails (e.g. CUDA active) is a hard error', () => withTmpDir((dir) => {
    const spawner = makeFakeSpawner({ healthJson: { torch: '2.6.0', transformers: '4.55.0', cuda: true } });
    assert.throws(
      () => bootstrapScorerVenv({ stateDir: dir, rerankerScriptPath: RERANKER_SCRIPT, optOut: false }, spawner),
      (err) => {
        assert.ok(err instanceof VenvBootstrapError);
        assert.match(err.message, /failed the import verify/);
        assert.match(err.message, /CUDA/);
        return true;
      },
    );
  }));

  test('a broken env interpreter falls through to build the managed venv (not silently trusted)', () => withTmpDir((dir) => {
    // env python health probe returns drifted torch → unacceptable → build venv.
    let probeCount = 0;
    const spawner = (command, argv) => {
      if (argv.includes('--health')) {
        probeCount++;
        // first probe = env python (drifted); later probe = the built venv (good)
        const drifted = command === '/broken/python';
        return {
          status: 0,
          stdout: JSON.stringify(drifted
            ? { torch: '2.0.0', transformers: '4.55.0', cuda: false }
            : { torch: PINNED_TORCH_VERSION, transformers: PINNED_TRANSFORMERS_VERSION, cuda: false }),
          stderr: '', error: undefined,
        };
      }
      return { status: 0, stdout: '', stderr: '', error: undefined };
    };
    const res = bootstrapScorerVenv(
      { stateDir: dir, rerankerScriptPath: RERANKER_SCRIPT, envScorerPython: '/broken/python', optOut: false },
      spawner,
    );
    assert.equal(res.status, 'created');
    assert.equal(res.scorerPython, scorerVenvPython(dir));
    assert.ok(probeCount >= 2, 'probed the broken env then the freshly built venv');
  }));
});

// ─── BUILD 2: thread default ──────────────────────────────────────────────────

describe('BUILD 2 — reranker thread default', () => {
  test('explicit override always wins', () => {
    const r = resolveRerankerThreadDefault({ explicit: '8', logicalCpuCount: 64 });
    assert.equal(r.threads, 8);
    assert.equal(r.source, 'override');
  });

  test('caps a high-core HT machine at RERANKER_THREAD_CAP', () => {
    // 64 logical → ~32 physical → capped at the 16-thread cap (the 4090-box fix).
    const r = resolveRerankerThreadDefault({ logicalCpuCount: 64 });
    assert.equal(r.source, 'auto');
    assert.equal(r.threads, RERANKER_THREAD_CAP);
    assert.equal(RERANKER_THREAD_CAP, 16);
  });

  test('halves logical cores as an HT/physical estimate on a mid host', () => {
    // 12 logical → 6 physical (< cap) → 6.
    assert.equal(estimatePhysicalCores(12), 6);
    assert.equal(resolveRerankerThreadDefault({ logicalCpuCount: 12 }).threads, 6);
    // odd counts are taken as-is (no clean SMT halving signal).
    assert.equal(estimatePhysicalCores(9), 9);
    // tiny hosts floor at 1.
    assert.equal(estimatePhysicalCores(1), 1);
    assert.equal(estimatePhysicalCores(2), 2);
    assert.equal(resolveRerankerThreadDefault({ logicalCpuCount: 1 }).threads, 1);
  });

  test('malformed override is ignored and falls through to auto', () => {
    const r = resolveRerankerThreadDefault({ explicit: 'not-a-number', logicalCpuCount: 8 });
    assert.equal(r.source, 'auto');
    assert.equal(r.threads, 4); // 8 logical → 4 physical
  });

  test('applyRerankerThreadDefault writes RERANKER_NUM_THREADS without clobbering an override', () => {
    const overridden = { RERANKER_NUM_THREADS: '3' };
    assert.equal(applyRerankerThreadDefault(overridden, 64).source, 'override');
    assert.equal(overridden.RERANKER_NUM_THREADS, '3');

    const auto = {};
    const res = applyRerankerThreadDefault(auto, 64);
    assert.equal(res.source, 'auto');
    assert.equal(auto.RERANKER_NUM_THREADS, String(RERANKER_THREAD_CAP));
  });
});

// ─── BUILD 3: progress / ETA UX ───────────────────────────────────────────────

describe('BUILD 3 — progress enable decision', () => {
  test('explicit enabled wins; else off on --no-progress / CI / non-TTY', () => {
    assert.equal(progressEnabled({ explicitEnabled: true, noProgressFlag: true, ci: true, isTTY: false }), true);
    assert.equal(progressEnabled({ explicitEnabled: false, noProgressFlag: false, ci: false, isTTY: true }), false);
    assert.equal(progressEnabled({ noProgressFlag: true, ci: false, isTTY: true }), false);
    assert.equal(progressEnabled({ noProgressFlag: false, ci: true, isTTY: true }), false);
    assert.equal(progressEnabled({ noProgressFlag: false, ci: false, isTTY: false }), false);
    assert.equal(progressEnabled({ noProgressFlag: false, ci: false, isTTY: true }), true);
  });
});

describe('BUILD 3 — formatEta', () => {
  test('formats seconds / minutes / hours and guards non-finite', () => {
    assert.equal(formatEta(12), '12s');
    assert.equal(formatEta(184), '3m04s');
    assert.equal(formatEta(3723), '1h02m');
    assert.equal(formatEta(NaN), '?');
    assert.equal(formatEta(-5), '?');
  });
});

describe('BUILD 3 — ProgressReporter goes to stderr-sink only, never stdout', () => {
  test('a disabled reporter writes nothing', () => {
    const out = [];
    const p = new ProgressReporter({ label: 'x', total: 10, enabled: false, write: (c) => out.push(c) }, false);
    p.update(5); p.advance(); p.done();
    assert.equal(out.length, 0);
  });

  test('an enabled reporter renders to its injected sink with pct + ETA, then a final line', () => {
    const out = [];
    let clock = 1000;
    const p = new ProgressReporter(
      { label: 'download corpus', total: 100, unit: 'bytes', enabled: true, write: (c) => out.push(c), now: () => clock },
      false, // non-TTY → newline lines, never \r
    );
    clock = 2000; p.update(50);   // 50/100 in 1s → ETA ~1s
    clock = 3000; p.update(100);  // done
    p.done();
    const joined = out.join('');
    assert.match(joined, /download corpus: 50\/100 bytes \(50%\)/);
    assert.match(joined, /ETA/);
    assert.match(joined, /100\/100 bytes \(100%\)/);
    // Non-TTY rendering uses plain newlines, never a carriage return.
    assert.ok(!joined.includes('\r'), 'non-TTY progress must not emit carriage returns');
  });

  test('throttles intermediate renders but always emits the terminal update', () => {
    const out = [];
    let clock = 0;
    const p = new ProgressReporter(
      { label: 'replay', total: 1000, enabled: true, write: (c) => out.push(c), now: () => clock },
      false,
    );
    // Rapid updates within the 200ms throttle window collapse to one render…
    p.update(10);            // first render always shows
    clock = 50; p.update(20); // throttled
    clock = 100; p.update(30); // throttled
    const renderedBeforeFinal = out.length;
    clock = 100; p.update(1000); // reaching total is forced through
    assert.ok(out.length > renderedBeforeFinal, 'reaching total forces a render despite throttle');
    assert.match(out.join(''), /1000\/1000/);
  });
});

describe('BUILD 3 — renderSummaryBlock', () => {
  test('PASS/FAIL banner + indented lines to the injected sink', () => {
    const out = [];
    renderSummaryBlock('coretex-validator-setup', true, ['corpusRoot=0xabc', 'state file: /x/state.json'], (c) => out.push(c));
    const joined = out.join('');
    assert.match(joined, /coretex-validator-setup: PASS/);
    assert.match(joined, /corpusRoot=0xabc/);

    const fail = [];
    renderSummaryBlock('coretex-validator-sync', false, ['something broke'], (c) => fail.push(c));
    assert.match(fail.join(''), /coretex-validator-sync: FAIL/);
  });
});
