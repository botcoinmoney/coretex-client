/**
 * FAIL-CLOSED validator scorer (§2 score-honesty):
 *   - the deterministic stub / minilm are unreachable from the validator
 *     rescore path regardless of env;
 *   - model id + revision are locked to the bundle manifest pins;
 *   - a misconfigured env is a hard error NAMING the required vars;
 *   - the spawned validator-sync CLI applies the same gate to sync and
 *     verify-patch, and --skip-score-replay is the only skip (exit code 3,
 *     distinct from success).
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  assertValidatorRerankerEnv,
  createValidatorReranker,
  buildPostRevealEvalReportArtifact,
} from '../../dist/index.js';
import { SKIP_SCORE_REPLAY_EXIT_CODE } from '../../dist/validator-sync-cli.js';

const PINS = { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'pinned-test-revision' };

describe('assertValidatorRerankerEnv — fail-closed env gate', () => {
  test('clean env passes (qwen3 is forced even when CORETEX_RERANKER is unset)', () => {
    assert.doesNotThrow(() => assertValidatorRerankerEnv(PINS, {}));
    assert.doesNotThrow(() => assertValidatorRerankerEnv(PINS, { CORETEX_RERANKER: 'qwen3' }));
  });

  test('the deterministic stub is refused with an error naming the required vars', () => {
    for (const selector of ['deterministic', 'minilm', 'DETERMINISTIC', 'something-else']) {
      assert.throws(
        () => assertValidatorRerankerEnv(PINS, { CORETEX_RERANKER: selector }),
        (err) => {
          assert.match(err.message, /fail-closed/);
          assert.match(err.message, /CORETEX_RERANKER=qwen3/);
          assert.match(err.message, /--skip-score-replay/);
          assert.ok(err.message.includes(PINS.modelId), 'error must name the pinned model');
          return true;
        },
        `selector ${selector} must be refused`,
      );
    }
  });

  test('env model/revision overrides conflicting with the bundle pins are hard errors', () => {
    assert.throws(
      () => assertValidatorRerankerEnv(PINS, { CORETEX_RERANKER_MODEL_ID: 'evil/other-model' }),
      /CORETEX_RERANKER_MODEL_ID=evil\/other-model != bundle manifest pin/,
    );
    assert.throws(
      () => assertValidatorRerankerEnv(PINS, { CORETEX_RERANKER_REVISION: 'wrong-rev' }),
      /CORETEX_RERANKER_REVISION=wrong-rev != bundle manifest pin/,
    );
    // Redundant-but-equal env is allowed (it cannot diverge from the pin).
    assert.doesNotThrow(() => assertValidatorRerankerEnv(PINS, {
      CORETEX_RERANKER_MODEL_ID: PINS.modelId,
      CORETEX_RERANKER_REVISION: PINS.revision,
    }));
  });

  test('missing bundle pins are a hard error', () => {
    assert.throws(() => assertValidatorRerankerEnv({ modelId: '', revision: '' }, {}), /pins are required/);
  });

  test('invalid CORETEX_RERANKER_MODE is a hard error', () => {
    assert.throws(() => assertValidatorRerankerEnv(PINS, { CORETEX_RERANKER_MODE: 'magic' }), /CORETEX_RERANKER_MODE=magic/);
  });
});

describe('createValidatorReranker — pinned qwen3 regardless of env', () => {
  test('resolves the bundle-pinned model id + revision (spawn mode, no python launched until score())', async () => {
    const reranker = await createValidatorReranker(PINS, { CORETEX_RERANKER_MODE: 'spawn' });
    assert.equal(reranker.model, `${PINS.modelId}@${PINS.revision}`);
  });

  test('refuses a stub selector before constructing anything', async () => {
    await assert.rejects(
      () => createValidatorReranker(PINS, { CORETEX_RERANKER: 'deterministic' }),
      /fail-closed/,
    );
  });
});

// ── spawned CLI: the same gate guards sync and verify-patch ──────────────────

const cliPath = fileURLToPath(new URL('../../dist/validator-sync-cli.js', import.meta.url));

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-fail-closed-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runCli(cliArgs, env = {}, cwd) {
  return spawnSync(process.execPath, [cliPath, ...cliArgs], {
    encoding: 'utf8',
    ...(cwd ? { cwd } : {}),
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('CORETEX_') && !k.startsWith('BOTCOIN_') && k !== 'BASE_RPC_URL' && k !== 'EPOCH_ID')),
      ...env,
    },
  });
}

function writeBundle(dir, bundleHash) {
  const path = join(dir, 'bundle.json');
  writeFileSync(path, JSON.stringify({
    bundleHash,
    corpus: { root: `0x${'aa'.repeat(32)}` },
    model: { reranker: { modelId: PINS.modelId, revision: PINS.revision } },
  }));
  return path;
}

describe('validator-sync CLI — fail-closed scorer gate (spawned)', () => {
  const BUNDLE_HASH = `0x${'44'.repeat(32)}`;
  const syncArgs = (bundlePath, extra = []) => [
    '--epoch', '1',
    '--rpc-url', 'http://127.0.0.1:9',
    '--registry', `0x${'11'.repeat(20)}`,
    '--mining-contract', `0x${'22'.repeat(20)}`,
    '--bundle-manifest', bundlePath,
    '--rotation-manifest', 'file:///nonexistent/rotation.json',
    '--corpus-delta', 'file:///nonexistent/delta.json',
    ...extra,
  ];

  test('sync hard-fails on CORETEX_RERANKER=deterministic BEFORE any chain/artifact work', () => withTmpDir((dir) => {
    const proc = runCli(syncArgs(writeBundle(dir, BUNDLE_HASH)), { CORETEX_RERANKER: 'deterministic' }, dir);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /fail-closed/);
    assert.match(proc.stderr, /CORETEX_RERANKER=qwen3/);
  }));

  test('--skip-score-replay bypasses the env gate (and the run proceeds to the next mandatory check)', () => withTmpDir((dir) => {
    const proc = runCli(syncArgs(writeBundle(dir, BUNDLE_HASH), ['--skip-score-replay']), { CORETEX_RERANKER: 'deterministic' }, dir);
    assert.notEqual(proc.status, 0);
    // The gate did NOT fire; the run reached the mandatory signing-key check.
    assert.doesNotMatch(proc.stderr, /fail-closed/);
    assert.match(proc.stderr, /epoch signing public key is required/);
  }));

  test('verify-patch hard-fails on a stub env with an error naming the required vars', () => withTmpDir((dir) => {
    const bundlePath = writeBundle(dir, BUNDLE_HASH);
    const artifact = buildPostRevealEvalReportArtifact({
      version: 'coretex-post-reveal-eval-report-v1',
      epochId: 1,
      minerAddress: `0x${'33'.repeat(20)}`,
      outcome: 'STATE_ADVANCE',
      compactPatchBytesHex: '0x',
      thresholdPpm: 100,
      seedDerivation: { mode: 'future_blockhash_dual_pack' },
      receipt: {},
      context: { coreVersionHash: BUNDLE_HASH },
    });
    const artifactPath = join(dir, 'artifact.json');
    writeFileSync(artifactPath, JSON.stringify(artifact));
    const proc = runCli(
      ['verify-patch', '--hash', artifact.artifactHash, '--artifact-url', `file://${artifactPath}`, '--bundle-manifest', bundlePath],
      { CORETEX_RERANKER: 'deterministic' },
      dir,
    );
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /fail-closed/);
    assert.match(proc.stderr, /CORETEX_RERANKER=qwen3/);
  }));

  test(`verify-patch --skip-score-replay is loud and exits ${SKIP_SCORE_REPLAY_EXIT_CODE} (distinct from success)`, () => withTmpDir((dir) => {
    const bundlePath = writeBundle(dir, BUNDLE_HASH);
    const artifact = buildPostRevealEvalReportArtifact({
      version: 'coretex-post-reveal-eval-report-v1',
      epochId: 1,
      minerAddress: `0x${'33'.repeat(20)}`,
      outcome: 'STATE_ADVANCE',
      compactPatchBytesHex: '0x',
      thresholdPpm: 100,
      seedDerivation: { mode: 'future_blockhash_dual_pack' },
      receipt: {},
      context: { coreVersionHash: BUNDLE_HASH },
    });
    const artifactPath = join(dir, 'artifact.json');
    writeFileSync(artifactPath, JSON.stringify(artifact));
    const proc = runCli(
      ['verify-patch', '--hash', artifact.artifactHash, '--artifact-url', `file://${artifactPath}`, '--bundle-manifest', bundlePath, '--skip-score-replay'],
      { CORETEX_RERANKER: 'deterministic' },
      dir,
    );
    assert.equal(proc.status, SKIP_SCORE_REPLAY_EXIT_CODE, `stderr: ${proc.stderr}`);
    assert.match(proc.stderr, /does NOT attest score honesty/);
    const out = JSON.parse(proc.stdout);
    assert.match(out.scoreReplay, /SKIPPED/);
  }));
});
