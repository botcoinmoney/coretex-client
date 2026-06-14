import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// ── compiled client sync CLI (dist/client-sync-cli.js) ──

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  checkCorpusDeltaContinuity,
  checkTofuKeyPin,
  writeTofuKeyPin,
  checkClientBundleVersion,
  deriveEpochSecretRevealStatus,
  policyAtomsModeFromManifest,
  sha256Fingerprint,
} from '../../dist/client-sync-cli.js';
import { keccak256 } from '../../dist/state/keccak256.js';
import { bytesToHex } from '../../dist/state/merkle.js';

const cliPath = fileURLToPath(new URL('../../dist/client-sync-cli.js', import.meta.url));
const ZERO_BYTES32 = `0x${'00'.repeat(32)}`;
const SECRET = `0x${'33'.repeat(32)}`;
const COMMIT = bytesToHex(keccak256(Buffer.from(SECRET.slice(2), 'hex')));
const ROOT_A = `0x${'aa'.repeat(32)}`;
const ROOT_B = `0x${'bb'.repeat(32)}`;

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-client-sync-cli-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runCli(cliArgs, env = {}) {
  return spawnSync(process.execPath, [cliPath, ...cliArgs], {
    encoding: 'utf8',
    env: {
      ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('CORETEX_') && !k.startsWith('BOTCOIN_') && k !== 'BASE_RPC_URL' && k !== 'EPOCH_ID')),
      ...env,
    },
  });
}

describe('client sync CLI — corpus-delta continuity', () => {
  test('continuity holds when delta.previousRoot equals the local previous corpus root', () => {
    assert.doesNotThrow(() => checkCorpusDeltaContinuity(ROOT_A, ROOT_A.toUpperCase().replace('0X', '0x')));
  });

  test('continuity failure is a hard error', () => {
    assert.throws(
      () => checkCorpusDeltaContinuity(ROOT_A, ROOT_B),
      /corpus-delta continuity: delta\.previousRoot .* != local previous corpus root/,
    );
  });

  test('an unavailable local previous corpus root is a hard error (no silent skip)', () => {
    assert.throws(
      () => checkCorpusDeltaContinuity(ROOT_A, undefined),
      /local previous corpus root unavailable/,
    );
  });
});

describe('client sync CLI — TOFU epoch signing key pinning', () => {
  const KEY_A = '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n';
  const KEY_B = '-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----\n';

  test('first sync has no pin; writing then re-checking the SAME key passes', () => withTmpDir((dir) => {
    const pinPath = join(dir, 'epoch-signing-key.pin.json');
    const first = checkTofuKeyPin(pinPath, KEY_A);
    assert.equal(first.pinned, false);
    assert.equal(first.fingerprint, sha256Fingerprint(KEY_A));
    writeTofuKeyPin(pinPath, KEY_A);
    const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
    assert.equal(pin.schema, 'coretex.epoch-signing-key-pin.v1');
    assert.equal(pin.publicKeyPem, KEY_A);
    assert.equal(pin.fingerprint, sha256Fingerprint(KEY_A));
    const again = checkTofuKeyPin(pinPath, KEY_A);
    assert.equal(again.pinned, true);
  }));

  test('a served key differing from the pin is a hard error', () => withTmpDir((dir) => {
    const pinPath = join(dir, 'epoch-signing-key.pin.json');
    writeTofuKeyPin(pinPath, KEY_A);
    assert.throws(() => checkTofuKeyPin(pinPath, KEY_B), /TOFU key pin mismatch/);
  }));
});

describe('client sync CLI — bundle version self-check', () => {
  const LOCAL = `0x${'44'.repeat(32)}`;
  const CHAIN = `0x${'45'.repeat(32)}`;

  test('matching bundleHash passes', () => {
    assert.deepEqual(checkClientBundleVersion(LOCAL, LOCAL.toUpperCase().replace('0X', '0x'), false), { match: true });
  });

  test('mismatch is a hard "coretex client outdated" error naming the required hash', () => {
    assert.throws(
      () => checkClientBundleVersion(LOCAL, CHAIN, false),
      (err) => {
        assert.match(err.message, /coretex client outdated/);
        assert.match(err.message, new RegExp(`Required bundle hash: ${CHAIN}`));
        return true;
      },
    );
  });

  test('--allow-version-mismatch downgrades to a loud read-only warning', () => {
    const warnings = [];
    const result = checkClientBundleVersion(LOCAL, CHAIN, true, (m) => warnings.push(m));
    assert.deepEqual(result, { match: false });
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /coretex client outdated/);
    assert.match(warnings[0], /READ-ONLY/);
  });
});

describe('client sync CLI — epoch secret reveal status + mode flags', () => {
  test('zero mining secret reports awaiting_epoch_secret_reveal', () => {
    assert.deepEqual(
      deriveEpochSecretRevealStatus(COMMIT, ZERO_BYTES32),
      { evalReplayStatus: 'awaiting_epoch_secret_reveal', epochSecretRevealed: false },
    );
  });

  test('a matching revealed secret reports epoch_secret_revealed', () => {
    assert.deepEqual(
      deriveEpochSecretRevealStatus(COMMIT, SECRET),
      { evalReplayStatus: 'epoch_secret_revealed', epochSecretRevealed: true },
    );
  });

  test('a mismatched revealed secret is a hard error', () => {
    assert.throws(
      () => deriveEpochSecretRevealStatus(COMMIT, `0x${'99'.repeat(32)}`),
      /epochSecret commit/,
    );
  });

  test('policyAtomsMode derives HARD from the manifest pipelineVersion', () => {
    assert.equal(policyAtomsModeFromManifest({ evaluator: { profile: { pipelineVersion: 'coretex-retrieval-v2-policy-r5' } } }), true);
    assert.equal(policyAtomsModeFromManifest({ evaluator: { profile: { pipelineVersion: 'coretex-retrieval-v2-lens-r4' } } }), false);
    assert.equal(policyAtomsModeFromManifest({}), false);
  });
});

describe('client sync CLI — mandatory inputs (spawned)', () => {
  const baseArgs = (manifestPath) => [
    '--epoch', '1',
    '--rpc-url', 'http://127.0.0.1:9',
    '--registry', `0x${'11'.repeat(20)}`,
    '--mining-contract', `0x${'22'.repeat(20)}`,
    ...(manifestPath ? ['--bundle-manifest', manifestPath] : []),
    '--rotation-manifest', 'file:///nonexistent/rotation.json',
    '--corpus-delta', 'file:///nonexistent/delta.json',
  ];

  test('a missing local bundle manifest is a hard error (version check is not optional)', () => {
    const proc = runCli(baseArgs(null));
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /--bundle-manifest or CORETEX_BUNDLE_MANIFEST is required/);
  });

  test('a missing epoch signing public key is a hard error (signatures are mandatory)', () => withTmpDir((dir) => {
    const manifestPath = join(dir, 'bundle.json');
    writeFileSync(manifestPath, JSON.stringify({
      bundleHash: `0x${'44'.repeat(32)}`,
      corpus: { root: ROOT_A },
      model: { reranker: { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'test-revision' } },
    }));
    const proc = runCli(baseArgs(manifestPath));
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /epoch signing public key is required \(signature verification is mandatory\)/);
  }));

  test('a bundle manifest without model.reranker pins is a hard error (fail-closed scorer)', () => withTmpDir((dir) => {
    const manifestPath = join(dir, 'bundle.json');
    writeFileSync(manifestPath, JSON.stringify({ bundleHash: `0x${'44'.repeat(32)}`, corpus: { root: ROOT_A } }));
    const proc = runCli(baseArgs(manifestPath));
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /no model\.reranker\.modelId\/revision pins/);
  }));

  test('verify-patch requires --hash', () => {
    const proc = runCli(['verify-patch']);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /verify-patch requires --hash/);
  });

  test('verify-patch requires an artifact source', () => {
    const proc = runCli(['verify-patch', '--hash', `0x${'ab'.repeat(32)}`]);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /CORETEX_ARTIFACT_BASE_URL/);
  });

  test('verify-patch binds the fetched artifact to the requested hash', () => withTmpDir((dir) => {
    const artifactPath = join(dir, 'artifact.json');
    writeFileSync(artifactPath, JSON.stringify({ artifactHash: `0x${'cd'.repeat(32)}` }));
    const proc = runCli(['verify-patch', '--hash', `0x${'ab'.repeat(32)}`, '--artifact-url', `file://${artifactPath}`]);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /fetched artifact hash .* != requested/);
  }));
});
