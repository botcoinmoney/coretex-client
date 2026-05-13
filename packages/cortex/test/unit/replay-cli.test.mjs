import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  bgeM3DenseManifest,
  buildBundleManifest,
  memRerankerManifest,
  qwen3Reranker06BManifest,
  withRecomputedBundleHash,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));
const cliPath = join(repoRoot, 'packages/cortex/dist/replay-cli.js');

function withPackedState(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-replay-cli-'));
  try {
    const statePath = join(dir, 'state.bin');
    writeFileSync(statePath, Buffer.alloc(32768));
    return fn(statePath);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runWatch(args) {
  return spawnSync(process.execPath, [cliPath, 'watch', '--rpc', 'http://127.0.0.1:9', '--once', ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
  });
}

describe('coretex-replay canonical watch gates', () => {
  test('watch requires a bundle manifest by default', () => withPackedState((statePath) => {
    const proc = runWatch(['--parent-state', statePath]);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /requires --bundle-manifest/);
  }));

  test('watch requires expected bundle hash or core version hash', () => withPackedState((statePath) => {
    const manifestPath = join(repoRoot, 'packages/cortex/test/fixtures/nonexistent-manifest.json');
    const proc = runWatch(['--parent-state', statePath, '--bundle-manifest', manifestPath]);
    assert.notEqual(proc.status, 0);
    assert.match(proc.stderr, /requires --expected-bundle-hash or --core-version-hash/);
  }));

  test('watch refuses outdated client when bundle policy is hard-fail', () => withPackedState((statePath) => {
    const dir = mkdtempSync(join(tmpdir(), 'coretex-replay-manifest-'));
    try {
      const manifestPath = join(dir, 'manifest.json');
      const manifest = buildBundleManifest({
        repoRoot,
        corpusRoot: '0x' + '22'.repeat(32),
        corpusFiles: [],
        biEncoder: bgeM3DenseManifest({
          revision: '0123456789abcdef0123456789abcdef01234567',
          files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
        }),
        reranker: qwen3Reranker06BManifest({
          revision: '89abcdef0123456789abcdef0123456789abcdef',
          files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
        }),
        labelingReranker: memRerankerManifest({
          modelId: 'memreranker/4B',
          revision: 'cafebabedeadbeefcafebabedeadbeefcafebabe',
          files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
        }),
      });
      const pinned = withRecomputedBundleHash({
        ...manifest,
        evaluator: {
          ...manifest.evaluator,
          profile: {
            ...manifest.evaluator.profile,
            clientVersionPolicy: {
              minimumVersion: '9.0.0',
              hardFailOutdated: true,
            },
          },
        },
      });
      writeFileSync(manifestPath, JSON.stringify(pinned, null, 2), 'utf8');
      const proc = runWatch([
        '--parent-state',
        statePath,
        '--bundle-manifest',
        manifestPath,
        '--core-version-hash',
        pinned.bundleHash,
      ]);
      assert.notEqual(proc.status, 0);
      assert.match(proc.stderr, /OUTDATED_CLIENT/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }));

  test('outdated client soft-warns when hardFailOutdated=false', () => withPackedState((statePath) => {
    const dir = mkdtempSync(join(tmpdir(), 'coretex-replay-manifest-softwarn-'));
    try {
      const manifestPath = join(dir, 'manifest.json');
      const manifest = buildBundleManifest({
        repoRoot,
        corpusRoot: '0x' + '33'.repeat(32),
        corpusFiles: [],
        biEncoder: bgeM3DenseManifest({
          revision: '0123456789abcdef0123456789abcdef01234567',
          files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
        }),
        reranker: qwen3Reranker06BManifest({
          revision: '89abcdef0123456789abcdef0123456789abcdef',
          files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
        }),
        labelingReranker: memRerankerManifest({
          modelId: 'memreranker/4B',
          revision: 'cafebabedeadbeefcafebabedeadbeefcafebabe',
          files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
        }),
      });
      const pinned = withRecomputedBundleHash({
        ...manifest,
        evaluator: {
          ...manifest.evaluator,
          profile: {
            ...manifest.evaluator.profile,
            clientVersionPolicy: {
              minimumVersion: '9.0.0',
              hardFailOutdated: false,
            },
          },
        },
      });
      writeFileSync(manifestPath, JSON.stringify(pinned, null, 2), 'utf8');
      const proc = runWatch([
        '--parent-state',
        statePath,
        '--bundle-manifest',
        manifestPath,
        '--core-version-hash',
        pinned.bundleHash,
      ]);
      assert.match(proc.stderr, /warning: OUTDATED_CLIENT/);
      assert.doesNotMatch(proc.stderr, /bundle manifest verification failed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }));

  test('recommended-version warning does not fire for newer client versions', () => withPackedState((statePath) => {
    const dir = mkdtempSync(join(tmpdir(), 'coretex-replay-manifest-recommended-'));
    try {
      const manifestPath = join(dir, 'manifest.json');
      const manifest = buildBundleManifest({
        repoRoot,
        corpusRoot: '0x' + '44'.repeat(32),
        corpusFiles: [],
        biEncoder: bgeM3DenseManifest({
          revision: '0123456789abcdef0123456789abcdef01234567',
          files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
        }),
        reranker: qwen3Reranker06BManifest({
          revision: '89abcdef0123456789abcdef0123456789abcdef',
          files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
        }),
        labelingReranker: memRerankerManifest({
          modelId: 'memreranker/4B',
          revision: 'cafebabedeadbeefcafebabedeadbeefcafebabe',
          files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
        }),
      });
      const pinned = withRecomputedBundleHash({
        ...manifest,
        evaluator: {
          ...manifest.evaluator,
          profile: {
            ...manifest.evaluator.profile,
            clientVersionPolicy: {
              minimumVersion: '0.7.0',
              recommendedVersion: '0.7.2',
              hardFailOutdated: true,
            },
          },
        },
      });
      writeFileSync(manifestPath, JSON.stringify(pinned, null, 2), 'utf8');
      const proc = runWatch([
        '--parent-state',
        statePath,
        '--bundle-manifest',
        manifestPath,
        '--core-version-hash',
        pinned.bundleHash,
        '--client-version',
        '0.7.5',
      ]);
      assert.doesNotMatch(proc.stderr, /bundle recommends client/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }));
});
