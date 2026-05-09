import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

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
});
