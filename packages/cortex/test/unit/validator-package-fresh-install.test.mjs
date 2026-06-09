/**
 * Fresh-install hermetic test: `npm pack` the @botcoin/cortex package into a
 * temp dir, install the tarball into a scratch project (no network — the
 * package has zero runtime dependencies), and assert the standalone validator
 * surface survives installation:
 *   - both validator bins exist and run --help,
 *   - the reranker script-path resolver finds scripts/reranker_runner.py
 *     INSIDE the installed package,
 *   - the package.json `files` list ships everything the resolver and the
 *     setup CLI need (dist + scripts, including the canonical Python runner
 *     and the in-package materializer).
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const pkgDir = fileURLToPath(new URL('../..', import.meta.url));

let root;        // tmp root
let proj;        // scratch consumer project
let installed;   // <proj>/node_modules/@botcoin/cortex

function run(cmd, cmdArgs, opts = {}) {
  return spawnSync(cmd, cmdArgs, { encoding: 'utf8', ...opts });
}

before(() => {
  root = mkdtempSync(join(tmpdir(), 'coretex-fresh-install-'));
  proj = join(root, 'scratch-project');
  mkdirSync(proj, { recursive: true });
  writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'scratch-validator-host', private: true, version: '0.0.0' }));

  const packed = run('npm', ['pack', '--pack-destination', root], { cwd: pkgDir });
  assert.equal(packed.status, 0, `npm pack failed: ${packed.stderr}`);
  const tarball = readdirSync(root).find((f) => f.endsWith('.tgz'));
  assert.ok(tarball, 'npm pack produced no tarball');

  const install = run('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', join(root, tarball)], { cwd: proj });
  assert.equal(install.status, 0, `npm install failed: ${install.stderr}`);
  installed = join(proj, 'node_modules', '@botcoin', 'cortex');
  assert.ok(existsSync(installed), 'installed package root missing');
}, { timeout: 180_000 });

after(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('fresh npm install of @botcoin/cortex', () => {
  test('both validator bins exist and run --help', { timeout: 60_000 }, () => {
    for (const bin of ['coretex-validator-setup', 'coretex-validator-sync']) {
      const binPath = join(proj, 'node_modules', '.bin', bin);
      assert.ok(existsSync(binPath), `${bin} missing from node_modules/.bin`);
      const proc = run(process.execPath, [binPath, '--help'], { cwd: proj });
      assert.equal(proc.status, 0, `${bin} --help exited ${proc.status}: ${proc.stderr}`);
      assert.match(proc.stdout, new RegExp(bin));
    }
  });

  test('reranker script-path resolver finds the canonical runner INSIDE the installed package', () => {
    const probe = run(process.execPath, ['--input-type=module', '-e', `
      import { existsSync } from 'node:fs';
      const { resolveRerankerScriptPath, resolveCortexPackageRoot } = await import(${JSON.stringify(pathToFileURL(join(installed, 'dist', 'eval', 'reranker.js')).href)});
      const root = resolveCortexPackageRoot();
      const runner = resolveRerankerScriptPath({});
      if (!runner.startsWith(root)) throw new Error('runner escaped the package: ' + runner);
      if (!existsSync(runner)) throw new Error('runner missing: ' + runner);
      process.stdout.write(JSON.stringify({ root, runner }));
    `], { cwd: proj });
    assert.equal(probe.status, 0, probe.stderr);
    const { root: resolvedRoot, runner } = JSON.parse(probe.stdout);
    assert.equal(resolvedRoot, installed);
    assert.equal(runner, join(installed, 'scripts', 'reranker_runner.py'));
  });

  test('the files list ships everything the resolver and setup CLI need', () => {
    for (const rel of [
      'dist/validator-sync-cli.js',
      'dist/validator-setup-cli.js',
      'dist/eval/reranker.js',
      'scripts/reranker_runner.py',
      'scripts/materialize-production-corpus.mjs',
      'scripts/lib/build-v2-production-corpus.mjs',
      'scripts/lib/_package-paths.mjs',
    ]) {
      assert.ok(existsSync(join(installed, rel)), `installed package missing ${rel}`);
    }
  });

  test('the canonical Python runner inside the install renders the golden prompt template', () => {
    const probe = run('python3', ['--version']);
    if (probe.error || probe.status !== 0) {
      // python3 genuinely unavailable — the golden parity test already screams about this.
      return;
    }
    const res = run('python3', [join(installed, 'scripts', 'reranker_runner.py'), '--print-prompt-template'], { cwd: proj });
    assert.equal(res.status, 0, res.stderr);
    const out = JSON.parse(res.stdout);
    assert.equal(out.probeQuery, 'coretex prompt-template probe query');
    assert.ok(out.prompt.includes('<Instruct>:'));
  });
});
