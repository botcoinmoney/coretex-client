/**
 * Package-root script resolution for the canonical Python reranker runner
 * (standalone-package fix: the old `new URL('../../../../scripts/…')` default
 * escaped an installed node_modules package).
 *
 * Asserts `resolveCortexPackageRoot` / `resolveRerankerScriptPath` against BOTH
 * simulated layouts: a repo-checkout-style tree and a node_modules install.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';

import {
  CORETEX_PACKAGE_NAME,
  resolveCortexPackageRoot,
  resolveRerankerScriptPath,
} from '../../dist/index.js';

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-pkg-resolve-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Build a simulated @botcoin/coretex package at `pkgRoot` and return the URL
 *  of a fake compiled module at dist/eval/reranker.js inside it. */
function buildSimulatedPackage(pkgRoot) {
  mkdirSync(join(pkgRoot, 'dist', 'eval'), { recursive: true });
  mkdirSync(join(pkgRoot, 'scripts'), { recursive: true });
  writeFileSync(join(pkgRoot, 'package.json'), JSON.stringify({ name: CORETEX_PACKAGE_NAME, version: '0.0.0' }));
  writeFileSync(join(pkgRoot, 'dist', 'eval', 'reranker.js'), '// simulated compiled module\n');
  writeFileSync(join(pkgRoot, 'scripts', 'reranker_runner.py'), '# simulated canonical runner\n');
  return pathToFileURL(join(pkgRoot, 'dist', 'eval', 'reranker.js')).href;
}

describe('reranker script path resolution (package-root walk-up)', () => {
  test('repo-checkout layout: <repo>/packages/coretex/dist/eval → <repo>/packages/coretex', () => withTmpDir((dir) => {
    const pkgRoot = join(dir, 'repo', 'packages', 'cortex');
    // The workspace root has its OWN package.json with a different name — the
    // walk must stop at the @botcoin/coretex package, not the workspace root.
    mkdirSync(join(dir, 'repo'), { recursive: true });
    writeFileSync(join(dir, 'repo', 'package.json'), JSON.stringify({ name: 'botcoin-coretex' }));
    const fromUrl = buildSimulatedPackage(pkgRoot);
    assert.equal(resolveCortexPackageRoot(fromUrl), pkgRoot);
    assert.equal(resolveRerankerScriptPath({}, fromUrl), join(pkgRoot, 'scripts', 'reranker_runner.py'));
  }));

  test('node_modules install layout: <proj>/node_modules/@botcoin/coretex/dist/eval → the installed package', () => withTmpDir((dir) => {
    const proj = join(dir, 'proj');
    mkdirSync(proj, { recursive: true });
    writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'some-consumer-project' }));
    const pkgRoot = join(proj, 'node_modules', '@botcoin', 'coretex');
    const fromUrl = buildSimulatedPackage(pkgRoot);
    assert.equal(resolveCortexPackageRoot(fromUrl), pkgRoot);
    const resolved = resolveRerankerScriptPath({}, fromUrl);
    assert.equal(resolved, join(pkgRoot, 'scripts', 'reranker_runner.py'));
    assert.ok(existsSync(resolved), 'resolved runner must exist inside the simulated install');
  }));

  test('CORETEX_RERANKER_SCRIPT stays the explicit override', () => withTmpDir((dir) => {
    const fromUrl = buildSimulatedPackage(join(dir, 'pkg'));
    assert.equal(
      resolveRerankerScriptPath({ CORETEX_RERANKER_SCRIPT: '/custom/runner.py' }, fromUrl),
      '/custom/runner.py',
    );
  }));

  test('no @botcoin/coretex ancestor is a hard error (never silently spawn a wrong runner)', () => withTmpDir((dir) => {
    const stray = join(dir, 'stray', 'dist', 'eval');
    mkdirSync(stray, { recursive: true });
    writeFileSync(join(stray, 'reranker.js'), '// stray module\n');
    assert.throws(
      () => resolveCortexPackageRoot(pathToFileURL(join(stray, 'reranker.js')).href),
      new RegExp(`no package.json named ${CORETEX_PACKAGE_NAME}`),
    );
  }));

  test('the REAL package resolves to the in-package canonical runner', () => {
    const root = resolveCortexPackageRoot();
    const runner = resolveRerankerScriptPath({});
    assert.equal(runner, join(root, 'scripts', 'reranker_runner.py'));
    assert.ok(existsSync(runner), `canonical runner missing at ${runner}`);
  });
});
