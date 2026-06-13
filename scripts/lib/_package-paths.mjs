/**
 * Path resolution for the runtime scripts SHIPPED INSIDE the
 * @botcoin/coretex-client package. It must work in BOTH layouts:
 *
 *   1. repo checkout:        <repo>/scripts/lib/_package-paths.mjs
 *   2. node_modules install: <proj>/node_modules/@botcoin/coretex-client/scripts/lib/_package-paths.mjs
 *
 * `packageRoot` / `distIndex` / `distValidator` always resolve relative to the
 * package itself. `baseDir` is the base for resolving RELATIVE artifact paths
 * passed on the command line:
 *   1. `CORETEX_REPO_ROOT` env var, when set.
 *   2. The canonical repo root, when this package sits inside the repo checkout
 *      (detected via the package root package.json name `@botcoin/coretex-client`).
 *   3. process.cwd() (installed-package standalone use; callers such as
 *      coretex-validator-setup pass absolute paths anyway).
 */
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url)); // scripts/lib
export const packageRoot = resolve(here, '../..');
export const distRoot = resolve(packageRoot, 'dist');
export const distIndex = resolve(distRoot, 'index.js');
export const distValidator = resolve(distRoot, 'validator.js');
export const packageScriptsRoot = resolve(packageRoot, 'scripts');

function detectRepoRoot() {
  if (process.env.CORETEX_REPO_ROOT) return resolve(process.env.CORETEX_REPO_ROOT);
  const candidate = packageRoot;
  try {
    const pkgPath = resolve(candidate, 'package.json');
    if (existsSync(pkgPath)) {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      if (pkg.name === '@botcoin/coretex-client') return candidate;
    }
  } catch {
    /* unreadable candidate package.json — fall through to cwd */
  }
  return process.cwd();
}

/** Base directory for resolving relative artifact paths (see module doc). */
export const baseDir = detectRepoRoot();
