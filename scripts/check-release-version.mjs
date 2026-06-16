#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const pkgRoot = resolve(new URL('..', import.meta.url).pathname);
const pkg = JSON.parse(readFileSync(resolve(pkgRoot, 'package.json'), 'utf8'));
const src = readFileSync(resolve(pkgRoot, 'src/version.ts'), 'utf8');
const match = src.match(/CORTEX_CLIENT_VERSION\s*=\s*'([^']+)'/);

if (!match) {
  console.error('version:check: could not find CORTEX_CLIENT_VERSION in src/version.ts');
  process.exit(1);
}

if (pkg.version !== match[1]) {
  console.error(`version:check: package.json version ${pkg.version} != src/version.ts ${match[1]}`);
  process.exit(1);
}

console.log(`version:check ok: ${pkg.version}`);
