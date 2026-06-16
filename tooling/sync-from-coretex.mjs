#!/usr/bin/env node
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';
import { argv } from 'node:process';
import { execFileSync } from 'node:child_process';

function flag(name, fallback = undefined) {
  const idx = argv.indexOf(`--${name}`);
  return idx >= 0 && idx + 1 < argv.length ? argv[idx + 1] : fallback;
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = resolve(flag('source', '../coretex'));
const sourcePkgRoot = resolve(sourceRoot, 'packages/coretex');
const sourcePkgJson = JSON.parse(readFileSync(join(sourcePkgRoot, 'package.json'), 'utf8'));

if (!existsSync(join(sourcePkgRoot, 'src'))) {
  console.error(`sync-from-coretex: no packages/coretex/src under ${sourceRoot}`);
  process.exit(1);
}

const directCopies = [
  ['.npmignore', '.npmignore'],
];

const repoLevelCopies = [
  ['specs', 'specs'],
  ['LICENSE', 'LICENSE'],
  ['release/calibration/fixtures/state-root-vectors.json', 'release/calibration/fixtures/state-root-vectors.json'],
];

const renameCopies = [
  ['src/validator.ts', 'src/client.ts'],
  ['src/validator-runtime.ts', 'src/client-runtime.ts'],
  ['src/validator-setup-cli.ts', 'src/client-setup-cli.ts'],
  ['src/validator-sync-cli.ts', 'src/client-sync-cli.ts'],
  ['test/unit/validator-package-fresh-install.test.mjs', 'test/unit/client-package-fresh-install.test.mjs'],
  ['test/unit/validator-reranker-fail-closed.test.mjs', 'test/unit/client-reranker-fail-closed.test.mjs'],
  ['test/unit/validator-runtime.test.mjs', 'test/unit/client-runtime.test.mjs'],
  ['test/unit/validator-setup-cli.test.mjs', 'test/unit/client-setup-cli.test.mjs'],
  ['test/unit/validator-sync-atomicity.test.mjs', 'test/unit/client-sync-atomicity.test.mjs'],
  ['test/unit/validator-sync-backlog-drain.test.mjs', 'test/unit/client-sync-backlog-drain.test.mjs'],
  ['test/unit/validator-sync-corpus-autoresolve.test.mjs', 'test/unit/client-sync-corpus-autoresolve.test.mjs'],
  ['test/unit/validator-sync-defaults.test.mjs', 'test/unit/client-sync-defaults.test.mjs'],
  ['test/unit/validator-sync-hardening.test.mjs', 'test/unit/client-sync-hardening.test.mjs'],
  ['test/unit/validator-sync.test.mjs', 'test/unit/client-sync.test.mjs'],
];

const textReplacements = [
  [/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\//g, '../../../'],
  [/\.\.\/\.\.\/\.\.\/\.\.\//g, '../../'],
  [/\.\.\/\.\.\/\.\.\/\.\./g, '../..'],
  [/packages\/coretex\/dist\//g, 'dist/'],
  [/packages\/coretex\/src\//g, 'src/'],
  [/packages\/coretex\/test\//g, 'test/'],
  [/packages\/coretex\/scripts\//g, 'scripts/'],
  [/'@botcoin', 'coretex'/g, "'@botcoinmoney', 'coretex-client'"],
  [/"@botcoin", "coretex"/g, '"@botcoinmoney", "coretex-client"'],
  [/@botcoin\/coretex/g, '@botcoinmoney/coretex-client'],
  [/@botcoin\/coretex\/validator/g, '@botcoinmoney/coretex-client/client'],
  [/\.\/validator\.js/g, './client.js'],
  [/coretex-validator-sync/g, 'coretex-client-sync'],
  [/coretex-validator-setup/g, 'coretex-client-setup'],
  [/coretex-validator-replay/g, 'coretex-client-replay'],
  [/coretex-validator/g, 'coretex-client'],
  [/validator-sync/g, 'client-sync'],
  [/validator-setup/g, 'client-setup'],
  [/validator-runtime/g, 'client-runtime'],
  [/validator package/g, 'client package'],
  [/validator surface/g, 'client surface'],
  [/CoreTex validator/g, 'CoreTex client'],
  [/coretex validator/g, 'coretex client'],
];
const readmeAppendixPath = join(repoRoot, 'README.sync-appendix.md');
const rewriteExtensions = new Set(['.ts', '.js', '.mjs', '.cjs', '.md']);
const clientSyncWrapper = `#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { bytesToHex, keccak256 } from '../dist/index.js';
export * from '../dist/client-sync-cli.js';

export const ZERO_BYTES32 = '0x' + '00'.repeat(32);

function isBytes32Hex(value) {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isAddressHex(value) {
  return typeof value === 'string' && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function normalizeBytes32(value, label) {
  if (!isBytes32Hex(value)) throw new Error(\`\${label} must be bytes32 hex\`);
  return value.toLowerCase();
}

function normalizeAddress(value, label) {
  if (!isAddressHex(value)) throw new Error(\`\${label} must be address hex\`);
  return value.toLowerCase();
}

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function epochSecretCommit(epochSecret) {
  return bytesToHex(keccak256(hexToBytes(normalizeBytes32(epochSecret, 'epochSecret')))).toLowerCase();
}

function selector(signature) {
  return bytesToHex(keccak256(new TextEncoder().encode(signature))).slice(0, 10).toLowerCase();
}

function encodeUint64Arg(value) {
  const n = BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error(\`uint64 argument out of range: \${value}\`);
  return n.toString(16).padStart(64, '0');
}

function callData(signature, args = []) {
  return \`\${selector(signature)}\${args.map(encodeUint64Arg).join('')}\`;
}

function decodeBytes32(result, label) {
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]{64,}$/.test(result)) {
    throw new Error(\`\${label} eth_call returned malformed bytes32\`);
  }
  return \`0x\${result.slice(2, 66).toLowerCase()}\`;
}

function decodeAddress(result, label) {
  const word = decodeBytes32(result, label);
  return \`0x\${word.slice(-40)}\`;
}

export async function rpcEthCall({ rpcUrl, to, data }) {
  const payload = { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] };
  const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  if (!res.ok) throw new Error(\`RPC eth_call HTTP \${res.status}\`);
  const j = await res.json();
  if (j.error) throw new Error(\`RPC error: \${j.error.message ?? JSON.stringify(j.error)}\`);
  if (typeof j.result !== 'string') throw new Error('RPC eth_call missing result');
  return j.result;
}

async function callView({ rpcUrl, to, signature, args: callArgs = [], ethCall }) {
  return ethCall({ rpcUrl, to, signature, args: callArgs, data: callData(signature, callArgs) });
}

export function verifyEpochSecretRevealBinding({
  hiddenSeedCommit,
  miningEpochCommit,
  epochSecret,
  requireReveal = false,
}) {
  const hidden = normalizeBytes32(hiddenSeedCommit, 'registry hiddenSeedCommit');
  const commit = normalizeBytes32(miningEpochCommit, 'mining epochCommit');
  const secret = normalizeBytes32(epochSecret, 'mining epochSecret');
  if (commit !== hidden) {
    throw new Error(\`mining epochCommit \${commit} != registry hiddenSeedCommit \${hidden}\`);
  }
  if (secret === ZERO_BYTES32) {
    if (requireReveal) throw new Error('awaiting_epoch_secret_reveal: mining epochSecret is zero/unrevealed');
    return { evalReplayStatus: 'awaiting_epoch_secret_reveal', epochSecretRevealed: false };
  }
  const recomputed = epochSecretCommit(secret);
  if (recomputed !== hidden) {
    throw new Error(\`mining epochSecret commit \${recomputed} != registry hiddenSeedCommit \${hidden}\`);
  }
  return { evalReplayStatus: 'epoch_secret_revealed', epochSecretRevealed: true };
}

export async function readOnChainEpochPins({
  rpcUrl,
  registry,
  miningContract,
  epoch,
  requireReveal = false,
  ethCall = rpcEthCall,
}) {
  const registryAddress = normalizeAddress(registry, 'registry');
  const miningAddress = normalizeAddress(miningContract, 'miningContract');
  const epochNumber = Number(epoch);
  if (!Number.isSafeInteger(epochNumber) || epochNumber < 0) throw new Error('epoch must be a non-negative safe integer');
  const call = (to, signature, callArgs = []) => callView({ rpcUrl, to, signature, args: callArgs, ethCall });
  const chainRegistry = decodeAddress(await call(miningAddress, 'coreTexRegistry()'), 'mining.coreTexRegistry');
  if (chainRegistry !== registryAddress) {
    throw new Error(\`mining coreTexRegistry \${chainRegistry} != configured registry \${registryAddress}\`);
  }
  const pins = {
    parentStateRoot: decodeBytes32(await call(registryAddress, 'epochParentStateRoot(uint64)', [epochNumber]), 'registry.epochParentStateRoot'),
    liveStateRoot: decodeBytes32(await call(registryAddress, 'liveStateRoot(uint64)', [epochNumber]), 'registry.liveStateRoot'),
    coreVersionHash: decodeBytes32(await call(registryAddress, 'epochCoreVersionHash(uint64)', [epochNumber]), 'registry.epochCoreVersionHash'),
    corpusRoot: decodeBytes32(await call(registryAddress, 'epochCorpusRoot(uint64)', [epochNumber]), 'registry.epochCorpusRoot'),
    activeFrontierRoot: decodeBytes32(await call(registryAddress, 'epochActiveFrontierRoot(uint64)', [epochNumber]), 'registry.epochActiveFrontierRoot'),
    baselineManifestHash: decodeBytes32(await call(registryAddress, 'epochBaselineManifestHash(uint64)', [epochNumber]), 'registry.epochBaselineManifestHash'),
    hiddenSeedCommit: decodeBytes32(await call(registryAddress, 'epochHiddenSeedCommit(uint64)', [epochNumber]), 'registry.epochHiddenSeedCommit'),
  };
  const transitionCount = Number(BigInt(await call(registryAddress, 'transitionCount(uint64)', [epochNumber])));
  const miningEpochCommit = decodeBytes32(await call(miningAddress, 'epochCommit(uint64)', [epochNumber]), 'mining.epochCommit');
  const epochSecret = decodeBytes32(await call(miningAddress, 'epochSecret(uint64)', [epochNumber]), 'mining.epochSecret');
  const reveal = verifyEpochSecretRevealBinding({
    hiddenSeedCommit: pins.hiddenSeedCommit,
    miningEpochCommit,
    epochSecret,
    requireReveal,
  });
  return {
    ...pins,
    miningEpochCommit,
    transitionCount,
    registryAddress,
    miningContractAddress: miningAddress,
    evalReplayStatus: reveal.evalReplayStatus,
    epochSecretRevealed: reveal.epochSecretRevealed,
  };
}

export function mergeChainPins(offlinePins = {}, chainPins = {}) {
  const out = { ...offlinePins };
  for (const key of ['parentStateRoot', 'liveStateRoot', 'coreVersionHash', 'corpusRoot', 'activeFrontierRoot', 'baselineManifestHash', 'hiddenSeedCommit']) {
    if (!chainPins[key]) continue;
    if (out[key] && String(out[key]).toLowerCase() !== String(chainPins[key]).toLowerCase()) {
      throw new Error(\`registry pin mismatch \${key}: offline=\${out[key]} chain=\${chainPins[key]}\`);
    }
    out[key] = chainPins[key];
  }
  return out;
}

const invokedAsScript = (() => {
  if (!process.argv[1]) return false;
  try {
    return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
  } catch {
    return false;
  }
})();

if (invokedAsScript) {
  const proc = spawnSync(process.execPath, [new URL('../dist/client-sync-cli.js', import.meta.url), ...process.argv.slice(2)], {
    stdio: 'inherit',
  });
  process.exit(proc.status ?? 1);
}
`;

function copyTree(srcRel, destRel) {
  const srcAbs = join(sourcePkgRoot, srcRel);
  const destAbs = join(repoRoot, destRel);
  if (!existsSync(srcAbs)) return;
  rmSync(destAbs, { recursive: true, force: true });
  mkdirSync(dirname(destAbs), { recursive: true });
  cpSync(srcAbs, destAbs, {
    recursive: true,
    filter: (from) => {
      const rel = relative(sourcePkgRoot, from).replaceAll('\\', '/');
      if (rel === '') return true;
      if (rel.startsWith('src/validator')) return false;
      if (rel.startsWith('test/unit/validator')) return false;
      return true;
    },
  });
}

function copyFile(srcBase, srcRel, destBase, destRel) {
  const srcAbs = join(srcBase, srcRel);
  const destAbs = join(destBase, destRel);
  if (!existsSync(srcAbs)) {
    throw new Error(`sync-from-coretex: missing source file ${srcAbs}`);
  }
  mkdirSync(dirname(destAbs), { recursive: true });
  cpSync(srcAbs, destAbs);
}

function rewriteText(text) {
  let out = text;
  for (const [pattern, replacement] of textReplacements) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

function rewriteTreeText(rootAbs) {
  if (!existsSync(rootAbs)) return;
  for (const entry of readdirSync(rootAbs, { withFileTypes: true })) {
    const abs = join(rootAbs, entry.name);
    if (entry.isDirectory()) {
      rewriteTreeText(abs);
      continue;
    }
    const ext = entry.name.includes('.') ? `.${entry.name.split('.').pop()}` : '';
    if (!rewriteExtensions.has(ext)) continue;
    const raw = readFileSync(abs, 'utf8');
    const rewritten = rewriteText(raw);
    if (rewritten !== raw) writeFileSync(abs, rewritten);
  }
}

for (const [srcRel, destRel] of directCopies) {
  copyFile(sourcePkgRoot, srcRel, repoRoot, destRel);
}

for (const dir of ['src', 'test', 'scripts']) {
  copyTree(dir, dir);
}

for (const [srcRel, destRel] of repoLevelCopies) {
  const srcAbs = join(sourceRoot, srcRel);
  const destAbs = join(repoRoot, destRel);
  rmSync(destAbs, { recursive: true, force: true });
  mkdirSync(dirname(destAbs), { recursive: true });
  if (statSync(srcAbs).isDirectory()) {
    cpSync(srcAbs, destAbs, { recursive: true });
  } else {
    cpSync(srcAbs, destAbs);
  }
}

for (const dir of ['src', 'test', 'scripts', 'specs']) {
  rewriteTreeText(join(repoRoot, dir));
}

for (const [srcRel, destRel] of renameCopies) {
  const raw = readFileSync(join(sourcePkgRoot, srcRel), 'utf8');
  const text = rewriteText(raw);
  const destAbs = join(repoRoot, destRel);
  mkdirSync(dirname(destAbs), { recursive: true });
  writeFileSync(destAbs, text);
}

{
  const raw = readFileSync(join(sourcePkgRoot, 'README.md'), 'utf8');
  const text = rewriteText(raw);
  const appendix = existsSync(readmeAppendixPath)
    ? readFileSync(readmeAppendixPath, 'utf8').trim()
    : '';
  const merged = appendix ? `${text.trimEnd()}\n\n${appendix}\n` : `${text.trimEnd()}\n`;
  writeFileSync(join(repoRoot, 'README.md'), merged);
}

const sourceCommit = execFileSync('git', ['-C', sourceRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const sourceRepoUrl = execFileSync('git', ['-C', sourceRoot, 'remote', 'get-url', 'origin'], { encoding: 'utf8' }).trim();
writeFileSync(
  join(repoRoot, 'SYNC_PROVENANCE.json'),
  JSON.stringify({
    schema: 'coretex-client.sync-provenance.v1',
    sourceRepo: sourceRepoUrl,
    sourceCommit,
    sourcePackagePath: relative(sourceRoot, sourcePkgRoot).replaceAll('\\', '/'),
    syncedAt: new Date().toISOString(),
    notes: 'Updated by tooling/sync-from-coretex.mjs when shared client logic is refreshed from the canonical CoreTex repo.',
  }, null, 2) + '\n',
);

{
  const clientPkgPath = join(repoRoot, 'package.json');
  const clientPkg = JSON.parse(readFileSync(clientPkgPath, 'utf8'));
  clientPkg.version = sourcePkgJson.version;
  writeFileSync(clientPkgPath, JSON.stringify(clientPkg, null, 2) + '\n');
}

execFileSync('npm', ['install', '--package-lock-only'], {
  cwd: repoRoot,
  stdio: 'inherit',
});

writeFileSync(join(repoRoot, 'scripts', 'coretex-client-sync.mjs'), clientSyncWrapper);

console.log(`sync-from-coretex: synced from ${sourceRoot} @ ${sourceCommit}`);
