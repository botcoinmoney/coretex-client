/**
 * Finding 7 (integration): a sync that fails a MANDATORY check must leave the
 * prior trusted state — the TOFU key pin, the client state file, and the
 * substrate snapshot — BYTE-UNCHANGED. This spawns the compiled CLI against a
 * fake JSON-RPC endpoint that fails the bundle version self-check (a mandatory
 * gate), and asserts none of the three trusted files were mutated.
 *
 * The TrustedStateStaging mechanism itself (stage → dispose-without-commit
 * leaves prior files byte-identical; commit applies all together) is covered
 * directly in client-sync-hardening.test.mjs; this proves the CLI wires
 * EVERY trusted write through it and commits only after the gates pass.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { keccak256 } from '../../dist/state/keccak256.js';
import { bytesToHex } from '../../dist/state/merkle.js';

const cliPath = fileURLToPath(new URL('../../dist/client-sync-cli.js', import.meta.url));

const REGISTRY = `0x${'11'.repeat(20)}`;
const MINING = `0x${'22'.repeat(20)}`;
const LOCAL_BUNDLE = `0x${'44'.repeat(32)}`;
const CHAIN_BUNDLE = `0x${'45'.repeat(32)}`; // != local → mandatory version-check fail
const COMMIT = `0x${'33'.repeat(32)}`;

const sel = (s) => bytesToHex(keccak256(new TextEncoder().encode(s))).slice(0, 10);
const word32 = (hex) => hex.replace(/^0x/, '').padStart(64, '0');
const uintWord = (n) => BigInt(n).toString(16).padStart(64, '0');
const addressWord = (a) => `0x${'00'.repeat(12)}${a.slice(2).toLowerCase()}`;

/** Minimal fake Base RPC: enough chain context for the version self-check. */
function makeRpc() {
  const calls = [];
  const SELECTORS = {
    [sel('currentEpoch()')]: () => `0x${uintWord(7)}`,
    [sel('coreTexRegistry()')]: () => addressWord(REGISTRY),
    [sel('coreTexEpochContextSet(uint64)')]: () => `0x${uintWord(1)}`,
    [sel('epochParentStateRoot(uint64)')]: () => `0x${word32('0x' + '88'.repeat(32))}`,
    [sel('liveStateRoot(uint64)')]: () => `0x${word32('0x' + '99'.repeat(32))}`,
    [sel('transitionCount(uint64)')]: () => `0x${uintWord(0)}`,
    [sel('epochCoreVersionHash(uint64)')]: () => `0x${word32(CHAIN_BUNDLE)}`,
    [sel('epochCorpusRoot(uint64)')]: () => `0x${word32('0x' + '55'.repeat(32))}`,
    [sel('epochActiveFrontierRoot(uint64)')]: () => `0x${word32('0x' + '66'.repeat(32))}`,
    [sel('epochBaselineManifestHash(uint64)')]: () => `0x${word32('0x' + '77'.repeat(32))}`,
    [sel('epochHiddenSeedCommit(uint64)')]: () => `0x${word32(COMMIT)}`,
    [sel('epochCommit(uint64)')]: () => `0x${word32(COMMIT)}`,
    [sel('epochSecret(uint64)')]: () => `0x${word32('0x' + '00'.repeat(32))}`,
  };
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const { id, method, params } = JSON.parse(body);
      calls.push(method);
      let result;
      if (method === 'eth_blockNumber') {
        result = '0x3e8'; // 1000 — well above confirmation depth
      } else if (method === 'eth_call') {
        const data = params[0].data;
        const fn = SELECTORS[data.slice(0, 10)];
        result = fn ? fn() : `0x${'00'.repeat(32)}`;
      } else if (method === 'eth_getLogs') {
        result = [];
      } else {
        result = null;
      }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
    });
  });
  return { server, calls };
}

function withRpc(fn) {
  return new Promise((resolve, reject) => {
    const { server } = makeRpc();
    server.listen(0, '127.0.0.1', async () => {
      const { port } = server.address();
      try {
        await fn(`http://127.0.0.1:${port}`);
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        server.close();
      }
    });
  });
}

/** Run the CLI WITHOUT blocking the event loop — the fake RPC server lives in
 *  this same process and must be free to answer the child's fetches. */
function runCliAsync(cliArgs) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cliPath, ...cliArgs], {
      env: {
        ...Object.fromEntries(Object.entries(process.env).filter(([k]) =>
          !k.startsWith('CORETEX_') && !k.startsWith('BOTCOIN_') && k !== 'BASE_RPC_URL' && k !== 'EPOCH_ID')),
      },
    });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (c) => { stderr += c; });
    child.stdout.resume();
    child.on('close', (status) => resolve({ status, stderr }));
  });
}

describe('Finding 7 — a mandatory-check failure leaves trusted state byte-unchanged', () => {
  test('a failed bundle version self-check does not mutate the TOFU pin / state file / snapshot', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'coretex-sync-atomicity-'));
    try {
      const stateDir = join(dir, 'state');
      mkdirSync(stateDir, { recursive: true });

      // Prior trusted state on disk (a previously-verified sync).
      const pinPath = join(stateDir, 'epoch-signing-key.pin.json');
      const statePath = join(stateDir, 'client-sync-state.json');
      const snapPath = join(stateDir, 'substrate-state.bin');
      const priorPin = '{"schema":"coretex.epoch-signing-key-pin.v1","fingerprint":"0xprior"}\n';
      const priorState = '{"schema":"coretex.client-sync-state.v1","epoch":6,"prior":true}\n';
      const priorSnap = Buffer.from([1, 2, 3, 4]);
      writeFileSync(pinPath, priorPin);
      writeFileSync(statePath, priorState);
      writeFileSync(snapPath, priorSnap);

      // Local bundle manifest whose bundleHash != the chain coreVersionHash.
      const bundlePath = join(dir, 'bundle.json');
      writeFileSync(bundlePath, JSON.stringify({
        bundleHash: LOCAL_BUNDLE,
        corpus: { root: `0x${'55'.repeat(32)}` },
        model: { reranker: { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'rev' } },
      }));

      await withRpc(async (rpcUrl) => {
        const proc = await runCliAsync([
          '--epoch', '7',
          '--rpc-url', rpcUrl,
          '--registry', REGISTRY,
          '--mining-contract', MINING,
          '--bundle-manifest', bundlePath,
          '--state-dir', stateDir,
          '--rotation-manifest', 'file:///nonexistent/rotation.json',
          '--corpus-delta', 'file:///nonexistent/delta.json',
          '--public-key', 'file:///nonexistent/key.pem',
        ]);

        // The mandatory version self-check fails → non-zero exit, named error.
        assert.notEqual(proc.status, 0);
        assert.match(proc.stderr, /coretex client outdated/);

        // The three trusted-state files are BYTE-unchanged.
        assert.equal(readFileSync(pinPath, 'utf8'), priorPin);
        assert.equal(readFileSync(statePath, 'utf8'), priorState);
        assert.deepEqual(readFileSync(snapPath), priorSnap);
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
