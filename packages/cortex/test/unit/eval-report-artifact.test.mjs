import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildPostRevealEvalReportArtifact,
  runPerPatchEvaluation,
  verifyPostRevealEvalReportArtifact,
  bytesToHex,
  keccak256,
} from '../../dist/index.js';

const PARENT_ROOT = `0x${'aa'.repeat(32)}`;
const MINER = `0x${'10'.repeat(20)}`;
const EPOCH_SECRET = `0x${'01'.repeat(32)}`;
const CORPUS_ROOT = `0x${'cc'.repeat(32)}`;
const BUNDLE_HASH = `0x${'dd'.repeat(32)}`;
const BLOCKHASH = `0x${'02'.repeat(32)}`;
const PATCH_BYTES = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);

function hexToBytes(hex) {
  const s = hex.replace(/^0x/, '');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function epochSecretCommit(secret) {
  return bytesToHex(keccak256(hexToBytes(secret))).toLowerCase();
}

function makeRpcClient(blockhashByBlock = new Map(), head = 1000) {
  return {
    async getLatestBlockNumber() { return head; },
    async getBlockHash(n) {
      const h = blockhashByBlock.get(n);
      if (!h) throw new Error(`block ${n} not found`);
      return h;
    },
    async waitForBlock(n) {
      const h = blockhashByBlock.get(n);
      if (!h) throw new Error(`block ${n} not found`);
      return { number: n, blockhash: h, timestamp: 1700000000 };
    },
  };
}

async function buildArtifact() {
  const receipt = await runPerPatchEvaluation(
    {
      normalizedPatchBytes: PATCH_BYTES,
      parentRoot: PARENT_ROOT,
      minerAddress: MINER,
      epochId: 7,
      structurallyValid: true,
    },
    {
      rpcClient: makeRpcClient(new Map([[1030, BLOCKHASH]])),
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      targetBlockOffset: 30,
      thresholdPpm: 1_000,
      perMinerCap: 5,
      epochSecret: EPOCH_SECRET,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
      dedupCache: new Map(),
      minerAdmissions: new Map(),
    },
  );
  return buildPostRevealEvalReportArtifact({
    version: 'coretex-post-reveal-eval-report-v1',
    evalReportHash: `0x${'ef'.repeat(32)}`,
    epochId: 7,
    minerAddress: MINER,
    outcome: 'STATE_ADVANCE',
    compactPatchBytesHex: `0x${Buffer.from(PATCH_BYTES).toString('hex')}`,
    receipt,
    context: {
      parentStateRoot: PARENT_ROOT,
      corpusRoot: CORPUS_ROOT,
      coreVersionHash: BUNDLE_HASH,
      hiddenSeedCommit: epochSecretCommit(EPOCH_SECRET),
      replayTolerancePpm: 250,
    },
  });
}

describe('post-reveal eval report artifact', () => {
  test('verifies artifact hash, epoch secret binding, and dual-pack replay', async () => {
    const artifact = await buildArtifact();
    const result = await verifyPostRevealEvalReportArtifact(artifact, {
      rpcClient: makeRpcClient(new Map([[artifact.receipt.targetBlock, BLOCKHASH]])),
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: EPOCH_SECRET,
    });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.artifactHash, artifact.artifactHash);
      assert.equal(result.gateDeltaPpm, 0);
      assert.equal(result.confirmDeltaPpm, 0);
    }
  });

  test('mismatched epoch secret fails before scorer trust', async () => {
    const artifact = await buildArtifact();
    const result = await verifyPostRevealEvalReportArtifact(artifact, {
      rpcClient: makeRpcClient(new Map([[artifact.receipt.targetBlock, BLOCKHASH]])),
      scorer: async () => ({ scorePpm: 50_000, accepted: true }),
      epochSecret: `0x${'ee'.repeat(32)}`,
    });
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EPOCH_SECRET_COMMIT_MISMATCH');
  });
});
