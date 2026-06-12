import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  buildPostRevealEvalReportArtifact,
  evalReportArtifactRelativePath,
  evalReportArtifactUrl,
  hashPostRevealEvalReportArtifact,
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

async function buildReceipt() {
  return runPerPatchEvaluation(
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
}

function artifactFields(receipt, over = {}) {
  return {
    version: 'coretex-post-reveal-eval-report-v1',
    epochId: 7,
    minerAddress: MINER,
    outcome: 'STATE_ADVANCE',
    compactPatchBytesHex: `0x${Buffer.from(PATCH_BYTES).toString('hex')}`,
    thresholdPpm: 1_000,
    seedDerivation: {
      mode: 'future_blockhash_dual_pack',
      epochId: 7,
      receivedAtBlock: receipt.receivedAtBlock,
      targetBlock: receipt.targetBlock,
      targetBlockOffset: 30,
      blockhash: receipt.blockhash,
      patchHash: receipt.patchHash,
      parentStateRoot: PARENT_ROOT,
      corpusRoot: CORPUS_ROOT,
      bundleHash: BUNDLE_HASH,
    },
    receipt,
    context: {
      parentStateRoot: PARENT_ROOT,
      corpusRoot: CORPUS_ROOT,
      coreVersionHash: BUNDLE_HASH,
      hiddenSeedCommit: epochSecretCommit(EPOCH_SECRET),
      replayTolerancePpm: 250,
    },
    ...over,
  };
}

async function buildArtifact(over = {}) {
  const receipt = await buildReceipt();
  return buildPostRevealEvalReportArtifact(artifactFields(receipt, over));
}

function verifyDeps(artifact, over = {}) {
  return {
    rpcClient: makeRpcClient(new Map([[artifact.receipt.targetBlock, BLOCKHASH]])),
    scorer: async () => ({ scorePpm: 50_000, accepted: true }),
    epochSecret: EPOCH_SECRET,
    ...over,
  };
}

describe('post-reveal eval report artifact', () => {
  test('builder computes ONE hash and sets evalReportHash == artifactHash to it', async () => {
    const artifact = await buildArtifact();
    assert.match(artifact.artifactHash, /^0x[0-9a-f]{64}$/);
    assert.equal(artifact.evalReportHash, artifact.artifactHash);
    assert.equal(hashPostRevealEvalReportArtifact(artifact), artifact.artifactHash);
  });

  test('round-trips builder → JSON → hash → verify', async () => {
    const artifact = JSON.parse(JSON.stringify(await buildArtifact()));
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps(artifact));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (result.ok) {
      assert.equal(result.artifactHash, artifact.artifactHash);
      assert.equal(result.gateDeltaPpm, 0);
      assert.equal(result.confirmDeltaPpm, 0);
    }
  });

  test('mandatory seed-derivation inputs are part of the schema', async () => {
    const receipt = await buildReceipt();
    const fields = artifactFields(receipt);
    delete fields.seedDerivation;
    const artifact = buildPostRevealEvalReportArtifact(fields);
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps(artifact));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EVAL_ARTIFACT_MALFORMED');
  });

  test('malformed receipt shape fails closed instead of throwing TypeError', async () => {
    const receipt = await buildReceipt();
    const artifact = buildPostRevealEvalReportArtifact(artifactFields(receipt, { receipt: null }));
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps({ ...artifact, receipt }));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EVAL_ARTIFACT_MALFORMED');
  });

  test('tampered score field WITHOUT rehash fails the hash binding', async () => {
    const artifact = await buildArtifact();
    const tampered = { ...artifact, receipt: { ...artifact.receipt, gateScorePpm: 999_999 } };
    const result = await verifyPostRevealEvalReportArtifact(tampered, verifyDeps(artifact));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EVAL_ARTIFACT_HASH_MISMATCH');
  });

  test('tampered score field WITH valid rehash still fails dual-pack replay', async () => {
    // Adversarial coordinator: rebuilds a hash-consistent artifact around an
    // inflated score. The hash binds, the threshold passes — replay catches it.
    const receipt = await buildReceipt();
    const tamperedReceipt = { ...receipt, gateScorePpm: 999_999 };
    const artifact = buildPostRevealEvalReportArtifact(artifactFields(tamperedReceipt));
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps(artifact));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'GATE_SCORE_BEYOND_TOLERANCE');
  });

  test('tampered threshold (min dual score below it) fails threshold semantics', async () => {
    const receipt = await buildReceipt();
    const artifact = buildPostRevealEvalReportArtifact(artifactFields(receipt, { thresholdPpm: 60_000 }));
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps(artifact));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EVAL_ARTIFACT_THRESHOLD_VIOLATION');
  });

  test('evalReportHash diverging from artifactHash is rejected', async () => {
    const artifact = await buildArtifact();
    const tampered = { ...artifact, evalReportHash: `0x${'ef'.repeat(32)}` };
    const result = await verifyPostRevealEvalReportArtifact(tampered, verifyDeps(artifact));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EVAL_REPORT_HASH_MISMATCH');
  });

  test('seed-derivation block that disagrees with the receipt is rejected even when hash-consistent', async () => {
    const receipt = await buildReceipt();
    const fields = artifactFields(receipt);
    const artifact = buildPostRevealEvalReportArtifact({
      ...fields,
      seedDerivation: { ...fields.seedDerivation, receivedAtBlock: receipt.receivedAtBlock + 1, targetBlock: receipt.targetBlock + 1 },
    });
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps(artifact));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EVAL_ARTIFACT_SEED_INPUTS_MISMATCH');
  });

  test('mismatched epoch secret fails before scorer trust', async () => {
    const artifact = await buildArtifact();
    const result = await verifyPostRevealEvalReportArtifact(artifact, verifyDeps(artifact, {
      epochSecret: `0x${'ee'.repeat(32)}`,
    }));
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.code, 'EPOCH_SECRET_COMMIT_MISMATCH');
  });

  test('published artifact path convention is eval-reports/<artifactHash>.json', async () => {
    const artifact = await buildArtifact();
    assert.equal(
      evalReportArtifactRelativePath(artifact.artifactHash),
      `eval-reports/${artifact.artifactHash.toLowerCase()}.json`,
    );
    assert.equal(
      evalReportArtifactUrl('https://artifacts.example/', artifact.artifactHash),
      `https://artifacts.example/eval-reports/${artifact.artifactHash.toLowerCase()}.json`,
    );
    assert.throws(() => evalReportArtifactRelativePath('0x1234'), /bytes32/);
  });
});
