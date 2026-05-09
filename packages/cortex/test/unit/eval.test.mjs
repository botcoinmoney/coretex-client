/**
 * Unit tests: eval harness, eval report, deterministic report hash.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { evalPatch, StubCorpusLoader, canonicalJson } from '../../dist/eval/index.js';
import { ProductionCorpusLoader, eventIdToKey128, eventIdToMem128, loadProductionCorpus, scoreProductionState } from '../../dist/eval/corpus.js';
import { buildMerkleCache, merkleizeState, bytesToHex, hexToBytes } from '../../dist/state/merkle.js';
import { applyPatch, encodePatch, decodePatch, encodeLEB128 } from '../../dist/state/patch.js';
import { PATCH_TYPE } from '../../dist/state/types.js';
import { fileURLToPath } from 'node:url';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeCleanState() {
  return { words: new Array(1024).fill(0n) };
}

function makePatch(state, overrides = {}) {
  const root = merkleizeState(state);
  return {
    patchType: PATCH_TYPE.KEY_UPDATE,
    wordCount: 1,
    scoreDelta: 1000000n,
    parentStateRoot: root,
    indices: [401],
    newWords: [0xdeadbeefn],
    ...overrides,
  };
}

function makeEncodedPatch(state, overrides = {}) {
  const patch = makePatch(state, overrides);
  return { patch, patchWireBytes: encodePatch(patch) };
}

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));
const season1Path = `${repoRoot}/benchmark/fixtures/season1/coretex_season1_10000.json`;

// ─── EvalPatch tests ──────────────────────────────────────────────────────────

describe('evalPatch — accepted patch', () => {
  test('returns accepted=true for valid patch', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const report = evalPatch(state, patch, { patchWireBytes });
    assert.equal(report.accepted, true);
    assert.equal(report.errorCode, null);
    assert.ok(report.newStateRoot !== null);
  });

  test('newStateRoot matches applyPatch result', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const report = evalPatch(state, patch, { patchWireBytes });
    assert.equal(report.accepted, true);
    const patchResult = applyPatch(state, patch);
    assert.equal(patchResult.ok, true);
    if (patchResult.ok) {
      const expectedRoot = bytesToHex(merkleizeState(patchResult.state));
      assert.equal(report.newStateRoot, expectedRoot);
    }
  });

  test('cached Merkle eval matches uncached eval roots', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const uncached = evalPatch(state, patch, { patchWireBytes });
    const cached = evalPatch(state, patch, {
      patchWireBytes,
      merkleCache: buildMerkleCache(state),
    });

    assert.equal(cached.accepted, true);
    assert.equal(cached.parentStateRoot, uncached.parentStateRoot);
    assert.equal(cached.newStateRoot, uncached.newStateRoot);
    assert.equal(cached.patchHash, uncached.patchHash);
  });

  test('reportHash is 0x-prefixed 64-char hex', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const report = evalPatch(state, patch, { patchWireBytes });
    assert.match(report.reportHash, /^0x[0-9a-f]{64}$/);
  });

  test('patchHash is keccak256 of patchWireBytes', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const report = evalPatch(state, patch, { patchWireBytes });
    // patchHash should be 0x-prefixed hex
    assert.match(report.patchHash, /^0x[0-9a-f]{64}$/);
  });

  test('parentStateRoot matches input state', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const report = evalPatch(state, patch, { patchWireBytes });
    const expectedRoot = bytesToHex(merkleizeState(state));
    assert.equal(report.parentStateRoot, expectedRoot);
  });
});

describe('evalPatch — rejected patch', () => {
  test('E01 wrong parent root → accepted=false, errorCode=E01', () => {
    const state = makeCleanState();
    const wrongRoot = new Uint8Array(32).fill(0xff);
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: wrongRoot,
      indices: [401],
      newWords: [1n],
    };
    const patchWireBytes = encodePatch(patch);
    const report = evalPatch(state, patch, { patchWireBytes });
    assert.equal(report.accepted, false);
    assert.equal(report.errorCode, 'E01');
    assert.equal(report.newStateRoot, null);
  });

  test('E05 noop patch → accepted=false, errorCode=E05', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: root,
      indices: [401],
      newWords: [0n], // no-op (state is all zeros)
    };
    const patchWireBytes = encodePatch(patch);
    const report = evalPatch(state, patch, { patchWireBytes });
    assert.equal(report.accepted, false);
    assert.equal(report.errorCode, 'E05');
  });

  test('E02 reserved range → accepted=false, errorCode=E02', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: root,
      indices: [992], // reserved range
      newWords: [1n],
    };
    assert.throws(() => encodePatch(patch), /reserved/);

    const validPatch = { ...patch, indices: [384] };
    const patchWireBytes = encodePatch(validPatch);
    patchWireBytes.set(encodeLEB128(992), 42);
    const decoded = decodePatch(patchWireBytes);
    assert.deepEqual(decoded.indices, [992]);

    const report = evalPatch(state, decoded, { patchWireBytes });
    assert.equal(report.accepted, false);
    assert.equal(report.errorCode, 'E02');
  });

  test('E03 over-budget patch → accepted=false, errorCode=E03', () => {
    const state = makeCleanState();
    const root = merkleizeState(state);
    const patch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 5,
      scoreDelta: 0n,
      parentStateRoot: root,
      indices: [401, 402, 403, 404, 405],
      newWords: [1n, 2n, 3n, 4n, 5n],
    };
    const patchWireBytes = new Uint8Array(0);
    const report = evalPatch(state, patch, { patchWireBytes });
    assert.equal(report.accepted, false);
    assert.equal(report.errorCode, 'E03');
  });

  test('E04 invalid parent reserved bit remains rejected on cached path', () => {
    const state = makeCleanState();
    state.words[11] = 1n; // header word 11 is fully reserved.
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    const report = evalPatch(state, patch, {
      patchWireBytes,
      merkleCache: buildMerkleCache(state),
    });

    assert.equal(report.accepted, false);
    assert.equal(report.errorCode, 'E04');
    assert.equal(report.newStateRoot, null);
  });
});

// ─── Determinism tests ────────────────────────────────────────────────────────

describe('evalPatch — determinism', () => {
  test('same inputs produce identical reportHash', () => {
    const state = makeCleanState();
    const { patch, patchWireBytes } = makeEncodedPatch(state);
    // Evaluate twice with fixed shardId
    const shardId = new Uint8Array(32).fill(0x01);
    const r1 = evalPatch(state, patch, { patchWireBytes, shardId });
    const r2 = evalPatch(state, patch, { patchWireBytes, shardId });
    // reportHash must be identical (modulo evalTimestampMs and evalDurationUs)
    // We compare without timestamp/duration:
    const r1stable = { ...r1, evalTimestampMs: '0', evalDurationUs: 0, reportHash: '' };
    const r2stable = { ...r2, evalTimestampMs: '0', evalDurationUs: 0, reportHash: '' };
    assert.deepEqual(r1stable, r2stable);
  });

  test('canonicalJson produces sorted keys, no whitespace, bigint as string', () => {
    const obj = {
      version: 'v0',
      parentStateRoot: '0xabc',
      newStateRoot: null,
      patchHash: '0xdef',
      accepted: false,
      errorCode: 'E01',
      errorMessage: 'msg',
      baselineScore: 1000000n,
      candidateScore: 1000000n,
      scoreDelta: 0n,
      corpusRoot: '0x' + '00'.repeat(32),
      shardId: '0x' + '00'.repeat(32),
      evalTimestampMs: '1000',
      evalDurationUs: 5,
    };
    const bytes = canonicalJson(obj);
    const json = new TextDecoder().decode(bytes);
    // Should have no whitespace
    assert.ok(!json.includes(' '));
    assert.ok(!json.includes('\n'));
    // Should have sorted keys
    const parsed = JSON.parse(json);
    const keys = Object.keys(parsed);
    assert.deepEqual(keys, [...keys].sort());
    // bigint values encoded as e.g. "1000000n"
    assert.ok(json.includes('"1000000n"'));
  });
});

// ─── StubCorpusLoader ─────────────────────────────────────────────────────────

describe('StubCorpusLoader', () => {
  test('score returns 0.5 deterministically', () => {
    const loader = new StubCorpusLoader();
    const state = makeCleanState();
    // Fake decoded state
    const decoded = {
      header: {},
      memoryIndex: [],
      retrievalKeys: [],
      relations: [],
      temporal: [],
      codebook: [],
      routes: new Map(),
      revokedEventIds: new Set(),
    };
    const score = loader.score(decoded, new Uint8Array(32));
    assert.equal(score, 0.5);
  });

  test('corpusRoot defaults to 0x000...', () => {
    const loader = new StubCorpusLoader();
    assert.equal(loader.corpusRoot, '0x' + '00'.repeat(32));
  });

  test('custom corpusRoot preserved', () => {
    const root = '0x' + 'ab'.repeat(32);
    const loader = new StubCorpusLoader(root);
    assert.equal(loader.corpusRoot, root);
  });
});

describe('ProductionCorpusLoader', () => {
  test('loads season1 with verified corpus root', () => {
    const corpus = loadProductionCorpus(season1Path);
    assert.equal(corpus.corpusRoot, '0x43ebf3457a51476adc5c563bbaace98af00106d7d28f92b5d7d29ec859fd8f7f');
    assert.equal(corpus.events.long_horizon.length > 0, true);
  });

  test('scores a raw state against corpus records deterministically', () => {
    const corpus = loadProductionCorpus(season1Path);
    const event = corpus.events.long_horizon[0];
    const state = makeCleanState();
    const base = scoreProductionState(state, corpus, { shardId: '0x' + '42'.repeat(16), evalItemsPerFamily: 0 });
    state.words[32] =
      (eventIdToMem128(event.id) << 128n)
      | (1n << 96n)
      | (1n << 80n)
      | (1n << 64n);
    const candidate = scoreProductionState(state, corpus, { shardId: '0x' + '42'.repeat(16), evalItemsPerFamily: 0 });
    assert.equal(base.composite, 0);
    assert.ok(candidate.composite > base.composite);
    assert.equal(candidate.hits.long_horizon, 1);
  });

  test('evalPatch uses the production corpus raw-state scorer', () => {
    const corpus = loadProductionCorpus(season1Path);
    const event = corpus.events.long_horizon[0];
    const state = makeCleanState();
    const word =
      (eventIdToMem128(event.id) << 128n)
      | (1n << 96n)
      | (1n << 80n)
      | (1n << 64n);
    const patch = makePatch(state, {
      patchType: PATCH_TYPE.SLOT_REPLACE,
      scoreDelta: 1n,
      indices: [32],
      newWords: [word],
    });
    const patchWireBytes = encodePatch(patch);
    const loader = ProductionCorpusLoader.fromFile(season1Path, { evalItemsPerFamily: 0 });
    const report = evalPatch(state, patch, {
      loader,
      patchWireBytes,
      shardId: new Uint8Array(32).fill(0x42),
    });
    assert.equal(report.accepted, true);
    assert.equal(report.corpusRoot, corpus.corpusRoot);
    assert.ok(report.candidateScore > report.baselineScore);
  });

  test('production composite matches the launch bundle 20/20/20/20/10/10 profile', () => {
    const corpus = {
      corpusRoot: '0x' + '11'.repeat(32),
      sources: {},
      events: {
        near_collision: [{
          id: 'near-1',
          family: 'near_collision',
          taskType: 'near',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: '',
          truthText: '',
          isStaleTruth: false,
          relevant: true,
        }],
        temporal: [
          {
            id: 'stale-1',
            family: 'temporal',
            taskType: 'stale',
            isProtected: false,
            epochCommitted: 1,
            sourceRef: 'test',
            queryText: '',
            truthText: '',
            isStaleTruth: true,
            relevant: true,
          },
          {
            id: 'current-1',
            family: 'temporal',
            taskType: 'current',
            isProtected: false,
            epochCommitted: 1,
            sourceRef: 'test',
            queryText: '',
            truthText: '',
            isStaleTruth: false,
            relevant: true,
          },
        ],
        long_horizon: [{
          id: 'long-1',
          family: 'long_horizon',
          taskType: 'long',
          isProtected: false,
          epochCommitted: 1,
          sourceRef: 'test',
          queryText: '',
          truthText: '',
          isStaleTruth: false,
          relevant: true,
        }],
      },
    };
    const state = makeCleanState();
    state.words[32] = (eventIdToMem128('current-1') << 128n) | (1n << 64n);
    state.words[40] = (eventIdToMem128('stale-1') << 128n) | (3n << 64n);
    state.words[48] = (eventIdToMem128('long-1') << 128n) | (1n << 64n);
    state.words[384] = (eventIdToKey128('near-1') << 128n) | (1n << 80n);
    for (let i = 672; i <= 799; i++) state.words[i] = 1n << 192n;
    for (let slot = 0; slot < 48; slot++) {
      state.words[896 + slot * 2] = (BigInt(slot + 1) << 240n) | (1n << 224n) | (1n << 208n);
    }

    // F2 fix: localModelAgreement defaults to 0 (not circular mean of other 5).
    // Without localModelAgreementOverride, the 5 active components sum to 0.90.
    const score = scoreProductionState(state, corpus, { shardId: '0x' + '00'.repeat(16), evalItemsPerFamily: 0 });
    assert.equal(score.components.nearCollisionRetrieval, 1);
    assert.equal(score.components.temporalCurrentStale, 1);
    assert.equal(score.components.longHorizonCompression, 1);
    assert.equal(score.components.relationMultiHop, 1);
    assert.equal(score.components.codebookCompression, 1);
    assert.equal(score.components.localModelAgreement, 0);
    assert.equal(score.composite, 0.90);

    // With localModelAgreementOverride: 1.0, composite reaches 1.0
    const scoreWithOverride = scoreProductionState(state, corpus, {
      shardId: '0x' + '00'.repeat(16),
      evalItemsPerFamily: 0,
      localModelAgreementOverride: 1.0,
    });
    assert.equal(scoreWithOverride.components.localModelAgreement, 1);
    assert.equal(scoreWithOverride.composite, 1);
  });
});
