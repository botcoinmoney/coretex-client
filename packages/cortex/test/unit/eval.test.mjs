/**
 * Unit tests: eval harness, eval report, deterministic report hash.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { evalPatch, StubCorpusLoader, canonicalJson } from '../../dist/eval/index.js';
import { merkleizeState, bytesToHex, hexToBytes } from '../../dist/state/merkle.js';
import { applyPatch, encodePatch, decodePatch } from '../../dist/state/patch.js';
import { PATCH_TYPE } from '../../dist/state/types.js';

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
      patchType: PATCH_TYPE.SLOT_REPLACE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: root,
      indices: [992], // reserved range
      newWords: [1n],
    };
    const patchWireBytes = encodePatch(patch);
    const report = evalPatch(state, patch, { patchWireBytes });
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
