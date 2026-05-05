/**
 * Unit tests: state_translation_patch + explicit reset path.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseStatTranslationPatch,
  applyStatTranslationPatch,
  encodeStatTranslationPatch,
  executeReset,
  UPGRADE_MAGIC,
  RESET_EVENT_MARKER,
} from '../../dist/upgrade/index.js';
import { merkleizeState, bytesToHex } from '../../dist/state/merkle.js';
import { encodePatch } from '../../dist/state/patch.js';
import { PATCH_TYPE } from '../../dist/state/types.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeCleanState() {
  return { words: new Array(1024).fill(0n) };
}

function makeValidPatch(state) {
  const root = merkleizeState(state);
  return {
    patchType: PATCH_TYPE.KEY_UPDATE,
    wordCount: 1,
    scoreDelta: 0n,
    parentStateRoot: root,
    indices: [400],
    newWords: [0xdeadbeefn],
  };
}

function makeTranslation(state, patches) {
  return {
    fromVersion: 0,
    toVersion: 1,
    fromCoreVersionHash: '0x' + '11'.repeat(32),
    toCoreVersionHash: '0x' + '22'.repeat(32),
    patches,
  };
}

// ─── parseStatTranslationPatch tests ──────────────────────────────────────────

describe('parseStatTranslationPatch', () => {
  test('BAD_MAGIC on wrong first byte', () => {
    const data = new Uint8Array(100).fill(0);
    data[0] = 0x00; // wrong magic
    const result = parseStatTranslationPatch(data);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'BAD_MAGIC');
  });

  test('TOO_SHORT on short input', () => {
    const data = new Uint8Array(10).fill(0);
    data[0] = UPGRADE_MAGIC;
    const result = parseStatTranslationPatch(data);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'TOO_SHORT');
  });

  test('round-trip: encode then parse preserves fields', () => {
    const state = makeCleanState();
    const patch = makeValidPatch(state);
    const translation = makeTranslation(state, [patch]);
    const encoded = encodeStatTranslationPatch(translation);
    const result = parseStatTranslationPatch(encoded);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.translation.fromVersion, 0);
      assert.equal(result.translation.toVersion, 1);
      assert.equal(result.translation.fromCoreVersionHash.toLowerCase(), translation.fromCoreVersionHash.toLowerCase());
      assert.equal(result.translation.toCoreVersionHash.toLowerCase(), translation.toCoreVersionHash.toLowerCase());
      assert.equal(result.translation.patches.length, 1);
    }
  });

  test('empty patch list is valid', () => {
    const translation = makeTranslation(makeCleanState(), []);
    const encoded = encodeStatTranslationPatch(translation);
    const result = parseStatTranslationPatch(encoded);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.translation.patches.length, 0);
    }
  });

  test('multiple patches round-trip', () => {
    const state = makeCleanState();
    const p1 = makeValidPatch(state);
    // Apply p1 to get new state for p2's parent root
    const p1Root = merkleizeState({ words: state.words.map((w, i) => i === 400 ? 0xdeadbeefn : w) });
    const p2 = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: p1Root,
      indices: [401],
      newWords: [0xcafebaben],
    };
    const translation = makeTranslation(state, [p1, p2]);
    const encoded = encodeStatTranslationPatch(translation);
    const result = parseStatTranslationPatch(encoded);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.translation.patches.length, 2);
    }
  });
});

// ─── applyStatTranslationPatch tests ─────────────────────────────────────────

describe('applyStatTranslationPatch', () => {
  test('applies patch and returns new state root', () => {
    const state = makeCleanState();
    const patch = makeValidPatch(state);
    const translation = makeTranslation(state, [patch]);
    const result = applyStatTranslationPatch(state, translation);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.patchesApplied, 1);
      assert.match(result.newStateRoot, /^0x[0-9a-f]{64}$/);
      // Verify state changed
      assert.equal(result.state.words[400], 0xdeadbeefn);
    }
  });

  test('VERSION_HASH_MISMATCH when fromCoreVersionHash does not match', () => {
    const state = makeCleanState();
    const patch = makeValidPatch(state);
    const translation = makeTranslation(state, [patch]);
    const result = applyStatTranslationPatch(state, translation, '0x' + '99'.repeat(32));
    assert.equal(result.ok, false);
    assert.equal(result.code, 'VERSION_HASH_MISMATCH');
  });

  test('PATCH_APPLY_ERROR on bad patch in translation', () => {
    const state = makeCleanState();
    // Make a patch with wrong parent root
    const badPatch = {
      patchType: PATCH_TYPE.KEY_UPDATE,
      wordCount: 1,
      scoreDelta: 0n,
      parentStateRoot: new Uint8Array(32).fill(0xff),
      indices: [400],
      newWords: [1n],
    };
    const translation = makeTranslation(state, [badPatch]);
    const result = applyStatTranslationPatch(state, translation);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'PATCH_APPLY_ERROR');
  });

  test('empty patch list returns state unchanged', () => {
    const state = makeCleanState();
    const translation = makeTranslation(state, []);
    const result = applyStatTranslationPatch(state, translation);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.patchesApplied, 0);
      const originalRoot = '0x' + bytesToHex(merkleizeState(state));
      assert.equal(result.newStateRoot.toLowerCase(), originalRoot.toLowerCase());
    }
  });
});

// ─── executeReset tests ───────────────────────────────────────────────────────

describe('executeReset', () => {
  test('emits ResetEvent with CORTEX_RESET marker', () => {
    const oldState = makeCleanState();
    const newGenesis = makeCleanState();
    newGenesis.words[400] = 0x1234n; // different from old
    const { event, state } = executeReset(
      oldState,
      newGenesis,
      100n,
      '0x' + '11'.repeat(32),
      '0x' + '22'.repeat(32),
    );
    assert.equal(event.marker, RESET_EVENT_MARKER);
    assert.equal(event.epoch, 100n);
    assert.equal(event.oldCoreVersionHash, '0x' + '11'.repeat(32));
    assert.equal(event.newCoreVersionHash, '0x' + '22'.repeat(32));
    assert.match(event.oldStateRoot, /^0x[0-9a-f]{64}$/);
    assert.match(event.newGenesisStateRoot, /^0x[0-9a-f]{64}$/);
    // The returned state should be the genesis state
    assert.equal(state.words[400], 0x1234n);
  });

  test('oldStateRoot and newGenesisStateRoot differ when states differ', () => {
    const oldState = makeCleanState();
    const newGenesis = { words: [...makeCleanState().words] };
    newGenesis.words[500] = 0xABCDn;
    const { event } = executeReset(oldState, newGenesis, 1n, '0x' + '00'.repeat(32), '0x' + 'ff'.repeat(32));
    assert.notEqual(event.oldStateRoot, event.newGenesisStateRoot);
  });
});
