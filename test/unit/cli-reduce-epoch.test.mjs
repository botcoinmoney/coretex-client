/**
 * Regression: `coretex-client reduce-epoch` must apply ALL same-parent
 * accepted patches via the canonical reducer. The old inline loop
 * re-validated each patch's wire parent against the already-advanced state,
 * so every patch after the first failed E01 and the command silently
 * reproduced a wrong (single-patch) newStateRoot.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

import {
  pack,
  unpack,
  PACKED_SIZE,
  merkleizeState,
  bytesToHex,
  encodePatch,
  PATCH_TYPE,
} from '../../dist/index.js';
import { reduce, makeReducerInput } from '../../dist/reducer/reducer.js';

const cliPath = join(dirname(fileURLToPath(import.meta.url)), '../../dist/cli.js');

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'cortex-reduce-epoch-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function makeSlotPatch(parentRoot, index, wordValue) {
  return {
    patchType: PATCH_TYPE.SLOT_REPLACE,
    wordCount: 1,
    scoreDelta: 0n,
    parentStateRoot: parentRoot,
    indices: [index],
    newWords: [wordValue],
  };
}

describe('cli reduce-epoch (canonical reducer)', () => {
  test('applies multiple same-parent patches and reproduces the reducer root', () => withTmpDir((dir) => {
    const state = unpack(new Uint8Array(PACKED_SIZE));
    const parentRootBytes = merkleizeState(state);
    const parentRoot = bytesToHex(parentRootBytes);

    const patchA = makeSlotPatch(parentRootBytes, 32, 0x1234n);
    const patchB = makeSlotPatch(parentRootBytes, 33, 0x5678n);
    const wireA = encodePatch(patchA);
    const wireB = encodePatch(patchB);

    const expected = reduce(state, [makeReducerInput(patchA, wireA), makeReducerInput(patchB, wireB)]);
    assert.equal(expected.accepted.length, 2, 'precondition: the canonical reducer accepts both');

    const stateFile = join(dir, 'state.bin');
    writeFileSync(stateFile, pack(state));
    const patchesFile = join(dir, 'patches.json');
    writeFileSync(patchesFile, JSON.stringify([
      {
        compactPatchBytesHex: '0x' + Buffer.from(wireA).toString('hex'),
        patchHash: '0x' + 'aa'.repeat(32),
        parentStateRoot: parentRoot,
      },
      {
        compactPatchBytesHex: '0x' + Buffer.from(wireB).toString('hex'),
        patchHash: '0x' + 'bb'.repeat(32),
        parentStateRoot: parentRoot,
      },
    ]));

    const proc = spawnSync(process.execPath, [cliPath, 'reduce-epoch', stateFile, patchesFile], {
      encoding: 'utf8',
    });
    assert.equal(proc.status, 0, proc.stderr);
    const out = JSON.parse(proc.stdout);
    assert.equal(out.ok, true);
    assert.equal(out.patchesApplied, 2);
    assert.equal(out.newStateRoot.toLowerCase(), expected.newStateRootHex.toLowerCase());
    assert.equal(out.patchSetRoot.toLowerCase(), expected.patchSetRootHex.toLowerCase());
    assert.deepEqual(out.acceptedPatchHashes.length, 2);
    assert.notEqual(out.newStateRoot.toLowerCase(), parentRoot.toLowerCase());
  }));

  test('records with a foreign parentStateRoot are excluded', () => withTmpDir((dir) => {
    const state = unpack(new Uint8Array(PACKED_SIZE));
    const parentRootBytes = merkleizeState(state);
    const parentRoot = bytesToHex(parentRootBytes);
    const wire = encodePatch(makeSlotPatch(parentRootBytes, 32, 0x42n));

    const stateFile = join(dir, 'state.bin');
    writeFileSync(stateFile, pack(state));
    const patchesFile = join(dir, 'patches.json');
    writeFileSync(patchesFile, JSON.stringify([
      {
        compactPatchBytesHex: '0x' + Buffer.from(wire).toString('hex'),
        patchHash: '0x' + 'aa'.repeat(32),
        parentStateRoot: '0x' + 'ff'.repeat(32),
      },
    ]));

    const proc = spawnSync(process.execPath, [cliPath, 'reduce-epoch', stateFile, patchesFile], {
      encoding: 'utf8',
    });
    assert.equal(proc.status, 0, proc.stderr);
    const out = JSON.parse(proc.stdout);
    assert.equal(out.patchesApplied, 0);
    assert.equal(out.newStateRoot.toLowerCase(), parentRoot.toLowerCase());
  }));
});
