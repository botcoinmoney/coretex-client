/**
 * Regression lock for the deterministic state-root + patch wire vectors
 * (release/calibration/fixtures/state-root-vectors.json), the on-chain /
 * standalone-replay parity fixture produced by scripts/state-root-vectors.mjs.
 *
 * A fresh checkout must be able to: rebuild genesis, replay each pinned patch
 * wire-byte-for-byte, and land on the pinned child state root + patch hash.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { merkleizeState, bytesToHex } from '../../dist/state/merkle.js';
import { decodePatch, applyPatch } from '../../dist/state/patch.js';
import { computePatchHash } from '../../dist/eval/seed-derivation.js';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(here, '../../../../release/calibration/fixtures/state-root-vectors.json');

function hexToBytes(hex) {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe('state-root vectors (on-chain / standalone replay parity)', () => {
  const fx = JSON.parse(readFileSync(FIXTURE, 'utf8'));
  const [genesisVec, ...patchVecs] = fx.vectors;

  test('genesis root matches the all-zero 1024-word state', () => {
    const genesis = { words: new Array(1024).fill(0n) };
    assert.equal(bytesToHex(merkleizeState(genesis)), genesisVec.stateRoot);
  });

  test('replaying pinned patch wire bytes reproduces every pinned root + patchHash', () => {
    let state = { words: new Array(1024).fill(0n) };
    for (const vec of patchVecs) {
      // parent root continuity
      assert.equal(bytesToHex(merkleizeState(state)), vec.parentStateRoot, `${vec.name}: parent root`);
      const wire = hexToBytes(vec.patchBytesHex);
      // domain-separated patch hash matches
      assert.equal(computePatchHash(wire), vec.patchHash, `${vec.name}: patchHash`);
      const patch = decodePatch(wire);
      const res = applyPatch(state, patch);
      assert.equal(res.ok, true, `${vec.name}: applyPatch rejected`);
      assert.equal(bytesToHex(merkleizeState(res.state)), vec.childStateRoot, `${vec.name}: child root`);
      state = res.state;
    }
  });

  test('layout-agreement battery in the fixture is all-PASS', () => {
    for (const [k, v] of Object.entries(fx.layoutAgreement)) {
      assert.equal(v, true, `layout battery ${k} must be PASS`);
    }
  });
});
