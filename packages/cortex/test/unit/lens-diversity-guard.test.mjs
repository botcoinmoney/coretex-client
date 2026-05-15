/**
 * §6.4 lens-diversity floor — substrate-level structural guard against
 * collapsing all 36 retrieval-key (lens) vectors to a single direction.
 *
 * Spec: docs/CORETEX_SUBSTRATE_EXPANSION_HARDENING.md §6.4.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  checkLensDiversity,
  decodeSubstrate,
  encodeRetrievalKeySlot,
  structuralValidity,
} from '../../dist/index.js';
import { RANGES } from '../../dist/state/types.js';

const ZERO_STATE = { words: new Array(1024).fill(0n) };
const MODEL_HASH = '0xdeadbeef';
const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };

function withWords(state, indexed) {
  const words = [...state.words];
  for (const [i, v] of indexed) words[i] = v;
  return { words };
}

/**
 * Build an int8-quantized lens-vector payload (4-byte BE float32 scale +
 * `dim` int8 codes) of the shape the public-corpus-index dequantizer
 * (and the new in-decoder dequantizer) expect.
 *
 * `floats` is a fp32 vector of length `dim`. We pick a per-vector scale
 * such that the largest absolute coefficient maps to +/- 100 (well clear
 * of the int8 saturation point) to keep round-trip noise low for cosine.
 */
function quantizeInt8(floats) {
  const dim = floats.length;
  let maxAbs = 0;
  for (const v of floats) if (Math.abs(v) > maxAbs) maxAbs = Math.abs(v);
  const scale = maxAbs > 0 ? maxAbs / 100 : 1;
  const out = new Uint8Array(4 + dim);
  const dv = new DataView(out.buffer);
  dv.setFloat32(0, scale, false);
  for (let i = 0; i < dim; i++) {
    let code = Math.round(floats[i] / scale);
    if (code > 127) code = 127;
    if (code < -128) code = -128;
    out[4 + i] = code & 0xff;
  }
  return out;
}

function placeRetrievalKey(state, slotIndex, vector) {
  const quantizedBytes = quantizeInt8(vector);
  const enc = encodeRetrievalKeySlot(
    {
      slotIndex,
      modelIdHash: MODEL_HASH,
      l2Norm: 1.0,
      versionTag: 1,
      quantizedBytes,
    },
    { retrievalKeyHeaderBytes: LAYOUT.headerBytes },
  );
  const indexed = enc.map((v, i) => [RANGES.RETRIEVAL_KEYS_START + slotIndex * 8 + i, v]);
  return withWords(state, indexed);
}

function buildSubstrateWithKeys(vectors) {
  let s = { words: [...ZERO_STATE.words] };
  for (let i = 0; i < vectors.length; i++) {
    s = placeRetrievalKey(s, i, vectors[i]);
  }
  return s;
}

describe('§6.4 lens-diversity floor — checkLensDiversity', () => {
  test('one active key → passes (no diversity to check)', () => {
    const v = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const state = buildSubstrateWithKeys([v]);
    const decoded = decodeSubstrate(state, {
      biEncoderModelIdHash: MODEL_HASH,
      retrievalKeyHeaderBytes: LAYOUT.headerBytes,
    });
    const res = checkLensDiversity(decoded.retrievalKeys, 0.7, LAYOUT);
    assert.equal(res.ok, true);
    assert.equal(res.reason, undefined);
    // Mean cosine undefined with <2 active keys.
    assert.equal(res.meanPairwiseCosine, undefined);
  });

  test('two orthogonal active keys → passes with mean cosine near 0', () => {
    const a = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const b = new Float32Array([0, 1, 0, 0, 0, 0, 0, 0]);
    const state = buildSubstrateWithKeys([a, b]);
    const decoded = decodeSubstrate(state, {
      biEncoderModelIdHash: MODEL_HASH,
      retrievalKeyHeaderBytes: LAYOUT.headerBytes,
    });
    const res = checkLensDiversity(decoded.retrievalKeys, 0.7, LAYOUT);
    assert.equal(res.ok, true);
    assert.ok(Math.abs(res.meanPairwiseCosine) < 0.05, `got ${res.meanPairwiseCosine}`);
  });

  test('36 colinear keys → fails with lens-diversity-collapse', () => {
    const vectors = [];
    for (let i = 0; i < 36; i++) {
      // All identical — pairwise cosine = 1.0 → mean = 1.0 → above any
      // floor < 1.0.
      vectors.push(new Float32Array([3, 1, 4, 1, 5, 9, 2, 6]));
    }
    const state = buildSubstrateWithKeys(vectors);
    const decoded = decodeSubstrate(state, {
      biEncoderModelIdHash: MODEL_HASH,
      retrievalKeyHeaderBytes: LAYOUT.headerBytes,
      lensDiversityFloor: 0.7,
      retrievalKeyLayout: LAYOUT,
    });
    assert.equal(decoded.lensDiversityCheck.ok, false);
    assert.equal(decoded.lensDiversityCheck.reason, 'lens-diversity-collapse');
    assert.ok(decoded.lensDiversityCheck.meanPairwiseCosine > 0.99);
    // Wire-level diagnostic: structuralValidity drives to 0 on collapse.
    assert.equal(structuralValidity(decoded), 0);
  });

  test('mixed-similarity keys above floor=0.7 → fails when mean exceeds floor', () => {
    // Three vectors all sharing a strong primary direction so the
    // pairwise mean cosine sits comfortably above 0.7 but is not the
    // degenerate identical-vector case.
    const a = new Float32Array([1.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    const b = new Float32Array([1.0, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0]);
    const c = new Float32Array([1.0, 0.0, 0.1, 0.05, 0.0, 0.0, 0.0, 0.0]);
    const state = buildSubstrateWithKeys([a, b, c]);
    const decoded = decodeSubstrate(state, {
      biEncoderModelIdHash: MODEL_HASH,
      retrievalKeyHeaderBytes: LAYOUT.headerBytes,
      lensDiversityFloor: 0.7,
      retrievalKeyLayout: LAYOUT,
    });
    assert.equal(decoded.lensDiversityCheck.ok, false);
    assert.equal(decoded.lensDiversityCheck.reason, 'lens-diversity-collapse');
    assert.ok(
      decoded.lensDiversityCheck.meanPairwiseCosine > 0.7,
      `mean cosine should exceed floor, got ${decoded.lensDiversityCheck.meanPairwiseCosine}`,
    );
    assert.equal(structuralValidity(decoded), 0);
  });

  test('decodeSubstrate without lensDiversityFloor leaves check absent', () => {
    const a = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const b = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]); // colinear
    const state = buildSubstrateWithKeys([a, b]);
    const decoded = decodeSubstrate(state, {
      biEncoderModelIdHash: MODEL_HASH,
      retrievalKeyHeaderBytes: LAYOUT.headerBytes,
      // no lensDiversityFloor, no retrievalKeyLayout
    });
    assert.equal(decoded.lensDiversityCheck, undefined);
    // structuralValidity still 1.0 since other decode invariants pass.
    assert.equal(structuralValidity(decoded), 1);
  });

  test('mean cosine exactly equal to floor → passes (strict-greater-than rejection)', () => {
    // Two vectors with a known mean pairwise cosine of 0.5 admitted at
    // floor=0.5 (the floor is the upper bound the miner is allowed to
    // operate at; only strict-exceed rejects).
    // cos(theta)=0.5 between unit vectors at 60°.
    const a = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const b = new Float32Array([0.5, Math.sqrt(3) / 2, 0, 0, 0, 0, 0, 0]);
    const res = checkLensDiversity(
      [
        {
          slotIndex: 0,
          modelIdHash: MODEL_HASH,
          l2Norm: 1,
          versionTag: 1,
          quantizedBytes: quantizeInt8(a),
        },
        {
          slotIndex: 1,
          modelIdHash: MODEL_HASH,
          l2Norm: 1,
          versionTag: 1,
          quantizedBytes: quantizeInt8(b),
        },
      ],
      0.5 + 5e-2, // allow for int8 quant noise — the floor is just above 0.5
      LAYOUT,
    );
    assert.equal(res.ok, true);
    assert.ok(Math.abs(res.meanPairwiseCosine - 0.5) < 5e-2);
  });
});
