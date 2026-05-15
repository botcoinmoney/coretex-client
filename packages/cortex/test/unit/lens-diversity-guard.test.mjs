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
  evaluateRetrievalBenchmarkState,
  CORETEX_PIPELINE_VERSION_THIS_BINARY,
  assertPipelineVersionMatches,
  createDeterministicReranker,
  createDeterministicBiEncoder,
  biEncoderModelIdHash,
  computeCorpusRoot,
  splitForRecord,
  DEFAULT_PROFILE,
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

// ─── Live-scorer wire-up: the guard must trigger via evaluateRetrievalBenchmarkState ─

describe('§6.4 lens-diversity floor — wired into live scorer', () => {
  // Build a tiny corpus + pack so we can score in-process.
  const BI = { modelId: 'BAAI/bge-m3', revision: 'a'.repeat(40), mode: 'dense' };
  const LAYOUT_SMALL = { dim: 8, quantization: 'int8', headerBytes: 9 };

  function makeEvent(id, family, corpusEpoch = 0) {
    const split = splitForRecord(id, corpusEpoch);
    return {
      id, family, domain: 'companies', split,
      queryText: `q-${id}`,
      truthDocuments: [{ id: `${id}::truth`, text: `truth-${id}`, isCurrent: true }],
      hardNegatives: [{ id: `${id}::neg0`, text: `wrong-${id}-0` }],
      qrels: [{ documentId: `${id}::truth`, relevance: 1.0 }, { documentId: `${id}::neg0`, relevance: 0.0 }],
      protected: false,
      provenance: { source: 'synthetic_challenge', sourceHash: '0x' + 'aa'.repeat(32) },
      embeddings: {
        modelId: BI.modelId, revision: BI.revision, layout: LAYOUT_SMALL,
        query: new Uint8Array(LAYOUT_SMALL.dim + 4),
        perTruth: new Map([[`${id}::truth`, new Uint8Array(LAYOUT_SMALL.dim + 4)]]),
        perNegative: new Map([[`${id}::neg0`, new Uint8Array(LAYOUT_SMALL.dim + 4)]]),
      },
    };
  }

  test('collapsed-lens substrate fails structural validity via live scorer (not just decode)', async () => {
    const events = Array.from({ length: 8 }, (_, i) => makeEvent(`r${i}`, 'near_collision'));
    const corpus = {
      events,
      byId: new Map(events.map((e) => [e.id, e])),
      corpusRoot: computeCorpusRoot(events),
      corpusEpoch: 0,
      biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision,
      biEncoderRetrievalKeyLayout: LAYOUT_SMALL,
      labelingModelId: 'memreranker/4B', labelingModelRevision: 'b'.repeat(40),
    };

    // Build a substrate with 4 active retrieval keys ALL colinear (identical bytes).
    const RANGES_LOCAL = { RETRIEVAL_KEYS_START: 384 };
    const collapsedBytes = new Uint8Array(LAYOUT_SMALL.dim + 4);
    // Scale = small fp32 BE; body = constant int8 in one direction
    const dv = new DataView(collapsedBytes.buffer);
    dv.setFloat32(0, 0.01, false);
    for (let i = 4; i < collapsedBytes.length; i++) collapsedBytes[i] = 127;
    const biEncoderHash = biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode);
    const words = new Array(1024).fill(0n);
    for (let s = 0; s < 4; s++) {
      const key = {
        slotIndex: s, modelIdHash: biEncoderHash, l2Norm: 1, versionTag: 1,
        quantizedBytes: collapsedBytes,
      };
      const w = encodeRetrievalKeySlot(key, { retrievalKeyHeaderBytes: LAYOUT_SMALL.headerBytes });
      const base = RANGES_LOCAL.RETRIEVAL_KEYS_START + s * 8;
      for (let j = 0; j < 8; j++) words[base + j] = w[j];
    }
    const collapsedState = { words };

    const reranker = await createDeterministicReranker();
    const biEncoder = createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT_SMALL });
    const pack = { epochId: 0, evalSeedCommit: '0x' + '11'.repeat(32), events: events.slice(0, 2) };
    const opts = {
      weights: DEFAULT_PROFILE.compositeWeights,
      biEncoder, reranker,
      retrievalKeyLayout: LAYOUT_SMALL,
      biEncoderHash,
      relationHopBudget: 2, abstentionThreshold: 0.001, rerankerTopK: 10, retrievalKeyTopK: 50,
      firstStageTopK: 50, lensTopK: 36, lensWeight: 0.1, anchorWeight: 0.15,
      relationExpansionBudget: 50, temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1,
      lensDiversityFloor: 0.70,                                    // pinned in profile
      pipelineVersion: CORETEX_PIPELINE_VERSION_THIS_BINARY,
    };

    const score = await evaluateRetrievalBenchmarkState(collapsedState, corpus, pack, opts);
    // Collapsed lenses → structuralValidity = 0; composite includes the
    // w_structural_sanity weight (0.05) but it gets multiplied by sv=0.
    assert.equal(score.structuralValidity, 0, 'structural validity must drop to 0 on lens collapse via live scorer');
  });

  test('non-collapsed substrate passes structural validity via live scorer', async () => {
    const events = Array.from({ length: 8 }, (_, i) => makeEvent(`r${i}`, 'near_collision'));
    const corpus = {
      events,
      byId: new Map(events.map((e) => [e.id, e])),
      corpusRoot: computeCorpusRoot(events),
      corpusEpoch: 0,
      biEncoderModelId: BI.modelId, biEncoderRevision: BI.revision,
      biEncoderRetrievalKeyLayout: LAYOUT_SMALL,
      labelingModelId: 'memreranker/4B', labelingModelRevision: 'b'.repeat(40),
    };

    const reranker = await createDeterministicReranker();
    const biEncoder = createDeterministicBiEncoder({ modelId: BI.modelId, revision: BI.revision, layout: LAYOUT_SMALL });
    const pack = { epochId: 0, evalSeedCommit: '0x' + '11'.repeat(32), events: events.slice(0, 2) };
    const opts = {
      weights: DEFAULT_PROFILE.compositeWeights,
      biEncoder, reranker, retrievalKeyLayout: LAYOUT_SMALL,
      biEncoderHash: biEncoderModelIdHash(BI.modelId, BI.revision, BI.mode),
      relationHopBudget: 2, abstentionThreshold: 0.001, rerankerTopK: 10, retrievalKeyTopK: 50,
      firstStageTopK: 50, lensTopK: 36, lensWeight: 0.1, anchorWeight: 0.15,
      relationExpansionBudget: 50, temporalCurrentBoost: 0.1, temporalStaleSuppression: 0.1,
      lensDiversityFloor: 0.70,
      pipelineVersion: CORETEX_PIPELINE_VERSION_THIS_BINARY,
    };

    // Empty substrate — no active lenses → diversity check returns ok=true (nothing to collapse).
    const ZERO = { words: new Array(1024).fill(0n) };
    const score = await evaluateRetrievalBenchmarkState(ZERO, corpus, pack, opts);
    assert.equal(score.structuralValidity, 1, 'empty substrate must pass structural validity');
  });
});

// ─── §6.6 pipeline-version pin enforcement ─────────────────────────────────────

describe('§6.6 pipelineVersion pin enforcement', () => {
  test('assertPipelineVersionMatches accepts the binary\'s own version', () => {
    assert.doesNotThrow(() => assertPipelineVersionMatches(CORETEX_PIPELINE_VERSION_THIS_BINARY));
  });

  test('assertPipelineVersionMatches accepts undefined (older bundles without the pin)', () => {
    assert.doesNotThrow(() => assertPipelineVersionMatches(undefined));
    assert.doesNotThrow(() => assertPipelineVersionMatches(''));
  });

  test('assertPipelineVersionMatches throws on mismatch', () => {
    assert.throws(
      () => assertPipelineVersionMatches('coretex-retrieval-v3-future'),
      /pipelineVersion mismatch/,
    );
  });

  test('CORETEX_PIPELINE_VERSION_OVERRIDE env var bypasses the mismatch', () => {
    const original = process.env.CORETEX_PIPELINE_VERSION_OVERRIDE;
    try {
      process.env.CORETEX_PIPELINE_VERSION_OVERRIDE = 'coretex-retrieval-v3-future';
      assert.doesNotThrow(() => assertPipelineVersionMatches('coretex-retrieval-v3-future'));
    } finally {
      if (original === undefined) delete process.env.CORETEX_PIPELINE_VERSION_OVERRIDE;
      else process.env.CORETEX_PIPELINE_VERSION_OVERRIDE = original;
    }
  });
});
