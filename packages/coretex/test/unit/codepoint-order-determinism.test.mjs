/**
 * Codepoint-order determinism for pinned-hash sorts.
 *
 * Every production sort that feeds a pinned hash (corpusRoot leaf ordering,
 * hidden-pack derivation ordering) must use the deterministic codepoint
 * comparator, NEVER `localeCompare`: ICU collation is locale/version-dependent.
 * The probe ids 'a_x' vs 'a0x' are the divergence case — codepoint order puts
 * 'a0x' first ('0' = 0x30 < '_' = 0x5f) while en-locale collation puts 'a_x'
 * first. These tests pin the codepoint ordering end-to-end, so reintroducing
 * localeCompare flips the assertions regardless of the host locale.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  codePointCompare,
  computeCorpusRoot,
  computeCorpusEventLeafHash,
  deriveQueryPack,
} from '../../dist/index.js';
import { keccak256 } from '../../dist/state/keccak256.js';
import { bytesToHex } from '../../dist/state/merkle.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };
function ev(id) {
  return {
    id, family: 'temporal', domain: 'd', split: 'eval_hidden', queryText: `q ${id}`,
    truthDocuments: [{ id: `${id}-t`, text: 't', isCurrent: true }], hardNegatives: [],
    qrels: [{ documentId: `${id}-t`, relevance: 1 }], protected: false,
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + '00'.repeat(32) },
    embeddings: { modelId: 'm', revision: 'r', layout: LAYOUT, query: new Uint8Array(4 + 8), perTruth: new Map(), perNegative: new Map() },
  };
}

// The divergence ids, deliberately listed in NEITHER order.
const DIVERGENT_IDS = ['a_x', 'a0x', 'a1x'];
const CODEPOINT_ORDER = ['a0x', 'a1x', 'a_x'];

function u64BE(n) {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function digestU256(parts) {
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { buf.set(p, off); off += p.length; }
  const d = keccak256(buf);
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(d[i]);
  return v;
}
function hexBytes(hex) {
  const clean = hex.replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe('codepoint comparator vs locale collation', () => {
  test('codePointCompare orders the divergence case opposite to en-locale collation', () => {
    assert.ok(codePointCompare('a0x', 'a_x') < 0, 'codepoint: a0x before a_x');
    assert.ok(codePointCompare('a_x', 'a0x') > 0);
    assert.equal(codePointCompare('a_x', 'a_x'), 0);
    // ICU en collation puts a_x FIRST — the comparator must NOT agree with it.
    assert.ok('a_x'.localeCompare('a0x', 'en') < 0, 'en collation diverges on this pair');
    assert.deepEqual([...DIVERGENT_IDS].sort(codePointCompare), CODEPOINT_ORDER);
  });

  test('corpusRoot leaf ordering is codepoint order, independent of input order', () => {
    const events = new Map(DIVERGENT_IDS.map((id) => [id, ev(id)]));
    const rootA = computeCorpusRoot(['a_x', 'a0x', 'a1x'].map((id) => events.get(id)));
    const rootB = computeCorpusRoot(['a1x', 'a_x', 'a0x'].map((id) => events.get(id)));
    assert.equal(rootA, rootB, 'corpusRoot must not depend on input order');
    // Manual Merkle over leaves in EXPLICIT codepoint order, zero-padded to 4:
    // ((a0x, a1x), (a_x, zero)).
    const [l0, l1, l2] = CODEPOINT_ORDER.map((id) => computeCorpusEventLeafHash(events.get(id)));
    const pair = (left, right) => {
      const buf = new Uint8Array(64);
      buf.set(left, 0); buf.set(right, 32);
      return keccak256(buf);
    };
    assert.equal(rootA, bytesToHex(pair(pair(l0, l1), pair(l2, new Uint8Array(32)))), 'leaf order must be codepoint order');
  });

  test('deriveQueryPack samples over the codepoint-sorted id space', () => {
    const events = DIVERGENT_IDS.map((id) => ev(id));
    const corpus = {
      events, byId: new Map(events.map((e) => [e.id, e])), corpusRoot: '0x' + '00'.repeat(32), corpusEpoch: 0,
      biEncoderModelId: 'm', biEncoderRevision: 'r', biEncoderRetrievalKeyLayout: LAYOUT,
      labelingModelId: 'm', labelingModelRevision: 'r',
    };
    const seedHex = '0x' + 'a5'.repeat(32);
    const epochId = 7;
    const packSize = 2;
    const pack = deriveQueryPack(epochId, seedHex, corpus, { packSize, quotas: [] });

    // Replay the free-sampling loop against the EXPLICIT codepoint-sorted array.
    const seed = hexBytes(seedHex);
    const epochBE = u64BE(epochId);
    const expected = [];
    for (let i = 0; expected.length < packSize && i < CODEPOINT_ORDER.length * 8; i++) {
      const idx = digestU256([seed, epochBE, u64BE(i)]) % BigInt(CODEPOINT_ORDER.length);
      const id = CODEPOINT_ORDER[Number(idx)];
      if (!expected.includes(id)) expected.push(id);
    }
    assert.deepEqual(pack.events.map((e) => e.id), expected, 'pack derivation must index the codepoint-sorted event list');
  });
});
