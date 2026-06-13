/**
 * serializeProductionCorpus must round-trip every field that
 * computeCorpusEventLeafHash hashes (canonicalJson of the FULL in-memory
 * event). Evolved corpora carry optional metadata the genesis corpus lacks
 * (logicalFamily/band from the logical-delta bridge, causalDepth/
 * relationHopDepth/grounding from synthesis); dropping any of them on
 * serialize means a serialize→load round-trip computes a different leaf hash
 * and the materialized corpus fails root verification against the pinned root.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  computeCorpusEventLeafHash,
  computeCorpusRoot,
  serializeProductionCorpus,
} from '../../dist/index.js';
import { bytesToHex } from '../../dist/state/merkle.js';

const LAYOUT = { dim: 8, headerBytes: 9, quantization: 'int8' };

function fullEvent(id) {
  return {
    id,
    family: 'temporal',
    domain: 'd',
    split: 'eval_hidden',
    queryText: `q ${id}`,
    truthDocuments: [{ id: `${id}-t`, text: 't', isCurrent: true }],
    hardNegatives: [],
    qrels: [{ documentId: `${id}-t`, relevance: 1 }],
    protected: false,
    // Every optional field the leaf hash covers and evolve/synthesis can set:
    causalDepth: 2,
    relationHopDepth: 3,
    band: 'hard',
    grounding: 'distant',
    logicalFamily: 'temporal_validity',
    provenance: { source: 'synthetic_challenge', sourceHash: '0x' + '00'.repeat(32) },
    embeddings: {
      modelId: 'm',
      revision: 'r',
      layout: LAYOUT,
      query: new Uint8Array(4 + 8).fill(7),
      perTruth: new Map([[`${id}-t`, new Uint8Array(4 + 8).fill(9)]]),
      perNegative: new Map(),
    },
  };
}

function corpusOf(events) {
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    corpusRoot: computeCorpusRoot(events),
    corpusEpoch: 0,
    biEncoderModelId: 'm',
    biEncoderRevision: 'r',
    biEncoderRetrievalKeyLayout: LAYOUT,
    labelingModelId: 'lm',
    labelingModelRevision: 'lr',
  };
}

function hexToUint8(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Mirror loadProductionCorpus's whole-file event reconstruction (spread + hex→bytes). */
function loadEventFromDisk(e) {
  return {
    ...e,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: hexToUint8(e.embeddings.query),
      perTruth: new Map(Object.entries(e.embeddings.perTruth).map(([k, v]) => [k, hexToUint8(v)])),
      perNegative: new Map(Object.entries(e.embeddings.perNegative).map(([k, v]) => [k, hexToUint8(v)])),
    },
  };
}

describe('serializeProductionCorpus round-trip', () => {
  test('leaf hash and corpusRoot survive serialize → JSON → load for fully-annotated events', () => {
    const events = [fullEvent('e1'), fullEvent('e2')];
    const corpus = corpusOf(events);

    const onDisk = JSON.parse(JSON.stringify(serializeProductionCorpus(corpus)));
    const reloaded = onDisk.events.map(loadEventFromDisk);

    for (let i = 0; i < events.length; i++) {
      assert.equal(
        bytesToHex(computeCorpusEventLeafHash(reloaded[i])),
        bytesToHex(computeCorpusEventLeafHash(events[i])),
        `leaf hash drift for ${events[i].id} — serializeProductionCorpus dropped a hashed field`,
      );
    }
    assert.equal(computeCorpusRoot(reloaded), corpus.corpusRoot);
  });

  test('serialized events carry the evolve/synthesis metadata fields verbatim', () => {
    const onDisk = serializeProductionCorpus(corpusOf([fullEvent('e1')]));
    const e = onDisk.events[0];
    assert.equal(e.causalDepth, 2);
    assert.equal(e.relationHopDepth, 3);
    assert.equal(e.band, 'hard');
    assert.equal(e.grounding, 'distant');
    assert.equal(e.logicalFamily, 'temporal_validity');
  });

  test('fields absent in memory stay absent on disk (genesis corpora unchanged)', () => {
    const bare = fullEvent('e1');
    delete bare.causalDepth;
    delete bare.relationHopDepth;
    delete bare.band;
    delete bare.grounding;
    delete bare.logicalFamily;
    const onDisk = serializeProductionCorpus(corpusOf([bare]));
    const e = onDisk.events[0];
    for (const k of ['causalDepth', 'relationHopDepth', 'band', 'grounding', 'logicalFamily']) {
      assert.ok(!(k in e), `${k} must not appear on disk when unset (would change genesis leaf hashes)`);
    }
  });
});
