/**
 * hardnessBucketFor regression: the alias-qrel-repair pass adds
 * relation-target truth docs to a source event's qrels at
 * relevance >= 0.5 (typically 1.0). Those qrels are POSITIVE — they
 * should NOT count toward the "max negative qrel" heuristic that
 * classifies hardness.
 *
 * Before the fix, repaired multi_hop_relation events reclassified to
 * bucket='hard' because alias qrels at relevance=1 pushed maxNeg to
 * 1.0. This broke deriveQueryPack: the old launch profile.hiddenPack
 * quotas required bucket='medium' for multi_hop_relation, and the
 * eval_hidden split had 0 events at that bucket.
 *
 * The fix excludes qrels with relevance >= 0.5 from the hard-negative
 * loop. These tests pin that contract.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { hardnessBucketFor } from '../../dist/index.js';

function makeEvent({ truthIds = ['t0'], qrels }) {
  return {
    id: 'ev',
    family: 'multi_hop_relation',
    domain: 'companies',
    split: 'eval_hidden',
    queryText: 'q',
    timestamp: Date.now(),
    epochId: 0,
    truthDocuments: truthIds.map((id) => ({ id, text: '', isCurrent: true })),
    negativeDocuments: [],
    hardNegatives: [],
    qrels,
    relations: [],
    embeddings: {
      modelId: 'm', revision: 'r',
      layout: { dim: 8, headerBytes: 9, quantization: 'int8' },
      query: new Uint8Array(12), perTruth: new Map(), perNegative: new Map(),
    },
  };
}

describe('hardnessBucketFor — alias-qrel exclusion', () => {
  test('alias qrels at relevance=1.0 do not flip bucket to hard', () => {
    // Source event has its own truth + a relation-aliased relevance=1.0
    // qrel for some other event's truth. With the fix, maxNeg stays 0
    // → bucket='easy'. Without the fix, maxNeg would be 1.0 → 'hard'.
    const ev = makeEvent({
      truthIds: ['my-truth'],
      qrels: [
        { documentId: 'my-truth', relevance: 1 },        // own truth
        { documentId: 'aliased-target-truth', relevance: 1 }, // repair alias
      ],
    });
    assert.equal(hardnessBucketFor(ev), 'easy');
  });

  test('alias qrels at relevance=0.8 also do not flip bucket', () => {
    const ev = makeEvent({
      truthIds: ['my-truth'],
      qrels: [
        { documentId: 'my-truth', relevance: 1 },
        { documentId: 'graded-alias', relevance: 0.8 },
      ],
    });
    assert.equal(hardnessBucketFor(ev), 'easy');
  });

  test('genuine hard negative at 0.4 still classifies as hard', () => {
    const ev = makeEvent({
      truthIds: ['my-truth'],
      qrels: [
        { documentId: 'my-truth', relevance: 1 },
        { documentId: 'near-collision-distractor', relevance: 0.4 },
      ],
    });
    assert.equal(hardnessBucketFor(ev), 'hard');
  });

  test('medium negative at 0.2 classifies as medium', () => {
    const ev = makeEvent({
      truthIds: ['my-truth'],
      qrels: [
        { documentId: 'my-truth', relevance: 1 },
        { documentId: 'medium-distractor', relevance: 0.2 },
      ],
    });
    assert.equal(hardnessBucketFor(ev), 'medium');
  });

  test('mixed: 0.4 hard negative co-exists with 1.0 alias — still hard', () => {
    // The alias is excluded but the genuine hard negative is honored.
    const ev = makeEvent({
      truthIds: ['my-truth'],
      qrels: [
        { documentId: 'my-truth', relevance: 1 },
        { documentId: 'alias-target', relevance: 1 },
        { documentId: 'true-hard-neg', relevance: 0.4 },
      ],
    });
    assert.equal(hardnessBucketFor(ev), 'hard');
  });

  test('exactly 0.5 boundary — treated as positive (excluded)', () => {
    const ev = makeEvent({
      truthIds: ['my-truth'],
      qrels: [
        { documentId: 'my-truth', relevance: 1 },
        { documentId: 'boundary-alias', relevance: 0.5 },
      ],
    });
    // 0.5 is excluded; no other negatives → bucket='easy'.
    assert.equal(hardnessBucketFor(ev), 'easy');
  });
});
