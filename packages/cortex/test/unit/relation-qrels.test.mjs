import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  addRelationAnswerAliasQrels,
  canonicalAnswerText,
} from '../../dist/index.js';

describe('relation answer alias qrels', () => {
  test('canonicalAnswerText lowercases and normalizes whitespace only', () => {
    assert.equal(
      canonicalAnswerText(' Company A:   Revenue is $5M. '),
      canonicalAnswerText('company a: revenue is $5m.'),
    );
    assert.notEqual(
      canonicalAnswerText('Company A: Revenue is $5M.'),
      canonicalAnswerText('Company B: Revenue is $5M.'),
    );
  });

  test('adds full-credit target truth qrel for multi-hop answer entity aliases', () => {
    const queryTruth = {
      id: 'question_X::truth',
      text: 'Company A: Revenue is $5M.',
      isCurrent: true,
    };
    const targetTruth = {
      id: 'entity_Y::truth',
      text: ' company a: revenue is $5m. ',
      isCurrent: true,
    };
    const baseQrels = [
      { documentId: queryTruth.id, relevance: 1 },
      { documentId: 'question_X::neg0', relevance: 0.4 },
    ];

    const result = addRelationAnswerAliasQrels(baseQrels, {
      family: 'multi_hop_relation',
      truthDocuments: [queryTruth],
      relations: [{ other_id: 'entity_Y', edgeType: 'derived_from' }],
      relationTruthDocumentsByEventId: new Map([['entity_Y', [targetTruth]]]),
    });

    assert.equal(result.qrels.find((q) => q.documentId === queryTruth.id)?.relevance, 1);
    assert.equal(result.qrels.find((q) => q.documentId === targetTruth.id)?.relevance, 1);
    assert.equal(result.stats.added, 1);
    assert.equal(result.stats.fullCredit, 1);

    const deduped = addRelationAnswerAliasQrels(result.qrels, {
      family: 'multi_hop_relation',
      truthDocuments: [queryTruth],
      relations: [{ other_id: 'entity_Y', edgeType: 'derived_from' }],
      relationTruthDocumentsByEventId: new Map([['entity_Y', [targetTruth]]]),
    });
    assert.equal(deduped.qrels.filter((q) => q.documentId === targetTruth.id).length, 1);
  });

  test('does not add aliases outside multi-hop relation records', () => {
    const result = addRelationAnswerAliasQrels([], {
      family: 'near_collision',
      truthDocuments: [{ id: 'event::truth', text: 'Answer text', isCurrent: true }],
      relations: [{ other_id: 'entity_Y', edgeType: 'derived_from' }],
      relationTruthDocumentsByEventId: new Map([[
        'entity_Y',
        [{ id: 'entity_Y::truth', text: 'Answer text', isCurrent: true }],
      ]]),
    });

    assert.equal(result.qrels.length, 0);
    assert.equal(result.stats.added, 0);
  });
});
