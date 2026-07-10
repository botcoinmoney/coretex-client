import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { checkScorerJobPins } from '../../dist/scorer-server-cli.js';
import {
  CORETEX_PIPELINE_VERSION_BMU_V1,
  CORETEX_PIPELINE_VERSION_BMU_V2,
  CORETEX_PIPELINE_VERSIONS_SUPPORTED,
  isBmuScoringLaw,
  isBmuV2ScoringLaw,
  isR5StateLaw,
  bmuExclusionKeysForEvent,
} from '../../dist/index.js';

const B32 = (b) => `0x${b.repeat(32)}`;
const basePins = {
  modelId: 'm', revision: 'r', promptTemplateHash: B32('aa'),
  bundleHash: B32('bb'), corpusRoot: B32('cc'), coreVersionHash: B32('bb'),
};
const baseJob = {
  corpusRoot: basePins.corpusRoot,
  bundleHash: basePins.bundleHash,
  coreVersionHash: basePins.coreVersionHash,
  expectedScorerPins: {
    modelId: basePins.modelId, revision: basePins.revision,
    promptTemplateHash: basePins.promptTemplateHash,
    bundleHash: basePins.bundleHash, corpusRoot: basePins.corpusRoot,
  },
};

describe('BMU v2 client wire law', () => {
  test('v2 is a supported BMU scoring law over the historical r5 state law', () => {
    assert.equal(CORETEX_PIPELINE_VERSIONS_SUPPORTED.has(CORETEX_PIPELINE_VERSION_BMU_V2), true);
    assert.equal(isBmuScoringLaw(CORETEX_PIPELINE_VERSION_BMU_V1), true);
    assert.equal(isBmuScoringLaw(CORETEX_PIPELINE_VERSION_BMU_V2), true);
    assert.equal(isBmuV2ScoringLaw(CORETEX_PIPELINE_VERSION_BMU_V1), false);
    assert.equal(isBmuV2ScoringLaw(CORETEX_PIPELINE_VERSION_BMU_V2), true);
    assert.equal(isR5StateLaw(CORETEX_PIPELINE_VERSION_BMU_V1), true);
    assert.equal(isR5StateLaw(CORETEX_PIPELINE_VERSION_BMU_V2), true);
  });

  test('scorer law pin is exact and fail-closed in both directions', () => {
    const versionedPins = { ...basePins, scoringPipelineVersion: CORETEX_PIPELINE_VERSION_BMU_V2 };
    assert.equal(checkScorerJobPins({ ...baseJob, scoringPipelineVersion: CORETEX_PIPELINE_VERSION_BMU_V2 }, versionedPins), null);
    assert.match(checkScorerJobPins(baseJob, versionedPins), /absent.*loaded/);
    assert.match(
      checkScorerJobPins({ ...baseJob, scoringPipelineVersion: CORETEX_PIPELINE_VERSION_BMU_V1 }, versionedPins),
      /scoringPipelineVersion/,
    );
    assert.match(
      checkScorerJobPins({ ...baseJob, scoringPipelineVersion: CORETEX_PIPELINE_VERSION_BMU_V2 }, basePins),
      /unversioned bundle/,
    );
  });

  test('confirm exclusion carries canonical identity and alias keys', () => {
    const keys = bmuExclusionKeysForEvent({
      id: 'row', subjectEntityId: 'subject-1',
      bmuTask: {
        family: 'temporal', budgetB: 1,
        requiredEvidence: ['doc'], forbiddenEvidence: [], answer: { id: 'doc' },
        motifGroupId: 'motif-1', templateId: 'template-1',
        entityHoldoutKeys: ['id:subject-1', 'alias:alice'],
      },
    });
    assert.deepEqual(keys, [
      'motif:motif-1', 'subject:subject-1', 'template:template-1',
      'entity:id:subject-1', 'entity:alias:alice',
    ]);
  });
});
