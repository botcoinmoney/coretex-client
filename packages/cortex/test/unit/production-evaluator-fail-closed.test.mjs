/**
 * §2 score-honesty: fail-closed production evaluator construction + boot
 * attestation.
 *
 * A coordinator booted bare (no CORTEX_REAL_EVAL / CORETEX_RERANKER /
 * CORETEX_RERANKER_PRODUCTION) must REFUSE to construct the production
 * evaluator — it must never sign receipts off the deterministic hash stub.
 * The deterministic reranker is unreachable from
 * `createProductionCoreTexEvaluator` for EVERY env combination.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  assertBundleBindingAtStartup,
  buildBundleManifest,
  buildCoordinatorBootAttestation,
  bgeM3DenseManifest,
  computeCoordinatorBootAttestationHash,
  createInMemoryDedupStore,
  createProductionCoreTexEvaluator,
  memRerankerManifest,
  qwen3Reranker06BManifest,
  qwenRerankerPromptTemplateHash,
  resolveProductionRerankerPlan,
  QWEN_RERANKER_DEFAULT_INSTRUCTION,
} from '../../dist/index.js';

const repoRoot = fileURLToPath(new URL('../../../..', import.meta.url));

const PIN = { modelId: 'Qwen/Qwen3-Reranker-0.6B', revision: 'e61197ed45024b0ed8a2d74b80b4d909f1255473' };

/** Fully-armed production env. Tests subtract one variable at a time. */
function productionEnv(over = {}) {
  return {
    CORTEX_REAL_EVAL: '1',
    CORETEX_RERANKER_PRODUCTION: '1',
    CORETEX_RERANKER: 'qwen3',
    ...over,
  };
}

function makeManifest() {
  return buildBundleManifest({
    repoRoot,
    corpusRoot: '0x' + '11'.repeat(32),
    corpusFiles: [],
    biEncoder: bgeM3DenseManifest({
      revision: '0123456789abcdef0123456789abcdef01234567',
      files: [{ path: 'model.safetensors', sha256: 'a'.repeat(64), bytes: 1 }],
    }),
    reranker: qwen3Reranker06BManifest({
      revision: PIN.revision,
      files: [{ path: 'model.safetensors', sha256: 'b'.repeat(64), bytes: 1 }],
    }),
    labelingReranker: memRerankerManifest({
      modelId: 'memreranker/4B',
      revision: 'cafebabedeadbeefcafebabedeadbeefcafebabe',
      files: [{ path: 'model.safetensors', sha256: 'c'.repeat(64), bytes: 1 }],
    }),
  });
}

function writeManifestFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'coretex-prod-eval-'));
  const path = join(dir, 'bundle.json');
  writeFileSync(path, JSON.stringify(makeManifest()));
  return path;
}

/** Run createProductionCoreTexEvaluator under a controlled process.env. */
async function constructWithEnv(env, optionsOver = {}) {
  const controlled = [
    'CORTEX_REAL_EVAL', 'CORETEX_RERANKER_PRODUCTION', 'CORETEX_RERANKER',
    'CORETEX_ALLOW_DETERMINISTIC_RERANKER', 'CORETEX_RERANKER_MODEL_ID',
    'CORETEX_RERANKER_REVISION', 'CORETEX_RERANKER_MODE', 'CORETEX_RERANKER_INSTRUCTION',
  ];
  const saved = new Map(controlled.map((k) => [k, process.env[k]]));
  for (const k of controlled) delete process.env[k];
  for (const [k, v] of Object.entries(env)) {
    if (v !== undefined) process.env[k] = v;   // process.env coerces undefined to 'undefined'
  }
  try {
    return await createProductionCoreTexEvaluator({
      epochId: 7,
      epochSecret: `0x${'01'.repeat(32)}`,
      corpusPath: '/nonexistent/corpus.json',
      bundleManifestPath: writeManifestFixture(),
      parentStateLoader: () => { throw new Error('unused'); },
      dedupStore: createInMemoryDedupStore(),
      perMinerCap: 5,
      ...optionsOver,
    });
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

describe('resolveProductionRerankerPlan — fail-closed env contract', () => {
  test('fully-armed env resolves the bundle pin (never the deterministic stub)', () => {
    const plan = resolveProductionRerankerPlan(PIN, productionEnv());
    assert.equal(plan.modelId, PIN.modelId);
    assert.equal(plan.revision, PIN.revision);
    assert.equal(plan.mode, 'qwen3-per-batch');
    assert.equal(plan.instruction, QWEN_RERANKER_DEFAULT_INSTRUCTION);
    const streaming = resolveProductionRerankerPlan(PIN, productionEnv({ CORETEX_RERANKER_MODE: 'streaming' }));
    assert.equal(streaming.mode, 'qwen3-streaming');
  });

  test('each missing env var fails construction with a clear error', () => {
    for (const missing of ['CORTEX_REAL_EVAL', 'CORETEX_RERANKER_PRODUCTION', 'CORETEX_RERANKER']) {
      const env = productionEnv();
      delete env[missing];
      assert.throws(
        () => resolveProductionRerankerPlan(PIN, env),
        new RegExp(missing),
        `unset ${missing} must refuse construction`,
      );
    }
  });

  test('there is NO env combination that yields a deterministic reranker', () => {
    // Every selector other than qwen3 — including the deterministic stub and
    // its CI escape hatch — is a construction error, not a fallback.
    for (const selector of ['deterministic', 'minilm', 'qwen2', '']) {
      assert.throws(
        () => resolveProductionRerankerPlan(PIN, productionEnv({ CORETEX_RERANKER: selector })),
        /CORETEX_RERANKER=qwen3 is required/,
      );
    }
    assert.throws(
      () => resolveProductionRerankerPlan(PIN, productionEnv({
        CORETEX_RERANKER: 'deterministic',
        CORETEX_ALLOW_DETERMINISTIC_RERANKER: '1',
      })),
      /CORETEX_RERANKER=qwen3 is required/,
    );
    assert.throws(
      () => resolveProductionRerankerPlan(PIN, productionEnv({ CORETEX_ALLOW_DETERMINISTIC_RERANKER: '1' })),
      /CORETEX_ALLOW_DETERMINISTIC_RERANKER/,
    );
  });

  test('env model/revision overrides that conflict with the bundle pin are refused', () => {
    assert.throws(
      () => resolveProductionRerankerPlan(PIN, productionEnv({ CORETEX_RERANKER_MODEL_ID: 'other/model' })),
      /conflicts with bundle reranker pin/,
    );
    assert.throws(
      () => resolveProductionRerankerPlan(PIN, productionEnv({ CORETEX_RERANKER_REVISION: 'deadbeef' })),
      /conflicts with bundle reranker pin/,
    );
    // Matching overrides are fine (idempotent restatement of the pin).
    assert.doesNotThrow(() => resolveProductionRerankerPlan(PIN, productionEnv({
      CORETEX_RERANKER_MODEL_ID: PIN.modelId,
      CORETEX_RERANKER_REVISION: PIN.revision,
    })));
  });

  test('missing bundle pin is a construction error', () => {
    assert.throws(() => resolveProductionRerankerPlan({ modelId: '', revision: '' }, productionEnv()), /bundle reranker pin/);
  });
});

describe('createProductionCoreTexEvaluator — fail-closed construction', () => {
  test('bare boot (no env) refuses before any corpus/model load', async () => {
    await assert.rejects(constructWithEnv({}), /CORTEX_REAL_EVAL=1 is required/);
  });

  test('each production env var is individually required', async () => {
    await assert.rejects(constructWithEnv(productionEnv({ CORTEX_REAL_EVAL: undefined })), /CORTEX_REAL_EVAL/);
    await assert.rejects(constructWithEnv(productionEnv({ CORETEX_RERANKER_PRODUCTION: undefined })), /CORETEX_RERANKER_PRODUCTION/);
    await assert.rejects(constructWithEnv(productionEnv({ CORETEX_RERANKER: undefined })), /CORETEX_RERANKER=qwen3 is required/);
  });

  test('deterministic selector can never construct, even with the test escape hatch', async () => {
    await assert.rejects(
      constructWithEnv(productionEnv({ CORETEX_RERANKER: 'deterministic', CORETEX_ALLOW_DETERMINISTIC_RERANKER: '1' })),
      /CORETEX_RERANKER=qwen3 is required/,
    );
  });

  test('perMinerCap is required and must be finite', async () => {
    await assert.rejects(constructWithEnv(productionEnv(), { perMinerCap: undefined }), /perMinerCap/);
    await assert.rejects(constructWithEnv(productionEnv(), { perMinerCap: Number.MAX_SAFE_INTEGER }), /perMinerCap/);
    await assert.rejects(constructWithEnv(productionEnv(), { perMinerCap: 0 }), /perMinerCap/);
  });

  test('dedup store is required (no in-memory default in production)', async () => {
    await assert.rejects(constructWithEnv(productionEnv(), { dedupStore: undefined }), /CoreTexEvalDedupStore/);
  });
});

describe('coordinator boot attestation', () => {
  function attestationFields(manifest) {
    return {
      bundleHash: manifest.bundleHash,
      rerankerModelId: PIN.modelId,
      rerankerRevision: PIN.revision,
      rerankerMode: 'qwen3-streaming',
      rerankerInstruction: QWEN_RERANKER_DEFAULT_INSTRUCTION,
      promptTemplateHash: qwenRerankerPromptTemplateHash(QWEN_RERANKER_DEFAULT_INSTRUCTION),
      memoryIRMode: 'off',
    };
  }

  test('buildCoordinatorBootAttestation hash-binds every field', () => {
    const manifest = makeManifest();
    const att = buildCoordinatorBootAttestation(attestationFields(manifest));
    assert.match(att.attestationHash, /^0x[0-9a-f]{64}$/);
    assert.equal(att.attestationHash, computeCoordinatorBootAttestationHash(att));
    // Any field tamper changes the hash.
    assert.notEqual(
      computeCoordinatorBootAttestationHash({ ...att, rerankerInstruction: 'tampered' }),
      att.attestationHash,
    );
    assert.notEqual(
      computeCoordinatorBootAttestationHash({ ...att, memoryIRMode: 'full' }),
      att.attestationHash,
    );
  });

  test('assertBundleBindingAtStartup accepts a matching attestation and refuses drift', () => {
    const manifest = makeManifest();
    const runtime = {
      torch: '2.6.0',
      transformers: '4.55.1',
      huggingface_hub: '0.36.2',
      tokenizers: '0.21.4',
    };
    const att = buildCoordinatorBootAttestation(attestationFields(manifest));
    assert.doesNotThrow(() => assertBundleBindingAtStartup({
      manifest,
      onChainCoreVersionHash: manifest.bundleHash,
      installedRuntimeVersions: runtime,
      bootAttestation: att,
    }));
    assert.throws(() => assertBundleBindingAtStartup({
      manifest,
      onChainCoreVersionHash: manifest.bundleHash,
      installedRuntimeVersions: runtime,
      bootAttestation: { ...att, rerankerRevision: 'deadbeef' },
    }), /does not bind|!= bundle pin/);
    const wrongModel = buildCoordinatorBootAttestation({ ...attestationFields(manifest), rerankerModelId: 'other/model' });
    assert.throws(() => assertBundleBindingAtStartup({
      manifest,
      onChainCoreVersionHash: manifest.bundleHash,
      installedRuntimeVersions: runtime,
      bootAttestation: wrongModel,
    }), /!= bundle pin/);
    const wrongBundle = buildCoordinatorBootAttestation({ ...attestationFields(manifest), bundleHash: `0x${'99'.repeat(32)}` });
    assert.throws(() => assertBundleBindingAtStartup({
      manifest,
      onChainCoreVersionHash: manifest.bundleHash,
      installedRuntimeVersions: runtime,
      bootAttestation: wrongBundle,
    }), /bundleHash/);
  });

  test('attestation field validation is fail-closed', () => {
    const manifest = makeManifest();
    assert.throws(() => buildCoordinatorBootAttestation({ ...attestationFields(manifest), promptTemplateHash: '0x12' }), /bytes32/);
    assert.throws(() => buildCoordinatorBootAttestation({ ...attestationFields(manifest), rerankerMode: 'deterministic' }), /rerankerMode/);
    assert.throws(() => buildCoordinatorBootAttestation({ ...attestationFields(manifest), memoryIRMode: 'F2' }), /memoryIRMode/);
    assert.throws(() => buildCoordinatorBootAttestation({ ...attestationFields(manifest), rerankerModelId: '' }), /rerankerModelId/);
  });
});
