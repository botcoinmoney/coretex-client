/**
 * Golden TS↔Python parity for the canonical Qwen reranker prompt template
 * (§2 score-honesty / prompt unification).
 *
 * packages/cortex/scripts/reranker_runner.py is the CANONICAL template (every
 * calibration baseline was derived through it; the repo-root
 * scripts/reranker_runner.py is a forwarding shim).
 * eval/reranker.ts:renderQwenRerankerPrompt must build the byte-identical
 * string. This test spawns the canonical runner with --print-prompt-template
 * (stdlib-only, no torch) and asserts byte equality. It SKIPS — loudly — ONLY
 * when python3 is genuinely unavailable on the host.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  QWEN_RERANKER_DEFAULT_INSTRUCTION,
  QWEN_RERANKER_PROMPT_PROBE,
  qwenRerankerPromptTemplateHash,
  renderQwenRerankerPrompt,
  resolveQwenRerankerInstruction,
  resolveRerankerScriptPath,
} from '../../dist/index.js';

// Resolve through the SAME package-root resolver production uses (B-fix):
// the canonical runner ships inside the package at scripts/reranker_runner.py.
const RUNNER = resolveRerankerScriptPath({});
assert.equal(
  RUNNER,
  fileURLToPath(new URL('../../scripts/reranker_runner.py', import.meta.url)),
  'package-root resolver must point at the in-package canonical runner',
);

function python3Available() {
  const probe = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  return !probe.error && probe.status === 0;
}

function renderViaPython(extraEnv = {}) {
  const res = spawnSync('python3', [RUNNER, '--print-prompt-template'], {
    encoding: 'utf8',
    env: { ...process.env, ...extraEnv },
  });
  assert.equal(res.status, 0, `runner exited ${res.status}: ${res.stderr}`);
  return JSON.parse(res.stdout);
}

const HAVE_PYTHON = python3Available();
if (!HAVE_PYTHON) {
  // eslint-disable-next-line no-console
  console.error(
    '\n!!! qwen-prompt-template-golden: python3 is NOT available on this host — '
    + 'the TS↔Python prompt-template byte-parity golden test is being SKIPPED. '
    + 'The canonical template CANNOT be attested as unified on this machine. !!!\n',
  );
}

describe('canonical Qwen reranker prompt template (TS↔Python golden parity)', () => {
  test('TS rendering == Python rendering byte-for-byte (default instruction)', { skip: !HAVE_PYTHON && 'python3 unavailable' }, () => {
    const py = renderViaPython();
    assert.equal(py.probeQuery, QWEN_RERANKER_PROMPT_PROBE.query, 'probe query constant drifted between languages');
    assert.equal(py.probeDocument, QWEN_RERANKER_PROMPT_PROBE.document, 'probe document constant drifted between languages');
    assert.equal(py.instruction, QWEN_RERANKER_DEFAULT_INSTRUCTION, 'default instruction constant drifted between languages');
    const ts = renderQwenRerankerPrompt(
      QWEN_RERANKER_PROMPT_PROBE.query,
      QWEN_RERANKER_PROMPT_PROBE.document,
      QWEN_RERANKER_DEFAULT_INSTRUCTION,
    );
    assert.equal(ts, py.prompt, 'TS prompt rendering is NOT byte-identical to the canonical Python template');
  });

  test('CORETEX_RERANKER_INSTRUCTION override renders identically in both languages', { skip: !HAVE_PYTHON && 'python3 unavailable' }, () => {
    const instruction = 'Pinned launch instruction: judge memory retrieval relevance';
    const py = renderViaPython({ CORETEX_RERANKER_INSTRUCTION: instruction });
    assert.equal(py.instruction, instruction);
    const ts = renderQwenRerankerPrompt(
      QWEN_RERANKER_PROMPT_PROBE.query,
      QWEN_RERANKER_PROMPT_PROBE.document,
      instruction,
    );
    assert.equal(ts, py.prompt);
  });

  test('canonical template carries the model-card structure (<Instruct>/<Query>/<Document>, <think> block)', () => {
    const prompt = renderQwenRerankerPrompt('q', 'd', 'i');
    assert.ok(prompt.includes('Judge whether the Document meets the requirements based on the Query and the Instruct provided.'));
    assert.ok(prompt.includes('<Instruct>: i\n<Query>: q\n<Document>: d'));
    assert.ok(prompt.endsWith('<|im_start|>assistant\n<think>\n\n</think>\n\n'));
  });

  test('resolveQwenRerankerInstruction pins the env var with the canonical default', () => {
    assert.equal(resolveQwenRerankerInstruction({}), QWEN_RERANKER_DEFAULT_INSTRUCTION);
    assert.equal(resolveQwenRerankerInstruction({ CORETEX_RERANKER_INSTRUCTION: 'x' }), 'x');
  });

  test('prompt-template hash is bytes32 and commits to the instruction', () => {
    const a = qwenRerankerPromptTemplateHash(QWEN_RERANKER_DEFAULT_INSTRUCTION);
    const b = qwenRerankerPromptTemplateHash('a different instruction');
    assert.match(a, /^0x[0-9a-f]{64}$/);
    assert.match(b, /^0x[0-9a-f]{64}$/);
    assert.notEqual(a, b);
    // Deterministic: same instruction → same commitment.
    assert.equal(a, qwenRerankerPromptTemplateHash(QWEN_RERANKER_DEFAULT_INSTRUCTION));
  });
});
