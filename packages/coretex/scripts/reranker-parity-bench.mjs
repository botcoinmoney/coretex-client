#!/usr/bin/env node
/**
 * Parity + benchmark harness for the reranker last-token-projection
 * optimization. Scores a fixed set of (query, document) pairs TWICE through
 * the real Qwen model — once via the legacy full-logits path
 * (CORETEX_RERANKER_FULL_LOGITS=1) and once via the default last-token path —
 * and asserts the scores are numerically identical (max abs delta below a
 * tiny epsilon, far inside any replay tolerance), while reporting the wall
 * time of each so the speedup is measured, not guessed.
 *
 * This is a heavy, on-demand harness (loads the ~0.6B model twice); it is NOT
 * part of the fast unit suite. Requires python3 + torch + transformers + the
 * cached Qwen3-Reranker-0.6B weights. Skips with a loud message otherwise.
 *
 *   node packages/coretex/scripts/reranker-parity-bench.mjs [pairCount]
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { cpus } from 'node:os';

const PYTHON = process.env.CORETEX_RERANKER_PYTHON ?? 'python3';

const here = dirname(fileURLToPath(import.meta.url));
const runner = resolve(here, 'reranker_runner.py');
const MODEL = 'Qwen/Qwen3-Reranker-0.6B';
const REVISION = 'e61197ed45024b0ed8a2d74b80b4d909f1255473';
const EPS = 1e-6; // score is sigmoid(yes-no); 1e-6 here is ~1ppm, well inside replay tolerance.
const pairCount = Number(process.argv[2] ?? '96');

// Deterministic, varied-length synthetic pairs (no network, no corpus dep).
const TOPICS = ['ledger reconciliation', 'epoch rotation', 'staking tiers', 'merkle root', 'reranker latency', 'corpus delta', 'frontier churn', 'abstention policy'];
function makePairs(n) {
  const pairs = [];
  for (let i = 0; i < n; i++) {
    const t = TOPICS[i % TOPICS.length];
    const reps = 1 + (i % 7); // vary document length to exercise padding/last-idx logic
    pairs.push({
      query: `What is the role of ${t} in the CoreTex protocol at index ${i}?`,
      document: `The ${t} subsystem coordinates state. `.repeat(reps) + `Record ${i} describes how ${t} interacts with the substrate and the epoch clock.`,
    });
  }
  return pairs;
}

function runOnce(pairs, fullLogits) {
  const env = {
    ...process.env,
    CUDA_VISIBLE_DEVICES: '',
    RERANKER_NUM_THREADS: process.env.RERANKER_NUM_THREADS ?? String(Math.max(1, cpus().length || 8)),
    ...(fullLogits ? { CORETEX_RERANKER_FULL_LOGITS: '1' } : {}),
    CORETEX_RERANKER_TELEMETRY: '1',
  };
  const t0 = Date.now();
  const res = spawnSync(PYTHON, [runner], {
    input: JSON.stringify({ model: MODEL, revision: REVISION, pairs }),
    env,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const ms = Date.now() - t0;
  if (res.status !== 0) {
    return { ok: false, stderr: (res.stderr || '').slice(-2000), ms };
  }
  const line = res.stdout.trim().split('\n').filter(Boolean).pop();
  const scores = JSON.parse(line).scores;
  const telem = (res.stderr || '').split('\n').filter((l) => l.includes('"telemetry"')).pop();
  return { ok: true, scores, ms, telemetry: telem ? JSON.parse(telem).telemetry : null };
}

const pairs = makePairs(pairCount);
console.log(`[parity-bench] scoring ${pairs.length} pairs through ${MODEL} twice (full-logits vs last-token)...`);

const full = runOnce(pairs, true);
if (!full.ok) {
  console.error(`[parity-bench] SKIP: model/runtime unavailable.\n${full.stderr}`);
  process.exit(2);
}
const fast = runOnce(pairs, false);
if (!fast.ok) {
  console.error(`[parity-bench] FAIL: last-token path errored.\n${fast.stderr}`);
  process.exit(1);
}

let maxDelta = 0;
for (let i = 0; i < pairs.length; i++) {
  maxDelta = Math.max(maxDelta, Math.abs(full.scores[i] - fast.scores[i]));
}
const speedup = full.ms / fast.ms;
console.log(JSON.stringify({
  pairs: pairs.length,
  maxScoreDelta: maxDelta,
  identicalWithinEps: maxDelta <= EPS,
  fullLogitsMs: full.ms,
  lastTokenMs: fast.ms,
  speedup: Number(speedup.toFixed(3)),
  fullLogitsTelemetry: full.telemetry,
  lastTokenTelemetry: fast.telemetry,
}, null, 2));

if (maxDelta > EPS) {
  console.error(`[parity-bench] FAIL: max score delta ${maxDelta} exceeds eps ${EPS}`);
  process.exit(1);
}
console.log(`[parity-bench] PASS: scores identical within ${EPS}; last-token path ${speedup.toFixed(2)}x faster.`);
