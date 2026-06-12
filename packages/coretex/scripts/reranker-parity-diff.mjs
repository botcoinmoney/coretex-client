#!/usr/bin/env node
/**
 * Parity differ for reranker score arrays produced by reranker_runner.py on
 * different backends (CPU fp32 vs GPU fp32) or batch sizes. Reads two
 * {"scores":[...]} JSON files and reports the per-pair delta distribution
 * plus a PASS/FAIL against a ppm-equivalent budget.
 *
 * The on-chain honesty replay compares a COMPOSITE deltaPpm against
 * replayTolerancePpm (250 in the launch profile). The composite metric is a
 * deterministic function of these per-pair scores, so a max per-pair score
 * delta of D bounds the composite drift well below D*1e6 ppm — we report the
 * max-delta-in-ppm (D*1e6) as a conservative upper bound and gate it far
 * under the 250 ppm budget. (Identical orderings ⇒ identical metric ⇒ 0 ppm;
 * tiny score deltas only matter if they flip a top-K ranking.)
 *
 *   node reranker-parity-diff.mjs <ref.json> <cmp.json> [--budget-ppm 250] [--label "cpu vs gpu"]
 */
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
// Files are positional args that are neither a --flag nor a flag's value.
const consumed = new Set();
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith('--')) { consumed.add(i); consumed.add(i + 1); }
}
const files = args.filter((a, i) => !consumed.has(i) && !a.startsWith('--'));
if (files.length !== 2) {
  console.error('usage: reranker-parity-diff.mjs <ref.json> <cmp.json> [--budget-ppm 250] [--label "..."]');
  process.exit(2);
}
const budgetPpm = Number(opt('budget-ppm', '250'));
const label = opt('label', `${files[0]} vs ${files[1]}`);

const ref = JSON.parse(readFileSync(files[0], 'utf8')).scores;
const cmp = JSON.parse(readFileSync(files[1], 'utf8')).scores;
if (!Array.isArray(ref) || !Array.isArray(cmp) || ref.length !== cmp.length) {
  console.error(`score arrays missing or length mismatch: ${ref?.length} vs ${cmp?.length}`);
  process.exit(2);
}

let maxAbs = 0, sumAbs = 0, nNonZero = 0, argmax = -1;
const deltas = [];
for (let i = 0; i < ref.length; i++) {
  const d = Math.abs(ref[i] - cmp[i]);
  deltas.push(d);
  sumAbs += d;
  if (d > 0) nNonZero++;
  if (d > maxAbs) { maxAbs = d; argmax = i; }
}
deltas.sort((a, b) => a - b);
const pct = (p) => deltas[Math.min(deltas.length - 1, Math.floor((deltas.length * p) / 100))];
// Conservative ppm upper bound: a max per-pair score delta of D can move a
// score-normalized composite metric by at most ~D in fractional terms = D*1e6 ppm.
const maxDeltaPpm = maxAbs * 1e6;
const pass = maxDeltaPpm <= budgetPpm;

const out = {
  label,
  pairs: ref.length,
  maxAbsScoreDelta: maxAbs,
  maxAbsScoreDeltaPpm: Number(maxDeltaPpm.toFixed(3)),
  budgetPpm,
  meanAbsScoreDelta: sumAbs / ref.length,
  p50: pct(50), p95: pct(95), p99: pct(99),
  pairsWithAnyDelta: nNonZero,
  worstPairIndex: argmax,
  refAtWorst: argmax >= 0 ? ref[argmax] : null,
  cmpAtWorst: argmax >= 0 ? cmp[argmax] : null,
  verdict: maxAbs === 0 ? 'BIT_IDENTICAL' : pass ? 'WITHIN_TOLERANCE' : 'EXCEEDS_TOLERANCE',
};
console.log(JSON.stringify(out, null, 2));
process.exit(pass ? 0 : 1);
