// DACR-LT-Training → CoreTex production-corpus bridge.
//
// The Botcoin coordinator publishes long-term training data to
// https://huggingface.co/datasets/botcoinmoney/dacr-lt-training, which
// is the deterministic export of its S3 dataset/v2/* layout (see
// /root/botcoin-coordinator-live/packages/coordinator/src/dataset-layout.ts +
// export-hf-dataset.ts).  This module reshapes those records into the
// §9 ProductionCorpusEvent retrieval-eval form expected by CoreTex.
//
// Mapping rules — see specs/corpus_bridge_v0.md for the exact contract.

import { createHash } from 'node:crypto';
import type {
  ProductionCorpusEvent,
  ProductionCorpusFamily,
  ProductionCorpusNoveltyBucket,
  ProductionCorpusRegion,
} from '../eval/corpus.js';

export type DacrChallengeDomain =
  | 'companies'
  | 'computational_biology'
  | 'quantum_physics'
  | 'scrna_imputation'
  | string;

/** A single DACR raw-attempt record from `raw_attempts/{domain}/part-*.jsonl`. */
export interface DacrRawAttempt {
  readonly split?: 'train' | 'validation' | 'test';
  readonly challenge_id: string;
  readonly challenge_seed: string;
  readonly challenge_domain: DacrChallengeDomain;
  readonly record_id?: string;
  readonly document?: string;
  readonly questions?: readonly string[];
  readonly constraints?: readonly string[];
  readonly question_metadata?: ReadonlyArray<Record<string, unknown>>;
  readonly trap_metadata?: {
    readonly worldSeed?: string | number;
    readonly traps?: ReadonlyArray<Record<string, unknown>>;
  };
  readonly submitted_answers?: Record<string, { value?: string; expected?: string; correct?: boolean }>;
  readonly answer_verification?: {
    readonly correct?: number;
    readonly total?: number;
    readonly required?: number;
    readonly passed_threshold?: boolean;
    readonly per_question?: Record<string, { submitted?: string; expected?: string; correct?: boolean; answer_type?: string }>;
  };
  readonly pass?: boolean;
  readonly reasoning_depth?: { readonly reasoning_depth_score?: number } | number;
  readonly trace_quality?: { readonly score?: number } | null;
  readonly miner_id?: string;
  readonly timestamp?: string;
}

/** A sequential-pair record from `pairs_sequential/{domain}/part-*.jsonl`. */
export interface DacrSequentialPair {
  readonly split?: 'train' | 'validation' | 'test';
  readonly challenge_id: string;
  readonly challenge_seed: string;
  readonly challenge_domain: DacrChallengeDomain;
  readonly pair_family?: string;
  readonly pair_quality?: { readonly dataset_export_eligible?: boolean; readonly rejection_reasons?: readonly string[] };
  readonly improvement_basis?: readonly string[];
  readonly questions?: readonly string[];
  readonly chosen?: {
    readonly submitted_answers?: Record<string, { value?: string; expected?: string; correct?: boolean }>;
    readonly answer_verification?: { readonly correct?: number; readonly total?: number; readonly per_question?: Record<string, { submitted?: string; expected?: string; correct?: boolean }> };
    readonly pass?: boolean;
  };
  readonly rejected?: {
    readonly submitted_answers?: Record<string, { value?: string; expected?: string; correct?: boolean }>;
    readonly answer_verification?: { readonly correct?: number; readonly total?: number; readonly per_question?: Record<string, { submitted?: string; expected?: string; correct?: boolean }> };
    readonly pass?: boolean;
  };
  readonly trap_metadata?: { readonly traps?: ReadonlyArray<Record<string, unknown>> };
}

export interface DacrBridgeOptions {
  readonly epochCommitted: number;
  readonly defaultDistractors?: number;
  readonly maxDistractors?: number;
}

/** Domain → family routing (heuristic, override per-domain in real production). */
export function routeDacrFamily(domain: DacrChallengeDomain): ProductionCorpusFamily {
  switch (domain) {
    case 'companies':
    case 'quantum_physics':
      return 'near_collision';
    case 'computational_biology':
    case 'scrna_imputation':
      return 'long_horizon';
    default:
      return 'long_horizon';
  }
}

/** Default substrate-region tags per family (matches plan §9 expected_state_regions). */
export function defaultDacrRegions(family: ProductionCorpusFamily): readonly ProductionCorpusRegion[] {
  if (family === 'near_collision') return ['memory_index', 'retrieval_keys'];
  if (family === 'temporal') return ['memory_index', 'temporal'];
  return ['memory_index', 'retrieval_keys'];
}

function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

function noveltyBucketFromHash(hash: string): ProductionCorpusNoveltyBucket {
  const slot = parseInt(hash.slice(0, 4), 16) % 3;
  return slot === 0 ? 'low' : slot === 1 ? 'medium' : 'high';
}

function hardnessSignalFrom(reasoning: DacrRawAttempt['reasoning_depth'], answerCorrectFraction: number): number {
  // Higher reasoning depth + lower correctness fraction = harder.
  let depth = 0.5;
  if (typeof reasoning === 'number') depth = Math.max(0, Math.min(1, reasoning));
  else if (reasoning && typeof reasoning === 'object' && typeof reasoning.reasoning_depth_score === 'number') {
    depth = Math.max(0, Math.min(1, reasoning.reasoning_depth_score));
  }
  const difficulty = 1 - Math.max(0, Math.min(1, answerCorrectFraction));
  return Math.max(0, Math.min(1, 0.6 * depth + 0.4 * difficulty));
}

function questionIndex(qKey: string): number {
  const m = qKey.match(/q0*(\d+)/i);
  if (!m) return 0;
  return Math.max(1, parseInt(m[1] ?? '1', 10)) - 1;
}

/** Pick distractors from the trap_metadata.traps and the cohort of *other* miners' answers. */
function pickDistractors(
  rec: { trap_metadata?: DacrRawAttempt['trap_metadata']; submitted_answers?: DacrRawAttempt['submitted_answers'] },
  qKey: string,
  truthValue: string,
  maxDistractors: number,
): string[] {
  const out = new Set<string>();
  const traps = rec.trap_metadata?.traps ?? [];
  for (const trap of traps) {
    const t = trap as Record<string, unknown>;
    for (const candidate of [t['wrong_value'], t['decoy'], t['decoy_value'], t['lure'], t['lure_value'], t['path_a_derived'], t['path_b_derived']]) {
      const stringified = candidate == null ? '' : String(candidate).trim();
      if (stringified && stringified !== truthValue) out.add(stringified);
      if (out.size >= maxDistractors) break;
    }
    if (out.size >= maxDistractors) break;
  }
  // Also include the "submitted but wrong" value for this question if any.
  const sub = rec.submitted_answers?.[qKey];
  if (sub && typeof sub.value === 'string' && sub.value !== truthValue && sub.correct === false) {
    out.add(sub.value);
  }
  return [...out].slice(0, maxDistractors);
}

/** Bridge a passing DACR raw-attempt to one or more §9 corpus events (one per correct question). */
export function bridgeDacrAttempt(record: DacrRawAttempt, opts: DacrBridgeOptions): ProductionCorpusEvent[] {
  if (record.pass !== true) return [];
  const verification = record.answer_verification?.per_question ?? {};
  const submitted = record.submitted_answers ?? {};
  const events: ProductionCorpusEvent[] = [];
  const family = routeDacrFamily(record.challenge_domain);
  const regions = defaultDacrRegions(family);
  const ansCount = record.answer_verification?.correct ?? 0;
  const ansTotal = record.answer_verification?.total ?? 1;
  const correctness = ansTotal > 0 ? ansCount / ansTotal : 0;
  const seedHash = sha256Hex(`${record.challenge_seed}:${record.challenge_domain}`);
  const novelty = noveltyBucketFromHash(seedHash);
  const hardness = hardnessSignalFrom(record.reasoning_depth, correctness);

  for (const [qKey, ver] of Object.entries(verification)) {
    if (ver?.correct !== true) continue;
    const expected = ver.expected ?? submitted[qKey]?.expected;
    if (typeof expected !== 'string' || expected.length === 0) continue;
    const qIdx = questionIndex(qKey);
    const queryText = (record.questions ?? [])[qIdx];
    if (typeof queryText !== 'string' || queryText.length === 0) continue;
    const distractors = pickDistractors(record, qKey, expected, opts.maxDistractors ?? 5);
    const id = `dacr-${record.challenge_id.slice(2, 14)}-${qKey}`;
    events.push({
      id,
      family,
      taskType: `${record.challenge_domain}:${qKey}`,
      isProtected: false,
      epochCommitted: opts.epochCommitted,
      sourceRef: `dacr-lt-training:${record.challenge_domain}/${record.challenge_id}`,
      queryText,
      truthText: expected,
      isStaleTruth: false,
      relevant: true,
      distractors,
      relations: [],
      expectedStateRegions: regions,
      validFromEpoch: opts.epochCommitted,
      expiresAtEpoch: 0,
      noveltyBucket: novelty,
      hardnessSignal: hardness,
    });
  }
  return events;
}

/** Bridge a sequential pair (chosen vs rejected) into temporal corpus events: chosen=current, rejected=stale. */
export function bridgeDacrSequentialPair(pair: DacrSequentialPair, opts: DacrBridgeOptions): ProductionCorpusEvent[] {
  if (pair.pair_quality?.dataset_export_eligible !== true) return [];
  if (!pair.chosen || !pair.rejected) return [];
  const chosenVer = pair.chosen.answer_verification?.per_question ?? {};
  const rejectedVer = pair.rejected.answer_verification?.per_question ?? {};
  const chosenAns = pair.chosen.submitted_answers ?? {};
  const rejectedAns = pair.rejected.submitted_answers ?? {};
  const events: ProductionCorpusEvent[] = [];
  const seedHash = sha256Hex(`${pair.challenge_seed}:${pair.challenge_domain}`);
  const novelty = noveltyBucketFromHash(seedHash);
  const baseRegions: readonly ProductionCorpusRegion[] = ['memory_index', 'temporal'];

  for (const [qKey, ver] of Object.entries(chosenVer)) {
    if (ver?.correct !== true) continue;
    const correctValue = ver.expected ?? chosenAns[qKey]?.expected;
    if (typeof correctValue !== 'string' || correctValue.length === 0) continue;
    const wrongValue = rejectedVer[qKey]?.submitted ?? rejectedAns[qKey]?.value;
    if (typeof wrongValue !== 'string' || wrongValue.length === 0 || wrongValue === correctValue) continue;
    const qIdx = questionIndex(qKey);
    const queryText = (pair.questions ?? [])[qIdx];
    if (typeof queryText !== 'string' || queryText.length === 0) continue;

    // current truth (chosen)
    events.push({
      id: `dacr-pair-${pair.challenge_id.slice(2, 14)}-${qKey}-current`,
      family: 'temporal',
      taskType: `${pair.challenge_domain}:${qKey}:current`,
      isProtected: false,
      epochCommitted: opts.epochCommitted,
      sourceRef: `dacr-lt-training:pairs_sequential/${pair.challenge_domain}/${pair.challenge_id}`,
      queryText,
      truthText: correctValue,
      isStaleTruth: false,
      relevant: true,
      distractors: [wrongValue],
      relations: [`supersedes:dacr-pair-${pair.challenge_id.slice(2, 14)}-${qKey}-stale`],
      expectedStateRegions: baseRegions,
      validFromEpoch: opts.epochCommitted,
      expiresAtEpoch: 0,
      noveltyBucket: novelty,
      hardnessSignal: 0.7,
    });
    // stale truth (rejected)
    events.push({
      id: `dacr-pair-${pair.challenge_id.slice(2, 14)}-${qKey}-stale`,
      family: 'temporal',
      taskType: `${pair.challenge_domain}:${qKey}:stale`,
      isProtected: false,
      epochCommitted: opts.epochCommitted,
      sourceRef: `dacr-lt-training:pairs_sequential/${pair.challenge_domain}/${pair.challenge_id}`,
      queryText,
      truthText: wrongValue,
      isStaleTruth: true,
      relevant: true,
      distractors: [correctValue],
      relations: [`superseded_by:dacr-pair-${pair.challenge_id.slice(2, 14)}-${qKey}-current`],
      expectedStateRegions: baseRegions,
      validFromEpoch: opts.epochCommitted,
      expiresAtEpoch: opts.epochCommitted,
      noveltyBucket: novelty,
      hardnessSignal: 0.6,
    });
  }
  return events;
}

/** Bridge a batch of records (mixed attempts + pairs) honoring opts. */
export function bridgeDacrBatch(
  attempts: ReadonlyArray<DacrRawAttempt>,
  pairs: ReadonlyArray<DacrSequentialPair>,
  opts: DacrBridgeOptions,
): ProductionCorpusEvent[] {
  const out: ProductionCorpusEvent[] = [];
  for (const att of attempts) out.push(...bridgeDacrAttempt(att, opts));
  for (const pair of pairs) out.push(...bridgeDacrSequentialPair(pair, opts));
  return out;
}
