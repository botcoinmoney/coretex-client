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

export interface DacrBookendPair extends DacrSequentialPair {
  readonly pair_type?: 'bookend' | string;
  readonly document?: string;
  readonly question_metadata?: ReadonlyArray<Record<string, unknown>>;
  readonly miner_id?: string;
}

export interface DacrSessionTrajectory {
  readonly split?: 'train' | 'validation' | 'test';
  readonly challenge_id: string;
  readonly challenge_seed: string;
  readonly challenge_domain: DacrChallengeDomain;
  readonly questions?: readonly string[];
  readonly question_metadata?: ReadonlyArray<Record<string, unknown>>;
  readonly trap_metadata?: DacrRawAttempt['trap_metadata'];
  readonly session?: {
    readonly miner_id?: string;
    readonly nonce?: string | number;
    readonly attempts_total?: number;
    readonly final_status?: string;
    readonly final_outcome?: string;
    readonly final_acceptance_path?: string;
    readonly pass_record_id?: string;
  };
  readonly session_annotations?: {
    readonly answer_trajectories?: Record<string, unknown>;
    readonly constraint_trajectories?: Record<string, unknown>;
    readonly reasoning_depth?: { readonly reasoning_depth_score?: number } | number;
  };
  readonly attempts?: readonly DacrRawAttempt[];
  readonly final_submitted_answers?: DacrRawAttempt['submitted_answers'];
}

export interface DacrBridgeOptions {
  readonly epochCommitted: number;
  readonly defaultDistractors?: number;
  readonly maxDistractors?: number;
  readonly distractorPool?: ReadonlyMap<string, readonly string[]>;
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

function familyForQuestion(
  domain: DacrChallengeDomain,
  metadata: ReadonlyArray<Record<string, unknown>> | undefined,
  qIdx: number,
): ProductionCorpusFamily {
  const override = metadata?.[qIdx]?.['coretex_family'];
  if (override === 'near_collision' || override === 'temporal' || override === 'long_horizon') return override;
  if (override === 'temporal_current_stale') return 'temporal';
  if (override === 'relation_multi_hop') return 'long_horizon';
  return routeDacrFamily(domain);
}

function challengeQuestionKey(challengeId: string, qKey: string): string {
  return `${challengeId.toLowerCase()}:${qKey.toLowerCase()}`;
}

function addDistractor(out: Set<string>, candidate: unknown, truthValue: string, maxDistractors: number): void {
  const stringified = candidate == null ? '' : String(candidate).trim();
  if (stringified && stringified !== truthValue) out.add(stringified);
  if (out.size > maxDistractors) {
    for (const value of [...out].slice(maxDistractors)) out.delete(value);
  }
}

/** Pick distractors from traps, wrong local submissions, and the cohort of other miners' answers. */
function pickDistractors(
  rec: { challenge_id?: string; trap_metadata?: DacrRawAttempt['trap_metadata']; submitted_answers?: DacrRawAttempt['submitted_answers'] },
  qKey: string,
  truthValue: string,
  maxDistractors: number,
  pool?: ReadonlyMap<string, readonly string[]>,
): string[] {
  const out = new Set<string>();
  const traps = rec.trap_metadata?.traps ?? [];
  for (const trap of traps) {
    const t = trap as Record<string, unknown>;
    for (const candidate of [
      t['wrong_value'],
      t['decoy'],
      t['decoy_value'],
      t['lure'],
      t['lure_value'],
      t['path_a_derived'],
      t['path_b_derived'],
      t['wrong_answer'],
      t['stale_value'],
    ]) {
      addDistractor(out, candidate, truthValue, maxDistractors);
      if (out.size >= maxDistractors) break;
    }
    if (out.size >= maxDistractors) break;
  }
  // Also include the "submitted but wrong" value for this question if any.
  const sub = rec.submitted_answers?.[qKey];
  if (sub && typeof sub.value === 'string' && sub.value !== truthValue && sub.correct === false) {
    out.add(sub.value);
  }
  if (rec.challenge_id) {
    for (const candidate of pool?.get(challengeQuestionKey(rec.challenge_id, qKey)) ?? []) {
      addDistractor(out, candidate, truthValue, maxDistractors);
      if (out.size >= maxDistractors) break;
    }
  }
  return [...out].slice(0, maxDistractors);
}

/** Bridge a passing DACR raw-attempt to one or more §9 corpus events (one per correct question). */
export function bridgeDacrAttempt(record: DacrRawAttempt, opts: DacrBridgeOptions): ProductionCorpusEvent[] {
  if (record.pass !== true) return [];
  const verification = record.answer_verification?.per_question ?? {};
  const submitted = record.submitted_answers ?? {};
  const events: ProductionCorpusEvent[] = [];
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
    const family = familyForQuestion(record.challenge_domain, record.question_metadata, qIdx);
    const regions = defaultDacrRegions(family);
    const distractors = pickDistractors(record, qKey, expected, opts.maxDistractors ?? 5, opts.distractorPool);
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
  return bridgeDacrTemporalPair(pair, 'pairs_sequential', opts);
}

export function bridgeDacrBookendPair(pair: DacrBookendPair, opts: DacrBridgeOptions): ProductionCorpusEvent[] {
  return bridgeDacrTemporalPair(pair, 'pairs_bookend', opts);
}

function bridgeDacrTemporalPair(
  pair: DacrSequentialPair | DacrBookendPair,
  sourceSegment: 'pairs_sequential' | 'pairs_bookend',
  opts: DacrBridgeOptions,
): ProductionCorpusEvent[] {
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
    const currentDistractors = uniqueStrings([
      wrongValue,
      ...pickDistractors(
        { challenge_id: pair.challenge_id, trap_metadata: pair.trap_metadata, submitted_answers: pair.rejected.submitted_answers },
        qKey,
        correctValue,
        opts.maxDistractors ?? 5,
        opts.distractorPool,
      ),
    ], opts.maxDistractors ?? 5);
    const staleDistractors = uniqueStrings([
      correctValue,
      ...pickDistractors(
        { challenge_id: pair.challenge_id, trap_metadata: pair.trap_metadata, submitted_answers: pair.chosen.submitted_answers },
        qKey,
        wrongValue,
        opts.maxDistractors ?? 5,
        opts.distractorPool,
      ),
    ], opts.maxDistractors ?? 5);
    const idPrefix = sourceSegment === 'pairs_bookend' ? 'dacr-bookend' : 'dacr-pair';
    const sourceRef = `dacr-lt-training:${sourceSegment}/${pair.challenge_domain}/${pair.challenge_id}`;

    // current truth (chosen)
    events.push({
      id: `${idPrefix}-${pair.challenge_id.slice(2, 14)}-${qKey}-current`,
      family: 'temporal',
      taskType: `${pair.challenge_domain}:${qKey}:current`,
      isProtected: false,
      epochCommitted: opts.epochCommitted,
      sourceRef,
      queryText,
      truthText: correctValue,
      isStaleTruth: false,
      relevant: true,
      distractors: currentDistractors,
      relations: [`supersedes:${idPrefix}-${pair.challenge_id.slice(2, 14)}-${qKey}-stale`, `pair_type:${sourceSegment}`],
      expectedStateRegions: baseRegions,
      validFromEpoch: opts.epochCommitted,
      expiresAtEpoch: 0,
      noveltyBucket: novelty,
      hardnessSignal: 0.7,
    });
    // stale truth (rejected)
    events.push({
      id: `${idPrefix}-${pair.challenge_id.slice(2, 14)}-${qKey}-stale`,
      family: 'temporal',
      taskType: `${pair.challenge_domain}:${qKey}:stale`,
      isProtected: false,
      epochCommitted: opts.epochCommitted,
      sourceRef,
      queryText,
      truthText: wrongValue,
      isStaleTruth: true,
      relevant: true,
      distractors: staleDistractors,
      relations: [`superseded_by:${idPrefix}-${pair.challenge_id.slice(2, 14)}-${qKey}-current`, `pair_type:${sourceSegment}`],
      expectedStateRegions: baseRegions,
      validFromEpoch: opts.epochCommitted,
      expiresAtEpoch: opts.epochCommitted,
      noveltyBucket: novelty,
      hardnessSignal: 0.6,
    });
  }
  return events;
}

export function bridgeDacrSession(session: DacrSessionTrajectory, opts: DacrBridgeOptions): ProductionCorpusEvent[] {
  const attempts = session.attempts ?? [];
  const finalAttempt =
    attempts.find((attempt) => attempt.record_id === session.session?.pass_record_id)
    ?? [...attempts].reverse().find((attempt) => attempt.pass === true)
    ?? attempts[attempts.length - 1];
  if (!finalAttempt) return [];
  const verification = finalAttempt.answer_verification?.per_question ?? {};
  const submitted = session.final_submitted_answers ?? finalAttempt.submitted_answers ?? {};
  const events: ProductionCorpusEvent[] = [];
  const ansCount = finalAttempt.answer_verification?.correct ?? 0;
  const ansTotal = finalAttempt.answer_verification?.total ?? 1;
  const correctness = ansTotal > 0 ? ansCount / ansTotal : 0;
  const seedHash = sha256Hex(`${session.challenge_seed}:${session.challenge_domain}:session`);
  const novelty = noveltyBucketFromHash(seedHash);
  const hardness = hardnessSignalFrom(session.session_annotations?.reasoning_depth ?? finalAttempt.reasoning_depth, correctness);
  const maxDistractors = opts.maxDistractors ?? 5;
  const sessionId = `${session.challenge_id.slice(2, 14)}-${session.session?.nonce ?? 'session'}`;

  for (const [qKey, ver] of Object.entries(verification)) {
    if (ver?.correct !== true) continue;
    const expected = ver.expected ?? submitted[qKey]?.expected;
    if (typeof expected !== 'string' || expected.length === 0) continue;
    const qIdx = questionIndex(qKey);
    const queryText = (session.questions ?? [])[qIdx];
    if (typeof queryText !== 'string' || queryText.length === 0) continue;
    const wrongs = attempts.flatMap((attempt) => {
      const answer = attempt.submitted_answers?.[qKey];
      return answer?.correct === false && typeof answer.value === 'string' ? [answer.value] : [];
    });
    const distractors = uniqueStrings([
      ...wrongs,
      ...pickDistractors(
        {
          challenge_id: session.challenge_id,
          trap_metadata: session.trap_metadata,
          submitted_answers: submitted,
        },
        qKey,
        expected,
        maxDistractors,
        opts.distractorPool,
      ),
    ], maxDistractors);
    const family = familyForQuestion(session.challenge_domain, session.question_metadata, qIdx);
    events.push({
      id: `dacr-session-${session.challenge_id.slice(2, 14)}-${qKey}`,
      family: family === 'temporal' ? 'long_horizon' : family,
      taskType: `${session.challenge_domain}:${qKey}:session`,
      isProtected: false,
      epochCommitted: opts.epochCommitted,
      sourceRef: `dacr-lt-training:sessions/${session.challenge_domain}/${session.challenge_id}`,
      queryText,
      truthText: expected,
      isStaleTruth: false,
      relevant: true,
      distractors,
      relations: [
        `session:${sessionId}`,
        `attempts:${session.session?.attempts_total ?? attempts.length}`,
        `final_status:${session.session?.final_status ?? 'unknown'}`,
      ],
      expectedStateRegions: ['memory_index', 'retrieval_keys', 'relations'],
      validFromEpoch: opts.epochCommitted,
      expiresAtEpoch: 0,
      noveltyBucket: novelty,
      hardnessSignal: Math.max(0.1, hardness),
    });
  }
  return events;
}

/** Bridge a batch of records (mixed attempts + pairs) honoring opts. */
export function bridgeDacrBatch(
  attempts: ReadonlyArray<DacrRawAttempt>,
  pairs: ReadonlyArray<DacrSequentialPair>,
  opts: DacrBridgeOptions,
  sessions: ReadonlyArray<DacrSessionTrajectory> = [],
  bookends: ReadonlyArray<DacrBookendPair> = [],
): ProductionCorpusEvent[] {
  const out: ProductionCorpusEvent[] = [];
  const distractorPool = buildCrossMinerDistractorPool(attempts, pairs, sessions, bookends);
  const mergedOpts = { ...opts, distractorPool };
  for (const att of attempts) out.push(...bridgeDacrAttempt(att, mergedOpts));
  for (const pair of pairs) out.push(...bridgeDacrSequentialPair(pair, mergedOpts));
  for (const session of sessions) out.push(...bridgeDacrSession(session, mergedOpts));
  for (const bookend of bookends) out.push(...bridgeDacrBookendPair(bookend, mergedOpts));
  return out;
}

function buildCrossMinerDistractorPool(
  attempts: ReadonlyArray<DacrRawAttempt>,
  pairs: ReadonlyArray<DacrSequentialPair>,
  sessions: ReadonlyArray<DacrSessionTrajectory>,
  bookends: ReadonlyArray<DacrBookendPair>,
): ReadonlyMap<string, readonly string[]> {
  const pool = new Map<string, Set<string>>();
  const add = (challengeId: string, qKey: string, value: unknown, expected?: string) => {
    const candidate = value == null ? '' : String(value).trim();
    if (!candidate || candidate === expected) return;
    const key = challengeQuestionKey(challengeId, qKey);
    const set = pool.get(key) ?? new Set<string>();
    set.add(candidate);
    pool.set(key, set);
  };

  for (const attempt of attempts) collectWrongAnswers(pool, add, attempt.challenge_id, attempt.submitted_answers);
  for (const pair of pairs) {
    collectWrongAnswers(pool, add, pair.challenge_id, pair.rejected?.submitted_answers);
    collectWrongAnswers(pool, add, pair.challenge_id, pair.chosen?.submitted_answers);
  }
  for (const bookend of bookends) {
    collectWrongAnswers(pool, add, bookend.challenge_id, bookend.rejected?.submitted_answers);
    collectWrongAnswers(pool, add, bookend.challenge_id, bookend.chosen?.submitted_answers);
  }
  for (const session of sessions) {
    for (const attempt of session.attempts ?? []) collectWrongAnswers(pool, add, session.challenge_id, attempt.submitted_answers);
    collectWrongAnswers(pool, add, session.challenge_id, session.final_submitted_answers);
  }

  return new Map([...pool.entries()].map(([key, values]) => [key, [...values]]));
}

function collectWrongAnswers(
  _pool: Map<string, Set<string>>,
  add: (challengeId: string, qKey: string, value: unknown, expected?: string) => void,
  challengeId: string,
  answers?: DacrRawAttempt['submitted_answers'],
): void {
  for (const [qKey, answer] of Object.entries(answers ?? {})) {
    if (answer.correct === false) add(challengeId, qKey, answer.value, answer.expected);
  }
}

function uniqueStrings(values: readonly string[], max: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
    if (out.length >= max) break;
  }
  return out;
}
