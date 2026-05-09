/**
 * V3-to-V4 corpus bridge.
 *
 * Reshapes raw V3 challenge records into §9-compliant ProductionCorpusEvent
 * objects suitable for admission into the production corpus.  Raw V3 dumps
 * are NOT admitted directly; they must pass through this bridge first.
 *
 * Only hashes and curated text are included — no private user data, no
 * coordinator signing keys, no raw attempt payloads.
 */

import { createHash } from 'node:crypto';

import type { ProductionCorpusEvent, ProductionCorpusFamily, ProductionCorpusNoveltyBucket, ProductionCorpusRegion } from '../eval/corpus.js';

// ── V3 source record shape ────────────────────────────────────────────────────

/**
 * A V3 challenge record as exported by the coordinator archive.
 * Contains only hashes and public metadata — never raw user data.
 */
export interface V3ChallengeRecord {
  readonly challengeId: string;
  readonly worldSeed: string;
  readonly domain: string;
  readonly rulesVersion: string;
  readonly manifestHash: string;
  readonly docHash: string;
  readonly questionsHash: string;
  readonly constraintsHash: string;
  readonly selectedQuestionIndices: readonly number[];
  readonly answerHashes: readonly string[];
  readonly sourceVersionHash: string;
  readonly coreCommitHash: string;
}

// ── Bridge options ────────────────────────────────────────────────────────────

export interface V3BridgeOptions {
  /** Epoch at which this record is being committed to the corpus. */
  readonly epochCommitted: number;
  /**
   * Override family routing.  If omitted, family is derived from
   * `domain` using the standard routing rules.
   */
  readonly family?: ProductionCorpusFamily;
  /**
   * Override default expectedStateRegions for every bridged record.
   * If omitted, defaults are computed per-family.
   */
  readonly defaultRegions?: ReadonlyArray<ProductionCorpusRegion>;
  /**
   * Optional hook for generating hard-negative distractor strings from
   * a V3 record.  The returned strings are used as `distractors`.
   */
  readonly mintHardNegatives?: (record: V3ChallengeRecord) => readonly string[];
}

// ── Family routing ────────────────────────────────────────────────────────────

/**
 * Route a V3 domain string to a ProductionCorpusFamily.
 *
 * Rules (applied in order):
 * - domain contains 'temporal' or 'time'  → temporal
 * - domain contains 'collision' or 'similar' → near_collision
 * - otherwise → long_horizon
 */
export function routeV3Family(domain: string): ProductionCorpusFamily {
  const d = domain.toLowerCase();
  if (d.includes('temporal') || d.includes('time')) return 'temporal';
  if (d.includes('collision') || d.includes('similar')) return 'near_collision';
  return 'long_horizon';
}

// ── Default regions per family ────────────────────────────────────────────────

function defaultRegionsFor(family: ProductionCorpusFamily): ReadonlyArray<ProductionCorpusRegion> {
  if (family === 'near_collision') return ['memory_index'];
  if (family === 'temporal') return ['memory_index', 'temporal'];
  return ['memory_index', 'retrieval_keys']; // long_horizon
}

// ── Hardness signal ───────────────────────────────────────────────────────────

/**
 * Compute `hardnessSignal` as `sha256(challengeId + manifestHash) mod 100`
 * normalised to [0, 1].  Deterministic for the same inputs.
 */
export function computeHardnessSignal(challengeId: string, manifestHash: string): number {
  const digest = createHash('sha256').update(`${challengeId}${manifestHash}`).digest();
  // Use first two bytes to get value in [0, 255*256+255]
  const raw = (digest[0]! * 256 + digest[1]!) % 100;
  return raw / 100;
}

// ── Novelty bucket ────────────────────────────────────────────────────────────

/**
 * Derive a novelty bucket by hash-bucketing `manifestHash` into thirds.
 * 0 → 'low', 1 → 'medium', 2 → 'high'.
 */
export function computeNoveltyBucket(manifestHash: string): ProductionCorpusNoveltyBucket {
  const digest = createHash('sha256').update(manifestHash).digest();
  const v = (digest[0]! + digest[1]! * 256) % 3;
  return v === 0 ? 'low' : v === 1 ? 'medium' : 'high';
}

// ── Corpus id ─────────────────────────────────────────────────────────────────

/**
 * Build a deterministic corpus record id from the V3 challengeId and epoch.
 * Format: `v3bridge-<epochCommitted>-<hex8>` where hex8 is the first 8 hex
 * chars of sha256(challengeId).
 */
function bridgeCorpusId(challengeId: string, epochCommitted: number): string {
  const digest = createHash('sha256').update(challengeId).digest('hex');
  return `v3bridge-${epochCommitted}-${digest.slice(0, 8)}`;
}

// ── Single record bridge ──────────────────────────────────────────────────────

/**
 * Bridge a single V3 challenge record into a §9-compliant ProductionCorpusEvent.
 *
 * The resulting record includes:
 * - challenge / provenance hashes as sourceRef
 * - family routing based on domain
 * - hardness signal and novelty bucket derived from hashes
 * - hard negatives from optional `mintHardNegatives` hook
 * - no private user data — only public hashes and curated text
 */
export function bridgeV3ToV4(record: V3ChallengeRecord, opts: V3BridgeOptions): ProductionCorpusEvent {
  const family = opts.family ?? routeV3Family(record.domain);
  const distractors: readonly string[] = opts.mintHardNegatives ? opts.mintHardNegatives(record) : [];
  const expectedStateRegions: ReadonlyArray<ProductionCorpusRegion> = opts.defaultRegions ?? defaultRegionsFor(family);
  const hardnessSignal = computeHardnessSignal(record.challengeId, record.manifestHash);
  const noveltyBucket = computeNoveltyBucket(record.manifestHash);

  // Build a stable source reference from public hashes (no private fields).
  const sourceRef = [
    `v3-challenge:${record.challengeId}`,
    `manifest:${record.manifestHash}`,
    `doc:${record.docHash}`,
    `questions:${record.questionsHash}`,
    `constraints:${record.constraintsHash}`,
    `source-version:${record.sourceVersionHash}`,
    `core:${record.coreCommitHash}`,
  ].join(';');

  // Relations: answer hashes expressed as dependency relations.
  const relations: readonly string[] = record.answerHashes.map(
    (h, i) => `answer_hash_${i}:${h}`,
  );

  // Query and truth text are constructed from curated hash references.
  // Coordinators may enrich these with actual text when reshaping for eval.
  const queryText = `domain:${record.domain} seed:${record.worldSeed} rules:${record.rulesVersion} questions:${record.questionsHash}`;
  const truthText = `manifest:${record.manifestHash} answers:[${record.answerHashes.join(',')}]`;

  return {
    id: bridgeCorpusId(record.challengeId, opts.epochCommitted),
    family,
    taskType: record.domain,
    isProtected: false,
    epochCommitted: opts.epochCommitted,
    sourceRef,
    queryText,
    truthText,
    isStaleTruth: false,
    relevant: true,
    // §9 fields
    distractors,
    relations,
    expectedStateRegions,
    validFromEpoch: opts.epochCommitted,
    expiresAtEpoch: 0,
    noveltyBucket,
    hardnessSignal,
  };
}

// ── Batch bridge ──────────────────────────────────────────────────────────────

/**
 * Bridge a batch of V3 challenge records into §9-compliant ProductionCorpusEvents.
 */
export function bridgeV3Batch(records: readonly V3ChallengeRecord[], opts: V3BridgeOptions): ProductionCorpusEvent[] {
  return records.map((record) => bridgeV3ToV4(record, opts));
}
