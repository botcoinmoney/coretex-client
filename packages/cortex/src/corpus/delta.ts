/**
 * Corpus delta — append/remove records and track root continuity.
 *
 * `corpusRoot[N+1] = root(corpusRecords[N] + corpus_delta[N])`
 * `parentCorpusRoot[N+1] = corpusRoot[N]`
 *
 * Root computation reuses `computeProductionCorpusRoot` from eval/corpus so
 * roots are bit-for-bit identical to those produced by the loader.
 */

import type { ProductionCorpus, ProductionCorpusEvent, ProductionCorpusFamily } from '../eval/corpus.js';
import { computeProductionCorpusRoot } from '../eval/corpus.js';

// ── Delta shape ───────────────────────────────────────────────────────────────

export interface CorpusDelta {
  /** Corpus root before this delta was applied. */
  readonly previousRoot: string;
  /** Corpus root after this delta has been applied. */
  readonly nextRoot: string;
  /** IDs of records added by this delta. */
  readonly addedIds: readonly string[];
  /** IDs of records removed by this delta. */
  readonly removedIds: readonly string[];
  /** Epoch at which this delta was produced. */
  readonly epoch: number;
  /** ISO-8601 timestamp string when this delta was generated. */
  readonly generatedAt: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const FAMILIES: ReadonlyArray<ProductionCorpusFamily> = ['near_collision', 'temporal', 'long_horizon'];

/** Flatten all events from a ProductionCorpus into a single ordered array. */
function flattenEvents(corpus: ProductionCorpus): ProductionCorpusEvent[] {
  const out: ProductionCorpusEvent[] = [];
  for (const family of FAMILIES) {
    const evs = corpus.events[family];
    for (const e of evs) out.push(e);
  }
  return out;
}

/**
 * Re-bucket an array of ProductionCorpusEvent records into the family groups
 * expected by ProductionCorpus.
 */
function bucketByFamily(events: ProductionCorpusEvent[]): Record<ProductionCorpusFamily, ProductionCorpusEvent[]> {
  const result: Record<ProductionCorpusFamily, ProductionCorpusEvent[]> = {
    near_collision: [],
    temporal: [],
    long_horizon: [],
  };
  for (const e of events) {
    result[e.family].push(e);
  }
  return result;
}

/**
 * Serialize a ProductionCorpusEvent back into the plain object shape that
 * `computeProductionCorpusRoot` expects (it reads raw item objects, not the
 * normalised TS interface).
 */
function eventToRawItem(e: ProductionCorpusEvent): Record<string, unknown> {
  return {
    id: e.id,
    family: e.family,
    task: e.taskType,
    protected: e.isProtected,
    epoch_committed: e.epochCommitted,
    source_ref: e.sourceRef,
    query: e.queryText,
    truth: e.truthText,
    is_stale: e.isStaleTruth,
    relevant: e.relevant,
    distractors: e.distractors,
    relations: e.relations,
    expected_state_regions: e.expectedStateRegions,
    valid_from_epoch: e.validFromEpoch,
    expires_at_epoch: e.expiresAtEpoch,
    novelty_bucket: e.noveltyBucket,
    hardness_signal: e.hardnessSignal,
  };
}

// ── Build delta ───────────────────────────────────────────────────────────────

/**
 * Build a CorpusDelta from:
 * - `previousCorpus`: the current in-memory corpus
 * - `additions`: new records to add
 * - `removals`: IDs of records to remove
 * - `epoch`: epoch number for the delta
 *
 * The `previousRoot` is taken from `previousCorpus.corpusRoot`.
 * The `nextRoot` is computed deterministically using the same Merkle algorithm
 * as `computeProductionCorpusRoot`.
 */
export function buildCorpusDelta(
  previousCorpus: ProductionCorpus,
  additions: readonly ProductionCorpusEvent[],
  removals: readonly string[],
  epoch: number,
): CorpusDelta {
  const removalSet = new Set(removals);
  const existing = flattenEvents(previousCorpus).filter((e) => !removalSet.has(e.id));

  // Deduplicate additions (skip ids already present after removals).
  const existingIds = new Set(existing.map((e) => e.id));
  const newEvents = additions.filter((e) => !existingIds.has(e.id));

  const merged = [...existing, ...newEvents];
  const rawItems = merged.map(eventToRawItem);
  const nextRoot = computeProductionCorpusRoot(rawItems);

  return {
    previousRoot: previousCorpus.corpusRoot,
    nextRoot,
    addedIds: newEvents.map((e) => e.id),
    removedIds: removals.filter((id) => existingIds.has(id) || removalSet.has(id)),
    epoch,
    generatedAt: new Date().toISOString(),
  };
}

// ── Apply delta ───────────────────────────────────────────────────────────────

/**
 * Apply a CorpusDelta to a ProductionCorpus.
 *
 * Throws if `delta.previousRoot !== corpus.corpusRoot` (hash continuity check).
 * Returns a new ProductionCorpus with the delta applied.  The `corpusRoot` of
 * the returned corpus equals `delta.nextRoot`.
 */
export function applyCorpusDelta(corpus: ProductionCorpus, delta: CorpusDelta): ProductionCorpus {
  if (delta.previousRoot !== corpus.corpusRoot) {
    throw new Error(
      `applyCorpusDelta: hash continuity check failed — `
      + `delta.previousRoot=${delta.previousRoot} but corpus.corpusRoot=${corpus.corpusRoot}`,
    );
  }

  const removalSet = new Set(delta.removedIds);
  const addedSet = new Set(delta.addedIds);

  // Collect all existing events minus removals.
  const kept = flattenEvents(corpus).filter((e) => !removalSet.has(e.id));

  // We need to locate the actual addition records from both:
  //   a) additions supplied when buildCorpusDelta was called (not stored in delta)
  //   b) the addedIds list in delta
  //
  // Since CorpusDelta does not persist the addition payloads (by design —
  // callers must supply them), applyCorpusDelta cannot reconstruct them from
  // the delta alone.  To keep the API simple and self-contained we require
  // the caller to have the additions available via the corpus itself: if the
  // additions are already in corpus.events (e.g. a pre-applied state), we
  // just filter.  For the normal use-case we need additions passed separately.
  //
  // However, since this function is `applyCorpusDelta(corpus, delta)` without
  // an additions parameter, we treat the delta as a forward patch: we use
  // the addedIds to verify root continuity but cannot re-add records that are
  // not already in `corpus`.  The design contract is:
  //
  //   Call `buildCorpusDelta` → store the delta + the addition records.
  //   Call `applyCorpusDelta` only after merging addition records into corpus.
  //
  // For the test/delta pipeline, additions will already be in corpus.events
  // (they were merged before buildCorpusDelta was called), so this works:
  // we just remove the removals and keep everything else (including additions
  // that are already present).

  const nextRawItems = kept.map(eventToRawItem);
  const computedNextRoot = computeProductionCorpusRoot(nextRawItems);
  if (computedNextRoot !== delta.nextRoot) {
    throw new Error(
      `applyCorpusDelta: computed nextRoot=${computedNextRoot} does not match delta.nextRoot=${delta.nextRoot}. `
      + `Ensure additions are pre-merged into corpus before calling applyCorpusDelta, `
      + `or that removedIds are correct.`,
    );
  }

  // Validate that all addedIds are present in the kept set (or were added
  // before this call).
  const keptIds = new Set(kept.map((e) => e.id));
  for (const id of addedSet) {
    if (!keptIds.has(id)) {
      throw new Error(
        `applyCorpusDelta: addedId ${id} not found in corpus after applying removals. `
        + `Merge additions into corpus before calling applyCorpusDelta.`,
      );
    }
  }

  return {
    events: bucketByFamily(kept),
    corpusRoot: delta.nextRoot,
    sources: corpus.sources,
  };
}
