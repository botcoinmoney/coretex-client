/**
 * Corpus admission policy.
 *
 * Applies a configurable set of quality and balance rules to a batch of
 * candidate ProductionCorpusEvent records before they are added to the corpus.
 * Reject reasons are specific strings so callers can filter/audit decisions.
 */

import type { ProductionCorpusEvent, ProductionCorpusRegion } from '../eval/corpus.js';

// ── Policy ────────────────────────────────────────────────────────────────────

export interface AdmissionPolicy {
  /** Maximum total corpus size across all domains. */
  readonly totalCap: number;
  /** Maximum records per domain (keyed by taskType). */
  readonly perDomainCap: number;
  /** Minimum number of distractor strings required per record. */
  readonly minDistractorsPerRecord: number;
  /** Minimum hardness signal value (inclusive lower bound in [0, 1]). */
  readonly minHardnessSignal: number;
  /** Whether sourceRef must be non-empty. */
  readonly requireSourceProvenance: boolean;
  /** Set of allowed state regions — records must reference at least one. */
  readonly allowedRegions: ReadonlyArray<ProductionCorpusRegion>;
}

/**
 * Reasonable production defaults aligned with §9 caps.
 */
export const DEFAULT_ADMISSION_POLICY: AdmissionPolicy = {
  totalCap: 10_000,
  perDomainCap: 1_500,
  minDistractorsPerRecord: 2,
  minHardnessSignal: 0.05,
  requireSourceProvenance: true,
  allowedRegions: ['memory_index', 'retrieval_keys', 'relations', 'temporal', 'codebook'],
};

// ── Decision ──────────────────────────────────────────────────────────────────

export interface AdmissionDecision {
  readonly admitted: ProductionCorpusEvent[];
  readonly rejected: ReadonlyArray<{ readonly record: ProductionCorpusEvent; readonly reason: string }>;
  readonly perDomainCounts: Record<string, number>;
}

// ── Admission logic ───────────────────────────────────────────────────────────

/**
 * Apply admission rules to a batch of candidates.
 *
 * Rules are applied in this order for each record:
 * 1. Source provenance: sourceRef must be non-empty when requireSourceProvenance
 * 2. Distractor count: distractors.length >= minDistractorsPerRecord
 * 3. Hardness signal: hardnessSignal >= minHardnessSignal
 * 4. Region overlap: at least one expectedStateRegion in allowedRegions
 * 5. Per-domain cap: perDomainCounts[domain] < perDomainCap
 * 6. Total cap: admitted.length < totalCap
 */
export function admitCorpusBatch(
  candidates: readonly ProductionCorpusEvent[],
  policy: AdmissionPolicy,
): AdmissionDecision {
  const admitted: ProductionCorpusEvent[] = [];
  const rejected: Array<{ record: ProductionCorpusEvent; reason: string }> = [];
  const perDomainCounts: Record<string, number> = {};

  const allowedSet = new Set<string>(policy.allowedRegions);

  for (const record of candidates) {
    // Rule 1: source provenance
    if (policy.requireSourceProvenance && record.sourceRef.trim() === '') {
      rejected.push({ record, reason: 'missing_source_provenance' });
      continue;
    }

    // Rule 2: distractor count
    if (record.distractors.length < policy.minDistractorsPerRecord) {
      rejected.push({ record, reason: 'insufficient_distractors' });
      continue;
    }

    // Rule 3: hardness signal
    if (record.hardnessSignal < policy.minHardnessSignal) {
      rejected.push({ record, reason: 'hardness_signal_too_low' });
      continue;
    }

    // Rule 4: region overlap
    const hasAllowedRegion = record.expectedStateRegions.some((r) => allowedSet.has(r));
    if (!hasAllowedRegion) {
      rejected.push({ record, reason: 'no_allowed_state_region' });
      continue;
    }

    // Rule 5: per-domain cap (domain keyed by taskType)
    const domain = record.taskType;
    const domainCount = perDomainCounts[domain] ?? 0;
    if (domainCount >= policy.perDomainCap) {
      rejected.push({ record, reason: 'per_domain_cap_exceeded' });
      continue;
    }

    // Rule 6: total cap
    if (admitted.length >= policy.totalCap) {
      rejected.push({ record, reason: 'total_cap_exceeded' });
      continue;
    }

    // Admitted
    admitted.push(record);
    perDomainCounts[domain] = domainCount + 1;
  }

  return { admitted, rejected, perDomainCounts };
}
