/**
 * Corpus admission policy for the retrieval-benchmark corpus.
 *
 * Applies a configurable set of quality and balance rules to a batch of
 * candidate ProductionCorpusEvent records before they enter a delta.
 * Reject reasons are typed strings so callers can audit decisions.
 *
 * The policy is shape-aware: it requires graded qrels, truth documents,
 * hard negatives, and embedding payloads. Records missing the load-bearing
 * retrieval shape are rejected.
 */

import type { ProductionCorpusEvent } from '../eval/retrieval-corpus.js';

// ── Policy ────────────────────────────────────────────────────────────────────

export interface AdmissionPolicy {
  /** Maximum total corpus size across all domains. */
  readonly totalCap: number;
  /** Maximum records per domain. */
  readonly perDomainCap: number;
  /** Minimum number of hard negative documents required per non-abstention record. */
  readonly minHardNegativesPerRecord: number;
  /** Minimum truth-document count required per non-abstention record. */
  readonly minTruthDocumentsPerRecord: number;
  /** Whether sourceHash must be non-empty bytes32. */
  readonly requireSourceProvenance: boolean;
  /** Per-record qrel coverage requirement: at least this many entries must be > 0. */
  readonly minPositiveQrelEntries: number;
  /** Bi-encoder model id the embedding payloads must reference. */
  readonly requiredBiEncoderModelId: string;
  /** Bi-encoder revision the embedding payloads must reference. */
  readonly requiredBiEncoderRevision: string;
}

export const DEFAULT_ADMISSION_POLICY: Omit<AdmissionPolicy, 'requiredBiEncoderModelId' | 'requiredBiEncoderRevision'> = {
  totalCap: 10_000,
  perDomainCap: 1_500,
  minHardNegativesPerRecord: 2,
  minTruthDocumentsPerRecord: 1,
  requireSourceProvenance: true,
  minPositiveQrelEntries: 1,
};

// ── Decision ──────────────────────────────────────────────────────────────────

export type AdmissionRejectionReason =
  | 'missing_source_provenance'
  | 'insufficient_hard_negatives'
  | 'insufficient_truth_documents'
  | 'insufficient_positive_qrels'
  | 'embedding_model_id_mismatch'
  | 'embedding_revision_mismatch'
  | 'per_domain_cap_exceeded'
  | 'total_cap_exceeded';

export interface AdmissionDecision {
  readonly admitted: ProductionCorpusEvent[];
  readonly rejected: ReadonlyArray<{ readonly record: ProductionCorpusEvent; readonly reason: AdmissionRejectionReason }>;
  readonly perDomainCounts: Record<string, number>;
}

// ── Admission logic ───────────────────────────────────────────────────────────

export function admitCorpusBatch(
  candidates: readonly ProductionCorpusEvent[],
  policy: AdmissionPolicy,
): AdmissionDecision {
  const admitted: ProductionCorpusEvent[] = [];
  const rejected: Array<{ record: ProductionCorpusEvent; reason: AdmissionRejectionReason }> = [];
  const perDomainCounts: Record<string, number> = {};

  for (const record of candidates) {
    if (policy.requireSourceProvenance && (record.provenance.sourceHash ?? '').trim() === '') {
      rejected.push({ record, reason: 'missing_source_provenance' });
      continue;
    }

    const isAbstention = record.truthDocuments.length === 0;
    if (!isAbstention && record.truthDocuments.length < policy.minTruthDocumentsPerRecord) {
      rejected.push({ record, reason: 'insufficient_truth_documents' });
      continue;
    }
    if (record.hardNegatives.length < policy.minHardNegativesPerRecord) {
      rejected.push({ record, reason: 'insufficient_hard_negatives' });
      continue;
    }

    if (!isAbstention) {
      const positives = record.qrels.filter((q) => q.relevance > 0).length;
      if (positives < policy.minPositiveQrelEntries) {
        rejected.push({ record, reason: 'insufficient_positive_qrels' });
        continue;
      }
    }

    if (record.embeddings.modelId !== policy.requiredBiEncoderModelId) {
      rejected.push({ record, reason: 'embedding_model_id_mismatch' });
      continue;
    }
    if (record.embeddings.revision !== policy.requiredBiEncoderRevision) {
      rejected.push({ record, reason: 'embedding_revision_mismatch' });
      continue;
    }

    const domain = record.domain;
    const domainCount = perDomainCounts[domain] ?? 0;
    if (domainCount >= policy.perDomainCap) {
      rejected.push({ record, reason: 'per_domain_cap_exceeded' });
      continue;
    }

    if (admitted.length >= policy.totalCap) {
      rejected.push({ record, reason: 'total_cap_exceeded' });
      continue;
    }

    admitted.push(record);
    perDomainCounts[domain] = domainCount + 1;
  }

  return { admitted, rejected, perDomainCounts };
}
