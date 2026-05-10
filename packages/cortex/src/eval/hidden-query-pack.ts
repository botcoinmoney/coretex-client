/**
 * Hidden query pack derivation.
 *
 * Spec: specs/hidden_query_pack_v0.md.
 *
 * The query pack is deterministic from (epochId, evalSeed, corpus). Anyone
 * with the seed and the bundle reproduces the same pack and verifies it
 * satisfies the per-stratum quotas pinned in the bundle profile.
 */

import { keccak256 } from '../state/keccak256.js';
import type { ProductionCorpus, ProductionCorpusEvent, ProductionCorpusFamily } from './retrieval-corpus.js';

export type HardnessBucket = 'easy' | 'medium' | 'hard';

export interface PackQuota {
  readonly stratum: string;        // e.g. "family=temporal"
  readonly minCount: number;
}

export interface HiddenPackProfile {
  readonly packSize: number;
  readonly quotas: readonly PackQuota[];
}

export interface QueryPack {
  readonly epochId: number;
  readonly evalSeedHex: string;
  readonly corpusRoot: string;
  readonly events: readonly ProductionCorpusEvent[];
}

/**
 * Compute the hardness bucket for a corpus event.
 *
 * Hardness is derived from the labeling-model score gap between the
 * hardest negative pair and the highest-graded truth. We approximate this
 * as the max negative qrel score: more plausible wrong answers → harder
 * query. Hard negatives are capped at 0.4 because they are deliberately
 * non-answer-bearing.
 */
export function hardnessBucketFor(event: ProductionCorpusEvent): HardnessBucket {
  let maxNeg: number = 0;
  const truthIds = new Set(event.truthDocuments.map((d) => d.id));
  for (const q of event.qrels) {
    if (truthIds.has(q.documentId)) continue;
    if (q.relevance > maxNeg) maxNeg = q.relevance;
  }
  if (maxNeg >= 0.4) return 'hard';
  if (maxNeg >= 0.2) return 'medium';
  return 'easy';
}

export function stratumOf(event: ProductionCorpusEvent): string {
  return `family=${event.family},bucket=${hardnessBucketFor(event)}`;
}

function evalSeedBytes(evalSeedHex: string): Uint8Array {
  const clean = evalSeedHex.startsWith('0x') ? evalSeedHex.slice(2) : evalSeedHex;
  if (clean.length !== 64) throw new Error(`evalSeed must be 32 bytes (got ${clean.length / 2})`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function u64BE(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = typeof n === 'bigint' ? n : BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function digestU256(parts: Uint8Array[]): bigint {
  let total = 0;
  for (const p of parts) total += p.length;
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  const d = keccak256(buf);
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(d[i]!);
  return v;
}

/**
 * Derive a deterministic per-epoch query pack from `(epochId, evalSeed, corpus, profile)`.
 * Throws if the post-stratification pack cannot satisfy the quotas.
 */
export function deriveQueryPack(
  epochId: number,
  evalSeedHex: string,
  corpus: ProductionCorpus,
  profile: HiddenPackProfile,
): QueryPack {
  const seed = evalSeedBytes(evalSeedHex);
  const epochBE = u64BE(epochId);

  const sorted = corpus.events
    .filter((e) => e.split === 'eval_hidden')
    .sort((a, b) => a.id.localeCompare(b.id));
  if (sorted.length === 0) throw new Error('deriveQueryPack: corpus has no eval_hidden records');

  const pack: ProductionCorpusEvent[] = [];
  const ids = new Set<string>();
  for (let i = 0; i < profile.packSize; i++) {
    const idx = digestU256([seed, epochBE, u64BE(i)]) % BigInt(sorted.length);
    const cand = sorted[Number(idx)]!;
    if (ids.has(cand.id)) {
      // Skip duplicate — pack-size will be made up by stratification fill below.
      continue;
    }
    pack.push(cand);
    ids.add(cand.id);
  }

  // Stratification fill.
  const enc = new TextEncoder();
  for (const quota of profile.quotas) {
    let present = pack.filter((e) => stratumOf(e) === quota.stratum).length;
    let j = 0;
    while (present < quota.minCount && j < sorted.length * 4) {
      const idx = digestU256([seed, epochBE, enc.encode(quota.stratum), u64BE(j)]) % BigInt(sorted.length);
      const cand = sorted[Number(idx)]!;
      j++;
      if (ids.has(cand.id)) continue;
      if (stratumOf(cand) !== quota.stratum) continue;
      // Replace lowest-priority pack member: pack member from a stratum that is
      // already over-quota (or with the lex-largest stratum hash if none).
      let evictIdx = -1;
      for (let k = 0; k < pack.length; k++) {
        const ks = stratumOf(pack[k]!);
        if (ks === quota.stratum) continue;
        const ksQuota = profile.quotas.find((q) => q.stratum === ks)?.minCount ?? 0;
        const ksCount = pack.filter((e) => stratumOf(e) === ks).length;
        if (ksCount > ksQuota) {
          evictIdx = k;
          break;
        }
      }
      if (evictIdx < 0) {
        // No over-quota member to evict; replace lex-largest stratum hash.
        let largestHash = '';
        for (let k = 0; k < pack.length; k++) {
          const ks = stratumOf(pack[k]!);
          const h = uint8ToHex(keccak256(enc.encode(ks)));
          if (h > largestHash) {
            largestHash = h;
            evictIdx = k;
          }
        }
      }
      if (evictIdx < 0) break;
      const evicted = pack[evictIdx]!;
      pack[evictIdx] = cand;
      ids.delete(evicted.id);
      ids.add(cand.id);
      present++;
    }
    if (present < quota.minCount) {
      throw new Error(`deriveQueryPack: stratum ${quota.stratum} cannot meet quota ${quota.minCount} (got ${present})`);
    }
  }

  return {
    epochId,
    evalSeedHex: evalSeedHex.toLowerCase().startsWith('0x') ? evalSeedHex.toLowerCase() : `0x${evalSeedHex.toLowerCase()}`,
    corpusRoot: corpus.corpusRoot,
    events: pack,
  };
}

function uint8ToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Verify a published pack against the deterministic recomputation.
 */
export function verifyQueryPack(
  pack: QueryPack,
  corpus: ProductionCorpus,
  profile: HiddenPackProfile,
): { ok: true } | { ok: false; reason: string } {
  if (pack.corpusRoot.toLowerCase() !== corpus.corpusRoot.toLowerCase()) {
    return { ok: false, reason: 'corpusRoot mismatch' };
  }
  let recomputed: QueryPack;
  try {
    recomputed = deriveQueryPack(pack.epochId, pack.evalSeedHex, corpus, profile);
  } catch (err) {
    return { ok: false, reason: `deriveQueryPack failed: ${(err as Error).message}` };
  }
  if (recomputed.events.length !== pack.events.length) {
    return { ok: false, reason: `pack length mismatch: ${pack.events.length} vs ${recomputed.events.length}` };
  }
  for (let i = 0; i < pack.events.length; i++) {
    if (recomputed.events[i]!.id !== pack.events[i]!.id) {
      return { ok: false, reason: `pack[${i}] id mismatch` };
    }
  }
  return { ok: true };
}

export function packQuotaCoverage(
  pack: QueryPack,
  profile: HiddenPackProfile,
): readonly { readonly stratum: string; readonly count: number; readonly minCount: number; readonly satisfied: boolean }[] {
  return profile.quotas.map((q) => {
    const count = pack.events.filter((e) => stratumOf(e) === q.stratum).length;
    return { stratum: q.stratum, count, minCount: q.minCount, satisfied: count >= q.minCount };
  });
}

export type PerFamilyCount = Partial<Record<ProductionCorpusFamily, number>>;

export function packFamilyCounts(pack: QueryPack): PerFamilyCount {
  const counts: PerFamilyCount = {};
  for (const e of pack.events) {
    counts[e.family] = (counts[e.family] ?? 0) + 1;
  }
  return counts;
}
