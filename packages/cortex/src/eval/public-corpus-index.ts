/**
 * PublicCorpusIndex — the label-free retrieval surface used by stage-1 of
 * the substrate-hardened scorer.
 *
 * Spec: docs/CORETEX_SUBSTRATE_EXPANSION_HARDENING.md §3 + §6.1.
 *
 * Anti-cheat boundary, by type:
 *   - PublicCorpusIndex contains only doc id + event id + embedding.
 *   - No qrels. No truthDocuments-as-answer-set. No relevance labels.
 *   - firstStageCandidates cannot accept ProductionCorpus by type — it only
 *     takes PublicCorpusIndex. Callers wanting to retrieve must build the
 *     index explicitly via buildPublicCorpusIndex(corpus), which makes the
 *     label-stripping step auditable at every callsite.
 *
 * The labels still live in ProductionCorpus and are consumed by the scoring
 * layer (nDCG / qrel attach), which runs AFTER the rerank. Stage-1 retrieval
 * never sees them.
 */

import { createHash } from 'node:crypto';

import type { ProductionCorpus, RetrievalKeyLayout } from './retrieval-corpus.js';

export interface PublicCorpusDoc {
  readonly id: string;
  readonly eventId: string;
  readonly embedding: Uint8Array;
}

export interface PublicCorpusIndex {
  readonly biEncoderModelId: string;
  readonly biEncoderRevision: string;
  readonly layout: RetrievalKeyLayout;
  readonly docs: readonly PublicCorpusDoc[]; // sorted by canonical id
  /** Flat row-major Float32Array of pre-dequantized doc embeddings.
   *  Length = docs.length × layout.dim. Doc i lives at [i*dim, (i+1)*dim).
   *  Pre-dequantize avoids 3.7M per-query allocations; cosine becomes a
   *  pure fp32 dot-product loop the V8 JIT can vectorize.                 */
  readonly denseEmbeddings: Float32Array;
  /** Inverse L2 norms, one per doc. cos(q,d) = dot(q,d) × invNorms[i] / |q|. */
  readonly denseInvNorms: Float32Array;
  readonly indexHash: string; // sha256 of canonical id list — for replay attestation
}

/**
 * Build the index from a labeled corpus. Deduplicates docs by canonical id:
 * a doc that appears as a hard negative in N events is included once. This
 * matters because stage-1 cosine over a duplicated doc would otherwise bias
 * Top-K toward frequently-repeated docs.
 *
 * Cross-host determinism: the returned `docs` array is sorted by canonical id
 * lexicographically, so two hosts building the index against the same corpus
 * produce byte-identical PublicCorpusIndex.
 */
export function buildPublicCorpusIndex(corpus: ProductionCorpus): PublicCorpusIndex {
  const layout = corpus.biEncoderRetrievalKeyLayout;
  if (corpus.events.length === 0) {
    return {
      biEncoderModelId: corpus.biEncoderModelId,
      biEncoderRevision: corpus.biEncoderRevision,
      layout,
      docs: [],
      denseEmbeddings: new Float32Array(0),
      denseInvNorms: new Float32Array(0),
      indexHash: `0x${'0'.repeat(64)}`,
    };
  }

  // Iterate events in stable order (corpus.events is already sorted by id from
  // the canonical writeCorpusOutputStreaming pipeline). For each doc id, the
  // first event that referenced it is the canonical owner — that pin makes the
  // dedupe deterministic across hosts.
  const seen = new Map<string, PublicCorpusDoc>();
  for (const event of corpus.events) {
    const perTruth = event.embeddings.perTruth;
    for (const truth of event.truthDocuments) {
      if (seen.has(truth.id)) continue;
      const emb = perTruth.get(truth.id);
      if (!emb) continue;
      seen.set(truth.id, { id: truth.id, eventId: event.id, embedding: emb });
    }
    for (const neg of event.hardNegatives) {
      if (seen.has(neg.id)) continue;
      const emb = event.embeddings.perNegative.get(neg.id);
      if (!emb) continue;
      seen.set(neg.id, { id: neg.id, eventId: event.id, embedding: emb });
    }
  }

  const docs = Array.from(seen.values()).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // Pre-dequantize into a row-major flat Float32Array + precompute inverse norms.
  // Memory: ~3.6 GB at launch scale (3.7M docs × 243 dim × 4 bytes). Trades RAM
  // for ~30× retrieval throughput; without it, every query re-allocates 3.7M
  // Float32Arrays and dequantizes ~900M int8 values per submit.
  //
  // Quantization wire format (matches `bi-encoder.ts:dequantize`):
  //   bytes[0:4]  big-endian float32 scale
  //   bytes[4:4+dim]  int8 body
  // `layout.headerBytes` exists in the layout struct for future schemes that
  // carry offset + flags, but the int8 production path is scale-only with a
  // 4-byte header. Hardcoded to keep alignment with the canonical decoder.
  const dim = layout.dim;
  const dense = new Float32Array(docs.length * dim);
  const invNorms = new Float32Array(docs.length);
  for (let i = 0; i < docs.length; i++) {
    const bytes = docs[i]!.embedding;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const scale = dv.getFloat32(0, false);
    let normSq = 0;
    const base = i * dim;
    for (let j = 0; j < dim; j++) {
      const b = bytes[4 + j]!;
      const signed = b > 127 ? b - 256 : b;
      const v = scale * signed;
      dense[base + j] = v;
      normSq += v * v;
    }
    invNorms[i] = normSq > 0 ? 1 / Math.sqrt(normSq) : 0;
  }

  const idsConcat = docs.map((d) => d.id).join('\n');
  const indexHash = `0x${createHash('sha256').update(idsConcat).digest('hex')}`;

  return {
    biEncoderModelId: corpus.biEncoderModelId,
    biEncoderRevision: corpus.biEncoderRevision,
    layout,
    docs,
    denseEmbeddings: dense,
    denseInvNorms: invNorms,
    indexHash,
  };
}

/**
 * Stage-1 retrieval: cosine over the public index, return Top-K. Substrate-
 * agnostic by construction (no `decoded` parameter, no qrel access). Stable
 * cross-host: byte-identical Top-K id list given byte-identical inputs.
 *
 * Performance: 679k events deduped → ~3M unique docs; one query takes
 *   ~30-100ms single-core (dominated by int8 → fp32 dequant + cosine).
 * The coordinator's pack-level cache (see stage1-cache.ts) amortizes this
 * across all patch evaluations within a pack.
 */
export function firstStageCandidates(
  queryVec: Float32Array,
  index: PublicCorpusIndex,
  k: number,
): readonly PublicCorpusDoc[] {
  if (k <= 0 || index.docs.length === 0) return [];

  const dim = index.layout.dim;
  const dense = index.denseEmbeddings;
  const invNorms = index.denseInvNorms;
  const docs = index.docs;
  const n = docs.length;

  // Pre-compute query norm once; cosine = dot(q, d) × invNorm[d] × invNorm[q].
  let qNormSq = 0;
  for (let i = 0; i < queryVec.length; i++) qNormSq += queryVec[i]! * queryVec[i]!;
  const invQNorm = qNormSq > 0 ? 1 / Math.sqrt(qNormSq) : 0;

  // Min-heap partial-sort, size k. The inner cosine loop is a tight fp32
  // dot product over flat arrays — V8 vectorizes it on AVX2/AVX-512.
  // ~50-150 ms for 3.7M docs × 243 dim at launch scale on AVX-512.
  type Heap = { cos: number; idx: number }[];
  const heap: Heap = [];

  for (let i = 0; i < n; i++) {
    const base = i * dim;
    let dot = 0;
    for (let j = 0; j < dim; j++) dot += queryVec[j]! * dense[base + j]!;
    const cos = dot * invNorms[i]! * invQNorm;

    if (heap.length < k) {
      heap.push({ cos, idx: i });
      heapifyUp(heap, heap.length - 1, docs);
    } else if (cos > heap[0]!.cos || (cos === heap[0]!.cos && docs[i]!.id < docs[heap[0]!.idx]!.id)) {
      heap[0] = { cos, idx: i };
      heapifyDown(heap, 0, docs);
    }
  }

  // Sort the k survivors descending by (cos, then docId asc as stable tie-break).
  return heap
    .sort((a, b) => {
      if (b.cos !== a.cos) return b.cos - a.cos;
      return docs[a.idx]!.id < docs[b.idx]!.id ? -1 : 1;
    })
    .map((h) => docs[h.idx]!);
}

// ─── Heap helpers (min-heap over Top-K) ──────────────────────────────────────

// Min-heap ordering: heap[0] is the WORST element currently in Top-K (smallest
// cosine, breaking ties with LARGEST docId so smaller docId wins on tie). The
// retriever evicts heap[0] when a better candidate arrives.
function compareMin(
  a: { cos: number; idx: number },
  b: { cos: number; idx: number },
  docs: readonly PublicCorpusDoc[],
): number {
  if (a.cos !== b.cos) return a.cos - b.cos;
  const ai = docs[a.idx]!.id;
  const bi = docs[b.idx]!.id;
  return ai < bi ? 1 : ai > bi ? -1 : 0;
}

function heapifyUp(
  heap: { cos: number; idx: number }[],
  i: number,
  docs: readonly PublicCorpusDoc[],
): void {
  while (i > 0) {
    const parent = (i - 1) >> 1;
    if (compareMin(heap[i]!, heap[parent]!, docs) < 0) {
      [heap[i], heap[parent]] = [heap[parent]!, heap[i]!];
      i = parent;
    } else break;
  }
}

function heapifyDown(
  heap: { cos: number; idx: number }[],
  i: number,
  docs: readonly PublicCorpusDoc[],
): void {
  const n = heap.length;
  while (true) {
    const left = 2 * i + 1;
    const right = 2 * i + 2;
    let smallest = i;
    if (left < n && compareMin(heap[left]!, heap[smallest]!, docs) < 0) smallest = left;
    if (right < n && compareMin(heap[right]!, heap[smallest]!, docs) < 0) smallest = right;
    if (smallest === i) break;
    [heap[i], heap[smallest]] = [heap[smallest]!, heap[i]!];
    i = smallest;
  }
}
