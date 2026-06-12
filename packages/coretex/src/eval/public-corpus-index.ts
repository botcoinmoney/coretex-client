/**
 * PublicCorpusIndex — the label-free retrieval surface used by stage-1 of
 * the substrate-hardened scorer.
 *
 * Spec: specs/substrate_retrieval_semantics.md and
 * specs/coretex_memory_control_plane.md.
 *
 * Anti-cheat boundary, by type:
 *   - PublicCorpusIndex contains only doc id + event id + embedding + public doc text.
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
  readonly text: string;
}

export type FirstStageMode = 'dense' | 'lexical' | 'hybrid';

export interface FirstStageRetrievalOptions {
  readonly mode?: FirstStageMode;
  readonly denseWeight?: number;
  readonly lexicalWeight?: number;
}

interface LexicalPosting {
  readonly idx: number;
  readonly tf: number;
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
  readonly lexicalPostings: ReadonlyMap<string, readonly LexicalPosting[]>;
  readonly lexicalIdf: ReadonlyMap<string, number>;
  readonly lexicalDocLengths: Float32Array;
  readonly lexicalAvgDocLength: number;
  readonly indexHash: string; // sha256 of canonical id list — for replay attestation
}

export function publicTextTokens(text: string): readonly string[] {
  return (text.toLowerCase().match(/[a-z0-9]+/g) ?? []).filter((t) => t.length > 1);
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
      lexicalPostings: new Map(),
      lexicalIdf: new Map(),
      lexicalDocLengths: new Float32Array(0),
      lexicalAvgDocLength: 0,
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
      seen.set(truth.id, { id: truth.id, eventId: event.id, embedding: emb, text: truth.text });
    }
    for (const neg of event.hardNegatives) {
      if (seen.has(neg.id)) continue;
      const emb = event.embeddings.perNegative.get(neg.id);
      if (!emb) continue;
      seen.set(neg.id, { id: neg.id, eventId: event.id, embedding: emb, text: neg.text });
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
  const lexicalDocLengths = new Float32Array(docs.length);
  let lexicalLengthSum = 0;
  const postingBuilders = new Map<string, LexicalPosting[]>();
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

    const tokens = publicTextTokens(docs[i]!.text);
    lexicalDocLengths[i] = tokens.length;
    lexicalLengthSum += tokens.length;
    const tf = new Map<string, number>();
    for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
    for (const [t, f] of tf) {
      let arr = postingBuilders.get(t);
      if (!arr) { arr = []; postingBuilders.set(t, arr); }
      arr.push({ idx: i, tf: f });
    }
  }
  const lexicalPostings = new Map<string, readonly LexicalPosting[]>();
  const lexicalIdf = new Map<string, number>();
  for (const [token, postings] of postingBuilders) {
    lexicalPostings.set(token, postings);
    lexicalIdf.set(token, Math.log(1 + (docs.length - postings.length + 0.5) / (postings.length + 0.5)));
  }
  const lexicalAvgDocLength = docs.length > 0 ? lexicalLengthSum / docs.length : 0;

  // Hybrid retrieval uses public doc text, so index attestation must bind text bytes
  // as well as doc ids. This remains label-free: no qrels or relevance enter stage-1.
  const idsConcat = docs.map((d) => `${d.id}\t${createHash('sha256').update(d.text).digest('hex')}`).join('\n');
  const indexHash = `0x${createHash('sha256').update(idsConcat).digest('hex')}`;

  return {
    biEncoderModelId: corpus.biEncoderModelId,
    biEncoderRevision: corpus.biEncoderRevision,
    layout,
    docs,
    denseEmbeddings: dense,
    denseInvNorms: invNorms,
    lexicalPostings,
    lexicalIdf,
    lexicalDocLengths,
    lexicalAvgDocLength,
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

export function lexicalFirstStageCandidates(
  queryText: string,
  index: PublicCorpusIndex,
  k: number,
): readonly PublicCorpusDoc[] {
  return lexicalFirstStageScored(queryText, index, k).map((s) => index.docs[s.idx]!);
}

export function retrieveFirstStageCandidates(
  queryText: string,
  queryVec: Float32Array,
  index: PublicCorpusIndex,
  k: number,
  opts: FirstStageRetrievalOptions = {},
): readonly PublicCorpusDoc[] {
  const mode = opts.mode ?? 'dense';
  if (mode === 'dense') return firstStageCandidates(queryVec, index, k);
  if (mode === 'lexical') return lexicalFirstStageCandidates(queryText, index, k);
  return hybridFirstStageScored(queryText, queryVec, index, k, opts).map((s) => index.docs[s.idx]!);
}

function lexicalFirstStageScored(
  queryText: string,
  index: PublicCorpusIndex,
  k: number,
): readonly { idx: number; score: number }[] {
  if (k <= 0 || index.docs.length === 0) return [];
  const k1 = 1.2;
  const b = 0.75;
  const scores = new Map<number, number>();
  for (const token of new Set(publicTextTokens(queryText))) {
    const postings = index.lexicalPostings.get(token);
    if (!postings) continue;
    const idf = index.lexicalIdf.get(token) ?? 0;
    for (const p of postings) {
      const dl = index.lexicalDocLengths[p.idx] ?? 0;
      const denom = p.tf + k1 * (1 - b + b * dl / Math.max(1, index.lexicalAvgDocLength));
      const score = idf * (p.tf * (k1 + 1)) / denom;
      scores.set(p.idx, (scores.get(p.idx) ?? 0) + score);
    }
  }
  return [...scores.entries()]
    .sort((a, b) => {
      if (b[1] !== a[1]) return b[1] - a[1];
      return index.docs[a[0]]!.id < index.docs[b[0]]!.id ? -1 : 1;
    })
    .slice(0, k)
    .map(([idx, score]) => ({ idx, score }));
}

function hybridFirstStageScored(
  queryText: string,
  queryVec: Float32Array,
  index: PublicCorpusIndex,
  k: number,
  opts: FirstStageRetrievalOptions,
): readonly { idx: number; score: number }[] {
  if (k <= 0 || index.docs.length === 0) return [];
  const denseWeight = opts.denseWeight ?? 1;
  const lexicalWeight = opts.lexicalWeight ?? 1;
  const dense = denseFirstStageScored(queryVec, index, k);
  const lexical = lexicalFirstStageScored(queryText, index, k);
  const scores = new Map<number, number>();
  const addNormalized = (items: readonly { idx: number; score: number }[], weight: number) => {
    if (items.length === 0 || weight === 0) return;
    const min = items[items.length - 1]!.score;
    const max = items[0]!.score;
    const span = max - min;
    for (const it of items) {
      const norm = span > 0 ? (it.score - min) / span : 1;
      scores.set(it.idx, (scores.get(it.idx) ?? 0) + weight * norm);
    }
  };
  addNormalized(dense, denseWeight);
  addNormalized(lexical, lexicalWeight);
  return [...scores.entries()]
    .sort((a, b) => {
      if (b[1] !== a[1]) return b[1] - a[1];
      return index.docs[a[0]]!.id < index.docs[b[0]]!.id ? -1 : 1;
    })
    .slice(0, k)
    .map(([idx, score]) => ({ idx, score }));
}

function denseFirstStageScored(
  queryVec: Float32Array,
  index: PublicCorpusIndex,
  k: number,
): readonly { idx: number; score: number }[] {
  if (k <= 0 || index.docs.length === 0) return [];
  const dim = index.layout.dim;
  const dense = index.denseEmbeddings;
  const invNorms = index.denseInvNorms;
  const docs = index.docs;
  const n = docs.length;
  let qNormSq = 0;
  for (let i = 0; i < queryVec.length; i++) qNormSq += queryVec[i]! * queryVec[i]!;
  const invQNorm = qNormSq > 0 ? 1 / Math.sqrt(qNormSq) : 0;
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
  return heap
    .sort((a, b) => {
      if (b.cos !== a.cos) return b.cos - a.cos;
      return docs[a.idx]!.id < docs[b.idx]!.id ? -1 : 1;
    })
    .map((h) => ({ idx: h.idx, score: h.cos }));
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
