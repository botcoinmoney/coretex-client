/**
 * CoreTex production corpus — retrieval-benchmark shape.
 *
 * Spec: specs/corpus_retrieval.md.
 *
 * This is the production corpus shape. The previous slot-fill ProductionCorpus
 * (event ledger with structural-commitment scoring) is gone. The retrieval
 * corpus carries graded qrels, splits, embeddings, and provenance.
 *
 * Loading and root computation are deterministic and reproducible from the
 * pinned bundle.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, openSync, readSync, closeSync, fstatSync } from 'node:fs';

import { keccak256 } from '../state/keccak256.js';
import { bytesToHex } from '../state/merkle.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export type ProductionCorpusFamily =
  | 'near_collision'
  | 'temporal'
  | 'long_horizon'
  | 'multi_hop_relation'
  // r5 operation families — first-class buckets (previously collapsed into near_collision) so
  // per-family quotas/metrics can isolate them. The scorer applies no family-specific behaviour to
  // these (only temporal / multi_hop_relation have special handling), so de-collapsing changes
  // metrics/quotas only, not scoring — but it DOES change event.family → corpusRoot (regen-gated).
  | 'conflict_lifecycle'
  | 'aspect_constraint'
  | 'coreference';

export type CorpusSplit = 'train_visible' | 'calibration' | 'eval_hidden' | 'canary';

export type RelationEdgeType =
  | 'supports'
  | 'supersedes'
  | 'coreference_of'
  | 'causes'
  | 'derived_from'
  | 'co_occurs_with';

export type GradedRelevance = 0.0 | 0.2 | 0.4 | 0.6 | 0.8 | 1.0;

const VALID_GRADED_RELEVANCE: ReadonlySet<number> = new Set([0.0, 0.2, 0.4, 0.6, 0.8, 1.0]);
/**
 * Runtime guard for the graded-relevance contract. The TS type does not validate at load time,
 * so an off-scale grade (e.g. the historical bridge `0.5`) would silently load and feed nDCG with
 * an out-of-contract gain. Throws on any value not in {0,0.2,0.4,0.6,0.8,1.0}.
 */
export function assertGradedRelevance(value: number, ctx = 'qrel'): GradedRelevance {
  if (!VALID_GRADED_RELEVANCE.has(value)) {
    throw new RangeError(`${ctx}: relevance ${value} is off the GradedRelevance scale {0,0.2,0.4,0.6,0.8,1.0}`);
  }
  return value as GradedRelevance;
}

export interface TruthDocument {
  readonly id: string;
  readonly text: string;
  readonly isCurrent: boolean;
  /** PUBLIC multi-aspect tags (aspect_constraint surface, A100 candidate). Construction-time public
   *  structure, NEVER a qrel. Used only by the default-off aspect-intent boost. Optional/back-compat. */
  readonly aspectTags?: readonly string[];
}

export interface QrelEntry {
  readonly documentId: string;
  readonly relevance: GradedRelevance;
}

export interface TemporalAnnotation {
  readonly validFromEpoch: number;
  readonly validUntilEpoch: number;     // 2^53-1 == open
  readonly currentStaleFlag: boolean;
  readonly supersedes_id?: string;
  readonly superseded_by_id?: string;
}

export interface RelationAnnotation {
  readonly other_id: string;
  readonly edgeType: RelationEdgeType;
  /** PUBLIC continuity label (e.g. `contradicts` / `scope_differs` / `supersedes`) the routing edgeType
   *  buckets into. Preserved on production relations so conflict DIRECTION is miner-visible + attested
   *  (in corpusRoot) even when miners receive only production events, not the raw logical corpus. */
  readonly label?: string;
}

export type ProvenanceSource = 'dataset_v2_direct' | 'hf_export' | 'synthetic_challenge';

export interface Provenance {
  readonly source: ProvenanceSource;
  readonly s3Key?: string;
  readonly challengeSeed?: string;       // hex-encoded uint128
  readonly challengeId?: string;
  readonly attemptId?: string;
  readonly sessionId?: string;
  readonly pairId?: string;
  readonly questionId?: string;
  readonly sourceHash: string;           // bytes32 hex
}

export interface RetrievalKeyLayout {
  readonly dim: number;
  readonly quantization: 'int8' | 'bf16';
  readonly headerBytes: number;
}

export interface EmbeddingPayload {
  readonly modelId: string;
  readonly revision: string;
  readonly layout: RetrievalKeyLayout;
  /** Per-record query embedding bytes (length === dim × bytesPerScalar). */
  readonly query: Uint8Array;
  /** Per truth document id → embedding bytes. */
  readonly perTruth: ReadonlyMap<string, Uint8Array>;
  /** Per hard-negative document id → embedding bytes. */
  readonly perNegative: ReadonlyMap<string, Uint8Array>;
}

/**
 * Hard-negative category emitted by the corpus generator at construction
 * time. Optional for backwards compatibility with pre-category corpora
 * (the previous MemReranker-4B-labeled corpus shape does not carry this
 * field). When present, `qrels` relevance for the hard negative is
 * derived from the bundle's `negCategoryRelevanceMap[category]`.
 */
export type HardNegativeCategory =
  | 'near_collision_entity'
  | 'near_collision_attribute'
  | 'temporal_stale'
  | 'trap'
  | 'lexical_distractor'
  | 'relation_neighbor'
  | 'unrelated';

export interface HardNegativeRecord {
  readonly id: string;
  readonly text: string;
  readonly category?: HardNegativeCategory;
  /** PUBLIC multi-aspect tags (see TruthDocument.aspectTags). Optional/back-compat. */
  readonly aspectTags?: readonly string[];
}

/**
 * Proposer-visible entity record. Public corpus metadata: the canonical name
 * and surface aliases a query can mention. The scorer's query-text entity
 * resolver (Layer-8 scale-aware seeding) matches `queryText` against these to
 * resolve the query's SUBJECT entity. Strictly construction-time / public —
 * NOT a hidden label. Aliases deliberately collide (reused first names) so
 * resolution is many-to-one and the reranker still disambiguates.
 */
export interface CorpusEntity {
  readonly id: string;
  readonly canonicalName: string;
  readonly aliases: readonly string[];
}

export interface ProductionCorpusEvent {
  readonly id: string;
  readonly family: ProductionCorpusFamily;
  readonly domain: string;
  readonly split: CorpusSplit;
  readonly queryText: string;
  readonly truthDocuments: readonly TruthDocument[];
  readonly hardNegatives: readonly HardNegativeRecord[];
  readonly qrels: readonly QrelEntry[];
  readonly protected: boolean;
  readonly temporal?: TemporalAnnotation;
  readonly relations?: readonly RelationAnnotation[];
  /**
   * Proposer-visible entity tags for this event's truth docs. Public corpus
   * metadata (the entity the memory is ABOUT), used by query-text entity
   * seeding to scope candidate expansion to the resolved subject entity's
   * memory neighborhood. Optional for backward compatibility — corpora that
   * predate entity tagging omit it (the key is absent, so it does not change
   * the canonical event hash / corpusRoot). NEVER an answer pointer: the
   * resolver reads `queryText` + the public entity table, never qrels.
   */
  readonly entityIds?: readonly string[];
  /**
   * PUBLIC retrieval scope for a query event: the owner entity whose memory
   * store this query searches (the session/user/project context a real memory
   * system always has). Set at corpus-generation time, NEVER inferred from
   * qrels/gold. When `ownerScoped` is true the scorer restricts stage-1 +
   * relation seeding to this owner's store — the realistic, well-posed task
   * (avoids the pooled subject-ambiguity that makes first-name queries
   * ~80-way ambiguous at scale). `ownerScoped=false` for cross-entity-by-design
   * families (entity_disambiguation, abstention) which must stay pooled.
   * Optional/back-compat: absent → unscoped (full-pool) behavior.
   */
  readonly ownerEntityId?: string;
  readonly ownerScoped?: boolean;
  /**
   * PUBLIC subject entity id this query is ABOUT (the one entity the answer concerns), set at
   * corpus-generation time from generator structure, NEVER from qrels/gold. Distinct from
   * `ownerEntityId` (the owner/universe scope): at scale a single owner holds many subjects whose
   * canonical names collide (112-way at 300k), so name-text resolution floods r5 policy admission.
   * This is the exact, collision-proof grounding the selector uses (see `resolveQuerySubjects`).
   * Optional/back-compat: absent → fail-closed name-text fallback.
   */
  readonly subjectEntityId?: string;
  readonly provenance: Provenance;
  readonly embeddings: EmbeddingPayload;
  /**
   * Synthesis-time depth of the longest causal / temporal / derivation
   * chain leading to this record. Optional for backward compatibility
   * with corpora that predate the depth-stratification hardening — old
   * records default to depth 1 (treated as "no causal chain") in
   * `strataOf`. New corpora generated by the challenge-library bridge
   * should populate this from the session-pair / bookend structure.
   *
   * Pinned by the synthesizer, never inferred post-hoc from edge count.
   */
  readonly causalDepth?: number;
  /**
   * Synthesis-time maximum relation-graph distance from any truth
   * document to the query. Optional for backward compatibility — old
   * records default to 1 in `strataOf`. New `multi_hop_relation`
   * records should populate this from the actual relation chain length
   * the synthesizer produced.
   */
  readonly relationHopDepth?: number;
  /**
   * Synthesis-time hidden-eval difficulty band ∈
   * {easy, medium, hard, very_hard, exhaustion}. Pinned by the generator
   * (DGEN-1) from the query's structural difficulty (revision depth, distractor
   * density, exhaustion probes). Optional for backward compatibility — old
   * records have no band and fall back to the qrel-derived hardness bucket in
   * `strataOf`. Used to make hidden-pack selection difficulty-aware (band quotas
   * + epoch band-progression), not just labeled.
   */
  readonly band?: 'easy' | 'medium' | 'hard' | 'very_hard' | 'exhaustion';
  /**
   * Realism slice tag for relation queries: 'distant' = answer is maximally
   * lexically-distant from the subject (routing strictly required); 'partial' =
   * answer carries a weak subject reference (reachable via edge AND partially
   * retrievable). Lets surfacing metrics report whether relation lift generalizes
   * off the most-adversarial end rather than only at it.
   */
  readonly grounding?: 'distant' | 'partial';
}

export interface ProductionCorpus {
  readonly events: readonly ProductionCorpusEvent[];
  readonly byId: ReadonlyMap<string, ProductionCorpusEvent>;
  /**
   * Proposer-visible entity table (canonicalName + aliases). Optional. Does
   * NOT participate in `corpusRoot` (only events are hashed) — it is public
   * resolver metadata, not Merkle-committed corpus content. Consumed by the
   * scorer's query-text entity resolver for scale-aware seeding.
   */
  readonly entities?: readonly CorpusEntity[];
  readonly corpusRoot: string;            // bytes32 hex
  readonly corpusEpoch: number;
  readonly biEncoderRevision: string;
  readonly biEncoderModelId: string;
  readonly biEncoderRetrievalKeyLayout: RetrievalKeyLayout;
  readonly labelingModelRevision: string;
  readonly labelingModelId: string;
}

// ─── Split ratios ─────────────────────────────────────────────────────────────

export interface SplitRatios {
  readonly trainVisiblePct: number;
  readonly calibrationPct: number;
  readonly evalHiddenPct: number;
  readonly canaryPct: number;
}

export const DEFAULT_SPLIT_RATIOS: SplitRatios = {
  trainVisiblePct: 70,
  calibrationPct: 10,
  evalHiddenPct: 15,
  canaryPct: 5,
};

/**
 * Deterministic split for a record id at a given corpus epoch. Stable across
 * deltas so a record's split never changes.
 */
export function splitForRecord(id: string, corpusEpoch: number, ratios: SplitRatios = DEFAULT_SPLIT_RATIOS): CorpusSplit {
  const total = ratios.trainVisiblePct + ratios.calibrationPct + ratios.evalHiddenPct + ratios.canaryPct;
  if (total !== 100) throw new Error(`SplitRatios must sum to 100, got ${total}`);
  const enc = new TextEncoder();
  const u64 = new Uint8Array(8);
  let v = BigInt(corpusEpoch);
  for (let i = 7; i >= 0; i--) {
    u64[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const idBytes = enc.encode(id);
  const buf = new Uint8Array(idBytes.length + 8);
  buf.set(idBytes, 0);
  buf.set(u64, idBytes.length);
  const digest = keccak256(buf);
  // first 8 bytes → uint64
  let h = 0n;
  for (let i = 0; i < 8; i++) h = (h << 8n) | BigInt(digest[i]!);
  const bucket = Number(h % 100n);
  if (bucket < ratios.trainVisiblePct) return 'train_visible';
  if (bucket < ratios.trainVisiblePct + ratios.calibrationPct) return 'calibration';
  if (bucket < ratios.trainVisiblePct + ratios.calibrationPct + ratios.evalHiddenPct) return 'eval_hidden';
  return 'canary';
}

/**
 * Canonical EXPECTED split for a production event, the single authority that delta/load validation must
 * use. The production corpus overloads two event kinds with DIFFERENT split semantics:
 *   - MEMORY-DOCUMENT events (the public retrieval store; `mem_*` ids) are ALWAYS `train_visible` — they
 *     are stored memories, never hidden eval queries;
 *   - QUERY/eval events use the deterministic `splitForRecord` assignment (which queries are hidden).
 * Validating EVERY event with `splitForRecord` (the prior bug) rejected legitimate `mem_*` docs (they are
 * train_visible, not their hashed split). The `mem_` prefix is part of the event id (hashed into
 * corpusRoot), so this rule is deterministic + replay-verifiable. Live-update memory docs added via a
 * corpus delta must therefore be `mem_*` + `train_visible`.
 */
export function expectedSplitForRecord(id: string, corpusEpoch: number, ratios: SplitRatios = DEFAULT_SPLIT_RATIOS): CorpusSplit {
  return id.startsWith('mem_') ? 'train_visible' : splitForRecord(id, corpusEpoch, ratios);
}

// ─── Canonical hashing ────────────────────────────────────────────────────────

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'undefined') return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'string') return JSON.stringify(value);
  if (value instanceof Uint8Array) return JSON.stringify(uint8ToHex(value));
  if (value instanceof Map) {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of value) obj[String(k)] = v;
    return canonicalJson(obj);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
}

function uint8ToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function hexToUint8(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('hexToUint8: odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Read corpus-level metadata from a v1 corpus JSON without loading the whole
 * file. The generator's writeCorpusOutputStreaming splits metadata across the
 * file: fields written BEFORE the `events` array (`schemaVersion`,
 * `corpusEpoch`, `source`, `challengeLibrary`, `biEncoder`, `labelingModel`)
 * live in the head; fields written AFTER the events-array close (`corpusRoot`,
 * any future trailing metadata) live in the trailer. Read both windows.
 */
function readCorpusJsonHeader(path: string): Record<string, unknown> {
  const HEAD_BYTES = 64 * 1024;
  const TAIL_BYTES = 32 * 1024;
  const fd = openSync(path, 'r');
  let head: string;
  let tail: string;
  let fileSize: number;
  try {
    const headBuf = Buffer.alloc(HEAD_BYTES);
    const headN = readSync(fd, headBuf, 0, headBuf.length, 0);
    head = headBuf.toString('utf8', 0, headN);
    // fstatSync via the fd to avoid an extra syscall.
    fileSize = fstatSync(fd).size;
    const tailLen = Math.min(TAIL_BYTES, fileSize);
    const tailStart = fileSize - tailLen;
    const tailBuf = Buffer.alloc(tailLen);
    const tailN = readSync(fd, tailBuf, 0, tailBuf.length, tailStart);
    tail = tailBuf.toString('utf8', 0, tailN);
  } finally {
    closeSync(fd);
  }

  const eventsIdx = head.indexOf('"events"');
  if (eventsIdx < 0) {
    throw new Error(
      `readCorpusJsonHeader: "events" key not found in first ${HEAD_BYTES} bytes of ${path}; ` +
      `not a streaming-shape v1 corpus`,
    );
  }
  const preTrimmed = head.slice(0, eventsIdx).replace(/,\s*$/, '');
  const preMeta = JSON.parse(`${preTrimmed},"events":[]}`) as Record<string, unknown>;

  // Parse post-events trailing metadata. Find `],` (events-array close + comma
  // before the next top-level key). Take the substring after `,`, wrap in `{}`,
  // parse. The trailer string ends with `\n}` of the outer object; preserve it.
  const closeIdx = tail.lastIndexOf('],');
  if (closeIdx < 0) return preMeta; // no trailing metadata
  const trailerInner = tail.slice(closeIdx + 2).trim().replace(/,?\s*$/, '');
  // trailerInner now looks like: `\n  "corpusRoot": "0x...",\n  ...,\n}` or
  // similar; strip the closing `}` so we can wrap into a fresh object.
  const stripped = trailerInner.endsWith('}') ? trailerInner.slice(0, -1).replace(/,?\s*$/, '') : trailerInner;
  let postMeta: Record<string, unknown> = {};
  try {
    postMeta = JSON.parse(`{${stripped}}`) as Record<string, unknown>;
  } catch (err) {
    throw new Error(
      `readCorpusJsonHeader: failed to parse trailing metadata window: ${(err as Error).message}; ` +
      `trailer snippet: ${stripped.slice(0, 200)}...`,
    );
  }
  return { ...preMeta, ...postMeta };
}

/**
 * Stream-read a corpus events NDJSON into the in-memory event array. Uses
 * chunked sync reads to stay well under V8's 512 MB single-string cap; the
 * resulting JS objects can fit in any reasonable heap because the
 * embeddings convert from hex to compact Uint8Array per line.
 */
function streamProductionCorpusEvents(ndjsonPath: string): ProductionCorpusEvent[] {
  const fd = openSync(ndjsonPath, 'r');
  const events: ProductionCorpusEvent[] = [];
  try {
    const bufSize = 64 * 1024 * 1024; // 64 MB chunks
    const buf = Buffer.alloc(bufSize);
    let pending = '';
    while (true) {
      const bytesRead = readSync(fd, buf, 0, bufSize, null);
      if (bytesRead <= 0) break;
      pending += buf.toString('utf8', 0, bytesRead);
      let nl: number;
      while ((nl = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, nl);
        pending = pending.slice(nl + 1);
        if (!line) continue;
        events.push(parseEventLine(line));
      }
    }
    if (pending.length > 0) events.push(parseEventLine(pending));
  } finally {
    closeSync(fd);
  }
  return events;
}

function parseEventLine(line: string): ProductionCorpusEvent {
  const e = JSON.parse(line) as {
    embeddings: {
      modelId: string;
      revision: string;
      layout: RetrievalKeyLayout;
      query: string;
      perTruth: Record<string, string>;
      perNegative: Record<string, string>;
    };
  } & Omit<ProductionCorpusEvent, 'embeddings'>;
  for (const q of e.qrels) assertGradedRelevance(q.relevance, `event ${e.id} qrel ${q.documentId}`);
  return {
    ...e,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: hexToUint8(e.embeddings.query),
      perTruth: new Map(Object.entries(e.embeddings.perTruth).map(([k, v]) => [k, hexToUint8(v)])),
      perNegative: new Map(Object.entries(e.embeddings.perNegative).map(([k, v]) => [k, hexToUint8(v)])),
    },
  };
}

/**
 * Compute the canonical corpus root by Merkleizing per-record canonical-JSON
 * leaves under keccak256.
 */
export function computeCorpusRoot(events: readonly ProductionCorpusEvent[]): string {
  if (events.length === 0) return '0x' + '00'.repeat(32);
  const sorted = [...events].sort((a, b) => a.id.localeCompare(b.id));
  let leaves = sorted.map((event) => {
    // Canonical-JSON of the full event (embeddings serialize as hex strings via canonicalJson).
    const enc = new TextEncoder();
    return keccak256(enc.encode(canonicalJson(event)));
  });
  const zero = new Uint8Array(32);
  let n = 1;
  while (n < leaves.length) n <<= 1;
  while (leaves.length < n) leaves.push(zero);
  while (leaves.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < leaves.length; i += 2) {
      const pair = new Uint8Array(64);
      pair.set(leaves[i]!, 0);
      pair.set(leaves[i + 1]!, 32);
      next.push(keccak256(pair));
    }
    leaves = next;
  }
  return bytesToHex(leaves[0]!);
}

// ─── Loader ───────────────────────────────────────────────────────────────────

export interface CorpusFileShape {
  readonly schemaVersion: 'coretex.production-corpus.v1';
  readonly corpusEpoch: number;
  readonly biEncoder: { readonly modelId: string; readonly revision: string; readonly layout: RetrievalKeyLayout };
  readonly labelingModel: { readonly modelId: string; readonly revision: string };
  readonly events: readonly ProductionCorpusEventOnDisk[];
  /** Proposer-visible entity table; optional, not part of corpusRoot. */
  readonly entities?: readonly CorpusEntity[];
  readonly corpusRoot: string;
}

export interface ProductionCorpusEventOnDisk
  extends Omit<ProductionCorpusEvent, 'embeddings' | 'hardNegatives' | 'qrels' | 'truthDocuments' | 'relations'> {
  readonly truthDocuments: readonly TruthDocument[];
  readonly hardNegatives: readonly HardNegativeRecord[];
  readonly qrels: readonly QrelEntry[];
  readonly relations?: readonly RelationAnnotation[];
  readonly embeddings: {
    readonly modelId: string;
    readonly revision: string;
    readonly layout: RetrievalKeyLayout;
    readonly query: string;                        // hex
    readonly perTruth: Record<string, string>;     // id -> hex
    readonly perNegative: Record<string, string>;  // id -> hex
  };
}

export interface LoadProductionCorpusOptions {
  /**
   * Skip the on-load Merkle re-verification (`computeCorpusRoot`). At launch
   * scale (≈679 k events) this is a ~20 minute compute that the generator
   * has already performed once at finalize time. Post-corpus scripts that
   * load the same file multiple times across separate processes set this
   * to `false` to avoid paying the cost on every load. Default `true`
   * preserves the existing invariant check.
   */
  readonly verifyCorpusRoot?: boolean;
  /**
   * Skip the per-event `splitForRecord` cross-check. Same rationale as
   * `verifyCorpusRoot` — the generator already enforced this. Default `true`.
   */
  readonly verifySplits?: boolean;
}

export function loadProductionCorpus(path: string, options: LoadProductionCorpusOptions = {}): ProductionCorpus {
  if (!existsSync(path)) throw new Error(`production corpus file not found: ${path}`);
  const verifyCorpusRoot = options.verifyCorpusRoot ?? true;
  const verifySplits = options.verifySplits ?? true;

  // Launch-scale corpora exceed V8's 512 MB single-string cap, so
  // JSON.parse(readFileSync(...)) is unusable on the full file. Two paths:
  //
  //   1) Sidecar NDJSON present  →  read metadata from the JSON header
  //      (first 32 KB is plenty; "events" key always comes after metadata
  //      in writeCorpusOutputStreaming output), then stream the NDJSON
  //      one event per line. Memory cost: one event at a time during
  //      parsing, then the assembled events array.
  //
  //   2) No sidecar               →  fall back to whole-file JSON.parse.
  //      Works for small/previous corpora (< ~400 MB) only.
  const ndjsonPath = `${path}.events.ndjson`;
  let raw: CorpusFileShape;
  let events: ProductionCorpusEvent[];

  if (existsSync(ndjsonPath)) {
    const meta = readCorpusJsonHeader(path) as Omit<CorpusFileShape, 'events'>;
    raw = { ...meta, events: [] } as CorpusFileShape;
    if (raw.schemaVersion !== 'coretex.production-corpus.v1') {
      throw new Error(`production corpus has unsupported schemaVersion: ${raw.schemaVersion}`);
    }
    events = streamProductionCorpusEvents(ndjsonPath);
  } else {
    raw = JSON.parse(readFileSync(path, 'utf8')) as CorpusFileShape;
    if (raw.schemaVersion !== 'coretex.production-corpus.v1') {
      throw new Error(`production corpus has unsupported schemaVersion: ${raw.schemaVersion}`);
    }
    events = raw.events.map((e) => ({
      ...e,
      embeddings: {
        modelId: e.embeddings.modelId,
        revision: e.embeddings.revision,
        layout: e.embeddings.layout,
        query: hexToUint8(e.embeddings.query),
        perTruth: new Map(Object.entries(e.embeddings.perTruth).map(([k, v]) => [k, hexToUint8(v)])),
        perNegative: new Map(Object.entries(e.embeddings.perNegative).map(([k, v]) => [k, hexToUint8(v)])),
      },
    }));
  }
  if (verifyCorpusRoot) {
    const computed = computeCorpusRoot(events);
    if (computed.toLowerCase() !== raw.corpusRoot.toLowerCase()) {
      throw new Error(`production corpus root mismatch: expected ${raw.corpusRoot} got ${computed}`);
    }
  }
  if (verifySplits) {
    // Verify per-event split assignment is stable.
    for (const e of events) {
      const expected = expectedSplitForRecord(e.id, raw.corpusEpoch);
      if (e.split !== expected) {
        throw new Error(`production corpus event ${e.id} declared split ${e.split} but expectedSplitForRecord returned ${expected}`);
      }
    }
  }
  // Verify embeddings model id/revision matches the bundle bi-encoder.
  // This is a fast O(n) loop, kept unconditional — protects against silent
  // bundle/corpus mismatch which is a launch-blocking class of bug.
  for (const e of events) {
    if (e.embeddings.modelId !== raw.biEncoder.modelId || e.embeddings.revision !== raw.biEncoder.revision) {
      throw new Error(`production corpus event ${e.id} embeddings model mismatch`);
    }
  }
  return {
    events,
    byId: new Map(events.map((e) => [e.id, e])),
    ...(raw.entities !== undefined ? { entities: raw.entities } : {}),
    corpusRoot: raw.corpusRoot.toLowerCase(),
    corpusEpoch: raw.corpusEpoch,
    biEncoderModelId: raw.biEncoder.modelId,
    biEncoderRevision: raw.biEncoder.revision,
    biEncoderRetrievalKeyLayout: raw.biEncoder.layout,
    labelingModelId: raw.labelingModel.modelId,
    labelingModelRevision: raw.labelingModel.revision,
  };
}

export function serializeProductionCorpus(corpus: ProductionCorpus): CorpusFileShape {
  const events: ProductionCorpusEventOnDisk[] = corpus.events.map((e) => ({
    id: e.id,
    family: e.family,
    domain: e.domain,
    split: e.split,
    queryText: e.queryText,
    truthDocuments: e.truthDocuments,
    hardNegatives: e.hardNegatives,
    qrels: e.qrels,
    protected: e.protected,
    ...(e.temporal !== undefined ? { temporal: e.temporal } : {}),
    ...(e.relations !== undefined ? { relations: e.relations } : {}),
    ...(e.entityIds !== undefined ? { entityIds: e.entityIds } : {}),
    ...(e.ownerEntityId !== undefined ? { ownerEntityId: e.ownerEntityId } : {}),
    ...(e.ownerScoped !== undefined ? { ownerScoped: e.ownerScoped } : {}),
    ...(e.subjectEntityId !== undefined ? { subjectEntityId: e.subjectEntityId } : {}),
    provenance: e.provenance,
    embeddings: {
      modelId: e.embeddings.modelId,
      revision: e.embeddings.revision,
      layout: e.embeddings.layout,
      query: uint8ToHex(e.embeddings.query),
      perTruth: Object.fromEntries(Array.from(e.embeddings.perTruth.entries()).map(([k, v]) => [k, uint8ToHex(v)])),
      perNegative: Object.fromEntries(Array.from(e.embeddings.perNegative.entries()).map(([k, v]) => [k, uint8ToHex(v)])),
    },
  }));
  return {
    schemaVersion: 'coretex.production-corpus.v1',
    corpusEpoch: corpus.corpusEpoch,
    biEncoder: {
      modelId: corpus.biEncoderModelId,
      revision: corpus.biEncoderRevision,
      layout: corpus.biEncoderRetrievalKeyLayout,
    },
    labelingModel: {
      modelId: corpus.labelingModelId,
      revision: corpus.labelingModelRevision,
    },
    events,
    ...(corpus.entities !== undefined ? { entities: corpus.entities } : {}),
    corpusRoot: corpus.corpusRoot,
  };
}

// ─── SHA-256 helper ───────────────────────────────────────────────────────────

export function corpusFileSha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export { canonicalJson as canonicalJsonForCorpus };
