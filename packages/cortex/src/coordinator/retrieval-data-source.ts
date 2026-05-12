/**
 * Coordinator data-source factory for the retrieval-benchmark endpoints.
 *
 * Spec: plan §Phase F.
 *
 * Wires:
 *   - GET /coretex/corpus/:id            (masks eval_hidden + canary)
 *   - GET /coretex/corpus/:id/embedding  (masks hidden until reveal)
 *   - GET /coretex/bundle/:bundleHash    (read-only)
 *   - POST /coretex/screen               (structural only)
 *   - POST /coretex/evaluate             (full retrieval scoring)
 *
 * Production wiring expects:
 *   - the loaded ProductionCorpus
 *   - the loaded CoreTexBundleManifest
 *   - the live evalSeed (only after reveal)
 *   - an evaluate callback that runs evaluateRetrievalBenchmarkPatch
 *   - a screen callback that runs structural validation only
 */

import type {
  CoreTexCoordinatorDataSource,
  CoreTexRouteGuardContext,
  CoreTexRouteGuardResult,
} from './endpoints.js';
import type { ProductionCorpus, ProductionCorpusEvent } from '../eval/retrieval-corpus.js';
import type { CoreTexBundleManifest } from '../bundle/index.js';

export interface RetrievalDataSourceOptions {
  readonly corpus: ProductionCorpus;
  readonly bundleManifest: CoreTexBundleManifest;
  readonly bundleHash: string;
  readonly screen: (body: unknown) => Promise<unknown> | unknown;
  readonly evaluate: (body: unknown) => Promise<unknown> | unknown;
  /**
   * Optional async variant of `evaluate`. When wired, POST
   * /coretex/evaluate-async returns `{status:'pending', patchHash,
   * targetBlock}` immediately; GET /coretex/result/:patchHash polls
   * until the in-background eval completes. Hosts that don't need
   * the async path leave both undefined.
   */
  readonly evaluateAsync?: (body: unknown) => Promise<unknown> | unknown;
  readonly getResult?: (patchHash: string) => Promise<unknown> | unknown;
  readonly getCurrentSubstrate?: () => Promise<unknown> | unknown;
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  readonly getPatch?: (hash: string) => Promise<unknown> | unknown;
  readonly getEvalReport?: (hash: string) => Promise<unknown> | unknown;
  readonly getChallengeBook?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getCorpusDelta?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getClientBundle?: (coreVersionHash: string) => Promise<unknown> | unknown;
  readonly authorize?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly rateLimit?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly health?: () => Promise<unknown> | unknown;
  /**
   * When true, calibration consumers (admin) can read the calibration split
   * payloads. Default false. Hidden + canary are always masked.
   */
  readonly allowCalibrationReads?: boolean;
}

const HIDDEN_SPLITS: ReadonlySet<string> = new Set(['eval_hidden', 'canary']);

export function createRetrievalDataSource(opts: RetrievalDataSourceOptions): CoreTexCoordinatorDataSource {
  const corpus = opts.corpus;
  const manifest = opts.bundleManifest;
  if (manifest.bundleHash.toLowerCase() !== opts.bundleHash.toLowerCase()) {
    throw new Error(`createRetrievalDataSource: bundle manifest hash ${manifest.bundleHash} != provided ${opts.bundleHash}`);
  }

  const ds: CoreTexCoordinatorDataSource = {
    async screen(body) { return sanitizeScreenResponse(await opts.screen(body)); },
    async evaluate(body) { return opts.evaluate(body); },
    async getCorpusRecord(recordId: string) {
      const event = corpus.byId.get(recordId);
      if (!event) return { error: 'coretex-corpus-not-found', recordId };
      if (HIDDEN_SPLITS.has(event.split)) {
        return { error: 'coretex-corpus-hidden', recordId, split: event.split };
      }
      if (event.split === 'calibration' && !opts.allowCalibrationReads) {
        return { error: 'coretex-corpus-calibration-restricted', recordId };
      }
      return serializePublicEvent(event);
    },
    async getCorpusRecordEmbedding(recordId: string) {
      const event = corpus.byId.get(recordId);
      if (!event) return { error: 'coretex-corpus-not-found', recordId };
      if (HIDDEN_SPLITS.has(event.split)) {
        return { error: 'coretex-embedding-hidden', recordId, split: event.split };
      }
      return serializeEmbeddings(event);
    },
    async getBundle(bundleHash: string) {
      if (bundleHash.toLowerCase() !== manifest.bundleHash.toLowerCase()) {
        return { error: 'coretex-bundle-not-found', bundleHash };
      }
      return manifest;
    },
  };
  if (opts.getCurrentSubstrate) (ds as Mutable).getCurrentSubstrate = opts.getCurrentSubstrate;
  if (opts.getSubstrate) (ds as Mutable).getSubstrate = opts.getSubstrate;
  if (opts.getPatch) (ds as Mutable).getPatch = opts.getPatch;
  if (opts.getEvalReport) (ds as Mutable).getEvalReport = opts.getEvalReport;
  if (opts.getChallengeBook) (ds as Mutable).getChallengeBook = opts.getChallengeBook;
  if (opts.getCorpusDelta) (ds as Mutable).getCorpusDelta = opts.getCorpusDelta;
  if (opts.getClientBundle) (ds as Mutable).getClientBundle = opts.getClientBundle;
  if (opts.rateLimit) (ds as Mutable).rateLimit = opts.rateLimit;
  if (opts.health) (ds as Mutable).health = opts.health;
  if (opts.evaluateAsync) (ds as Mutable).evaluateAsync = opts.evaluateAsync;
  if (opts.getResult) (ds as Mutable).getResult = opts.getResult;

  // POST /coretex/evaluate is live. The eval seed for each patch is
  // bound to a future Base blockhash via the per-patch on-chain
  // randomness design (docs/CORETEX_V4_ONCHAIN_RANDOMNESS_PLAN.md), so
  // coordinator pre-testing is structurally impossible. Anti-probing
  // is enforced by the dedup cache + per-miner cap inside the host's
  // evaluate callback (see real-evaluator.ts + live-eval-admission.ts).
  if (opts.authorize) (ds as Mutable).authorize = opts.authorize;
  return ds;
}

type Mutable = { -readonly [K in keyof CoreTexCoordinatorDataSource]: CoreTexCoordinatorDataSource[K] };

function serializePublicEvent(event: ProductionCorpusEvent): Record<string, unknown> {
  return {
    id: event.id,
    family: event.family,
    domain: event.domain,
    split: event.split,
    queryText: event.queryText,
    truthDocuments: event.truthDocuments,
    hardNegatives: event.hardNegatives,
    qrels: event.qrels,
    protected: event.protected,
    temporal: event.temporal,
    relations: event.relations,
    provenance: event.provenance,
  };
}

function serializeEmbeddings(event: ProductionCorpusEvent): Record<string, unknown> {
  return {
    id: event.id,
    modelId: event.embeddings.modelId,
    revision: event.embeddings.revision,
    layout: event.embeddings.layout,
    queryHex: bytesToHex(event.embeddings.query),
    perTruth: Object.fromEntries(
      Array.from(event.embeddings.perTruth.entries()).map(([k, v]) => [k, bytesToHex(v)]),
    ),
    perNegative: Object.fromEntries(
      Array.from(event.embeddings.perNegative.entries()).map(([k, v]) => [k, bytesToHex(v)]),
    ),
  };
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Strip the screen response to the structural-only shape declared in
 * the route docs: `{ pass: boolean, reasonCode?: string, receipt?: object }`.
 *
 * A miner-facing screen route MUST NOT leak retrieval-correlated
 * numbers — abstention rate, structural-floor margins, per-family
 * deltas, anything that lets a probe oracle reconstruct hidden-pack
 * distribution. The structural decision is binary; the reason code is
 * a fixed enum string. Anything else from the host callback is dropped.
 */
function sanitizeScreenResponse(raw: unknown): { pass: boolean; reasonCode?: string; receipt?: Record<string, unknown> } {
  if (!raw || typeof raw !== 'object') {
    return { pass: false, reasonCode: 'screen-malformed-response' };
  }
  const r = raw as Record<string, unknown>;
  const out: { pass: boolean; reasonCode?: string; receipt?: Record<string, unknown> } = {
    pass: r.pass === true,
  };
  if (typeof r.reasonCode === 'string') out.reasonCode = r.reasonCode;
  // The receipt sub-object is allowed but ONLY the structural signature
  // envelope — never per-query scores or family deltas. Hosts that
  // want to attach an EIP-712 receipt put it here; cortex never
  // synthesizes or inspects its contents beyond the type check.
  if (r.receipt && typeof r.receipt === 'object') out.receipt = r.receipt as Record<string, unknown>;
  return out;
}
