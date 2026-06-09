/**
 * CoreTex v0 launch-canonical miner-facing HTTP surface.
 *
 * The public CoreTex miner API has EXACTLY five endpoints:
 *
 *   GET  /coretex/health
 *   GET  /coretex/status?miner=0x…
 *   GET  /coretex/substrate/:stateRoot
 *   POST /coretex/submit
 *   GET  /coretex/receipt/:hash
 *
 * Everything else previously exposed (`/coretex/challenge`, `/coretex/patch/:hash`,
 * `/coretex/patch-received/:hash`, `/coretex/eval-report/:hash`,
 * `/coretex/corpus-delta/:epoch`, `/coretex/bundle/*`) is REMOVED for v0. Static
 * rules belong in `docs/BOTCOIN_CORETEX_MINER_SKILL.md`; dynamic per-epoch /
 * per-miner context belongs in `/coretex/status`; substrate is fetched by root.
 *
 * Adding a public CoreTex route requires updating CORETEX_ENDPOINTS here AND the
 * miner skill AND the API contract doc AND the gate in
 * `scripts/miner-api-contract-gate.mjs`. The gate fails the build if anything
 * drifts.
 */
export type CoreTexEndpointName =
  | 'health'
  | 'status'
  | 'substrate-by-root'
  | 'submit'
  | 'receipt-by-hash';

export interface CoreTexEndpoint {
  readonly name: CoreTexEndpointName;
  readonly method: 'GET' | 'POST';
  readonly path: string;
}

export const CORETEX_ENDPOINTS: readonly CoreTexEndpoint[] = [
  { name: 'health', method: 'GET', path: '/coretex/health' },
  { name: 'status', method: 'GET', path: '/coretex/status' },
  { name: 'substrate-by-root', method: 'GET', path: '/coretex/substrate/:stateRoot' },
  { name: 'submit', method: 'POST', path: '/coretex/submit' },
  { name: 'receipt-by-hash', method: 'GET', path: '/coretex/receipt/:hash' },
] as const;

export interface CoreTexHttpRequest {
  readonly method: string;
  readonly path: string;
  readonly body?: unknown;
  readonly headers?: Record<string, string | readonly string[] | undefined>;
  readonly remoteAddress?: string;
  /** Parsed query string (e.g. ?miner=0x…). Production routers pass req.query through. */
  readonly query?: Record<string, string | readonly string[] | undefined>;
}

export interface CoreTexHttpResponse {
  readonly handled: boolean;
  readonly status: number;
  readonly body: unknown;
}

export interface CoreTexRouteGuardContext {
  readonly endpoint: CoreTexEndpointName;
  readonly method: string;
  readonly path: string;
  readonly body?: unknown;
  readonly headers?: Record<string, string | readonly string[] | undefined>;
  readonly query?: Record<string, string | readonly string[] | undefined>;
  readonly remoteAddress?: string;
}

export type CoreTexRouteGuardResult =
  | void
  | boolean
  | {
      readonly ok?: boolean;
      readonly status?: number;
      readonly body?: unknown;
    };

/**
 * v0 production CoreTex coordinator data source.
 *
 * Five required methods + two optional guards (authorize, rateLimit). A
 * production data source MUST implement every method; the `notConfigured` 503
 * fallback exists so partial test stubs can mount the router during unit tests.
 */
export interface CoreTexCoordinatorDataSource {
  readonly authorize?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly rateLimit?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  /** Coordinator system health. NO miner-specific data. Includes
   *  `{version, epoch, chainId, confirmationDepth, chainLiveRoot, confirmedLiveRoot,
   *    finalityLagBlocks, epochPins, acceptingSubmissions, reason?}`. */
  readonly health?: () => Promise<unknown> | unknown;
  /** Per-miner dynamic context. `query.miner` is the miner address (lowercase). Returns
   *  `{epochId, currentStateRoot, confirmedTransitionCount, perMiner: {address,
   *    screenersThisEpoch, remaining, cap, nextIndex, lastReceiptHash}, perMinerScreenerCap,
   *    qualifiedScreenerPassesSinceLastStateAdvance, screenerThresholdPpm,
   *    minImprovementPpm, allowedPatchTypes, patchWordBudget, activeSubstrateSurfaces,
   *    acceptingSubmissions, bundleHash, coreVersionHash, corpusRoot, activeFrontierRoot}`. */
  readonly getStatus?: (query: Record<string, string | readonly string[] | undefined>) => Promise<unknown> | unknown;
  /** Packed substrate by confirmed state root. */
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  /** Accept a candidate patch. Body: `{patchBytesHex, parentStateRoot, minerAddress}`.
   *  Returns either a signed receipt envelope or a rejection. While an epoch
   *  cutover freeze is active the rejection code is `epoch_cutover_in_progress`;
   *  while a rotated context has no recomputed baseline it is
   *  `awaiting_baseline_recompute`. Rejection envelopes carry NO score
   *  telemetry (no deterministicDeltaPpm / requiredDeltaPpm or equivalent
   *  gradients) — the router passes responses through verbatim and MUST NOT
   *  decorate them. */
  readonly submit?: (body: unknown) => Promise<unknown> | unknown;
  /** Look up a previously signed receipt by patchHash. Lookup must work for BOTH
   *  the miner-submitted (original) hash AND the coordinator-rewritten signed hash.
   *  Returns `200 + envelope` for pending/confirmed (envelope tagged with state),
   *  `409 + PendingReceiptStale` for stale, `404` for expired/unknown. */
  readonly getReceipt?: (hash: string) => Promise<{ readonly status: number; readonly body: unknown } | null> | { readonly status: number; readonly body: unknown } | null;
}

/**
 * v0 launch coordinator router factory.
 *
 * Mount once per server:
 *
 * ```ts
 * const handle = createCoreTexCoordinatorRouteHandler(ds);
 * app.use(async (req, res, next) => {
 *   const r = await handle({
 *     method: req.method, path: req.path, body: req.body, headers: req.headers,
 *     query: req.query, remoteAddress: req.ip,
 *   });
 *   if (!r.handled) return next();
 *   res.status(r.status).json(r.body);
 * });
 * ```
 *
 * One factory, one handler. No path table outside this file.
 */
export function createCoreTexCoordinatorRouteHandler(
  source: CoreTexCoordinatorDataSource,
): (req: CoreTexHttpRequest) => Promise<CoreTexHttpResponse> {
  return (req) => handleCoreTexCoordinatorRoute(req, source);
}

export async function handleCoreTexCoordinatorRoute(
  req: CoreTexHttpRequest,
  source: CoreTexCoordinatorDataSource,
): Promise<CoreTexHttpResponse> {
  const method = req.method.toUpperCase();
  const path = stripTrailingSlash(req.path);

  if (method === 'GET' && path === '/coretex/health') {
    const denied = await guardRoute(req, source, 'health');
    if (denied) return denied;
    return handled(200, source.health ? await source.health() : { ok: true, service: 'coretex', serverTime: new Date().toISOString() });
  }

  if (method === 'GET' && path === '/coretex/status') {
    const denied = await guardRoute(req, source, 'status');
    if (denied) return denied;
    if (!source.getStatus) return notConfigured('status');
    return handled(200, await source.getStatus(req.query ?? {}));
  }

  const substrate = matchBytes32(path, /^\/coretex\/substrate\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && substrate) {
    const denied = await guardRoute(req, source, 'substrate-by-root');
    if (denied) return denied;
    if (!source.getSubstrate) return notConfigured('substrate-by-root');
    const result = await source.getSubstrate(substrate);
    if (!result) return handled(404, { error: 'coretex-substrate-not-found', stateRoot: substrate });
    if (isErrorBody(result)) return handled(502, result);
    return handled(200, result);
  }

  if (method === 'POST' && path === '/coretex/submit') {
    const denied = await guardRoute(req, source, 'submit');
    if (denied) return denied;
    if (!source.submit) return notConfigured('submit');
    return handled(200, await source.submit(req.body ?? null));
  }

  const receipt = matchBytes32(path, /^\/coretex\/receipt\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && receipt) {
    const denied = await guardRoute(req, source, 'receipt-by-hash');
    if (denied) return denied;
    if (!source.getReceipt) return notConfigured('receipt-by-hash');
    const result = await source.getReceipt(receipt);
    if (!result) return handled(404, { status: 'rejected', reason: 'unknown patchHash (not signed by this coordinator)' });
    return handled(result.status, result.body);
  }

  if (path.startsWith('/coretex/')) {
    return handled(404, { error: 'coretex-not-found' });
  }

  return { handled: false, status: 404, body: null };
}

function handled(status: number, body: unknown): CoreTexHttpResponse {
  return { handled: true, status, body };
}

function notConfigured(route: CoreTexEndpointName): CoreTexHttpResponse {
  return handled(503, { error: 'coretex-route-not-configured', route });
}

function isErrorBody(result: unknown): result is { readonly error: string } {
  return !!result && typeof result === 'object' && typeof (result as { error?: unknown }).error === 'string';
}

async function guardRoute(
  req: CoreTexHttpRequest,
  source: CoreTexCoordinatorDataSource,
  endpoint: CoreTexEndpointName,
): Promise<CoreTexHttpResponse | null> {
  const context: CoreTexRouteGuardContext = {
    endpoint,
    method: req.method.toUpperCase(),
    path: stripTrailingSlash(req.path),
  };
  if (req.body !== undefined) (context as { body?: unknown }).body = req.body;
  if (req.headers !== undefined) (context as { headers?: CoreTexHttpRequest['headers'] }).headers = req.headers;
  if (req.query !== undefined) (context as { query?: CoreTexHttpRequest['query'] }).query = req.query;
  if (req.remoteAddress !== undefined) (context as { remoteAddress?: string }).remoteAddress = req.remoteAddress;

  const auth = await normalizeGuardResult(source.authorize ? await source.authorize(context) : undefined, 401);
  if (auth) return auth;
  const rate = await normalizeGuardResult(source.rateLimit ? await source.rateLimit(context) : undefined, 429);
  if (rate) return rate;
  return null;
}

async function normalizeGuardResult(
  result: CoreTexRouteGuardResult,
  defaultStatus: number,
): Promise<CoreTexHttpResponse | null> {
  if (result === undefined || result === true) return null;
  if (result === false) return handled(defaultStatus, { error: defaultStatus === 429 ? 'coretex-rate-limited' : 'coretex-unauthorized' });
  if (result.ok === false) {
    return handled(result.status ?? defaultStatus, result.body ?? { error: defaultStatus === 429 ? 'coretex-rate-limited' : 'coretex-unauthorized' });
  }
  return null;
}

function stripTrailingSlash(path: string): string {
  return path.length > 1 ? path.replace(/\/+$/, '') : path;
}

function matchBytes32(path: string, pattern: RegExp): string | null {
  const match = pattern.exec(path);
  return match?.[1]?.toLowerCase() ?? null;
}
