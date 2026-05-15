export type CoreTexEndpointName =
  | 'challenge'
  | 'submit'
  | 'status'
  | 'substrate-by-root'
  | 'patch-by-hash'
  | 'patch-received-notice-by-hash'
  | 'eval-report-by-hash'
  | 'corpus-delta-by-epoch'
  | 'bundle-by-core-version-hash'
  | 'bundle-by-hash'
  | 'health';

export interface CoreTexEndpoint {
  readonly name: CoreTexEndpointName;
  readonly method: 'GET' | 'POST';
  readonly path: string;
}

export const CORETEX_ENDPOINTS: readonly CoreTexEndpoint[] = [
  { name: 'challenge', method: 'GET', path: '/coretex/challenge' },
  { name: 'submit', method: 'POST', path: '/coretex/submit' },
  { name: 'status', method: 'GET', path: '/coretex/status' },
  { name: 'substrate-by-root', method: 'GET', path: '/coretex/substrate/:stateRoot' },
  { name: 'patch-by-hash', method: 'GET', path: '/coretex/patch/:hash' },
  { name: 'patch-received-notice-by-hash', method: 'GET', path: '/coretex/patch-received/:hash' },
  { name: 'eval-report-by-hash', method: 'GET', path: '/coretex/eval-report/:hash' },
  { name: 'corpus-delta-by-epoch', method: 'GET', path: '/coretex/corpus-delta/:epoch' },
  { name: 'bundle-by-core-version-hash', method: 'GET', path: '/coretex/bundle/by-core-version/:coreVersionHash' },
  { name: 'bundle-by-hash', method: 'GET', path: '/coretex/bundle/:bundleHash' },
  { name: 'health', method: 'GET', path: '/coretex/health' },
] as const;

export interface CoreTexHttpRequest {
  readonly method: string;
  readonly path: string;
  readonly body?: unknown;
  readonly headers?: Record<string, string | readonly string[] | undefined>;
  readonly remoteAddress?: string;
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

export interface CoreTexCoordinatorDataSource {
  readonly authorize?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly rateLimit?: (context: CoreTexRouteGuardContext) => Promise<CoreTexRouteGuardResult> | CoreTexRouteGuardResult;
  readonly getChallenge?: () => Promise<unknown> | unknown;
  readonly submit?: (body: unknown) => Promise<unknown> | unknown;
  readonly getStatus?: () => Promise<unknown> | unknown;
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  readonly getPatch?: (hash: string) => Promise<unknown> | unknown;
  readonly getPatchReceivedNotice?: (hash: string) => Promise<unknown> | unknown;
  readonly getEvalReport?: (hash: string) => Promise<unknown> | unknown;
  readonly getCorpusDelta?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getBundleByCoreVersionHash?: (coreVersionHash: string) => Promise<unknown> | unknown;
  readonly getBundle?: (bundleHash: string) => Promise<unknown> | unknown;
  readonly health?: () => Promise<unknown> | unknown;
}

/**
 * Bind a data source to a single async handler. Usage in any HTTP framework:
 *
 * ```ts
 * const handle = createCoreTexCoordinatorRouteHandler(ds);
 * app.use(async (req, res, next) => {
 *   const r = await handle({ method: req.method, path: req.path, body: req.body, headers: req.headers });
 *   if (!r.handled) return next();
 *   res.status(r.status).json(r.body);
 * });
 * ```
 *
 * This is the entire integration surface: one factory call, one handler.
 * No route table, no path glue, no middleware-specific imports.
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

  if (method === 'GET' && path === '/coretex/challenge') {
    const denied = await guardRoute(req, source, 'challenge');
    if (denied) return denied;
    if (!source.getChallenge) return notConfigured('challenge');
    return handled(200, await source.getChallenge());
  }

  if (method === 'POST' && path === '/coretex/submit') {
    const denied = await guardRoute(req, source, 'submit');
    if (denied) return denied;
    if (!source.submit) return notConfigured('submit');
    return handled(200, await source.submit(req.body ?? null));
  }

  if (method === 'GET' && path === '/coretex/status') {
    const denied = await guardRoute(req, source, 'status');
    if (denied) return denied;
    if (!source.getStatus) return notConfigured('status');
    return handled(200, await source.getStatus());
  }

  const substrate = matchBytes32(path, /^\/coretex\/substrate\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && substrate) {
    const denied = await guardRoute(req, source, 'substrate-by-root');
    if (denied) return denied;
    if (!source.getSubstrate) return notConfigured('substrate-by-root');
    return handled(200, await source.getSubstrate(substrate));
  }

  const patch = matchBytes32(path, /^\/coretex\/patch\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && patch) {
    const denied = await guardRoute(req, source, 'patch-by-hash');
    if (denied) return denied;
    if (!source.getPatch) return notConfigured('patch-by-hash');
    return handled(200, await source.getPatch(patch));
  }

  const patchReceived = matchBytes32(path, /^\/coretex\/patch-received\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && patchReceived) {
    const denied = await guardRoute(req, source, 'patch-received-notice-by-hash');
    if (denied) return denied;
    if (!source.getPatchReceivedNotice) return notConfigured('patch-received-notice-by-hash');
    return handled(200, await source.getPatchReceivedNotice(patchReceived));
  }

  const evalReport = matchBytes32(path, /^\/coretex\/eval-report\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && evalReport) {
    const denied = await guardRoute(req, source, 'eval-report-by-hash');
    if (denied) return denied;
    if (!source.getEvalReport) return notConfigured('eval-report-by-hash');
    return handled(200, await source.getEvalReport(evalReport));
  }

  const corpusDeltaEpoch = matchEpoch(path, /^\/coretex\/corpus-delta\/([0-9]+)$/);
  if (method === 'GET' && corpusDeltaEpoch !== null) {
    const denied = await guardRoute(req, source, 'corpus-delta-by-epoch');
    if (denied) return denied;
    if (!source.getCorpusDelta) return notConfigured('corpus-delta-by-epoch');
    return handled(200, await source.getCorpusDelta(corpusDeltaEpoch));
  }

  const byCoreVersion = matchBytes32(path, /^\/coretex\/bundle\/by-core-version\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && byCoreVersion) {
    const denied = await guardRoute(req, source, 'bundle-by-core-version-hash');
    if (denied) return denied;
    if (!source.getBundleByCoreVersionHash) return notConfigured('bundle-by-core-version-hash');
    return handled(200, await source.getBundleByCoreVersionHash(byCoreVersion));
  }

  const bundleByHash = matchBytes32(path, /^\/coretex\/bundle\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && bundleByHash) {
    const denied = await guardRoute(req, source, 'bundle-by-hash');
    if (denied) return denied;
    if (!source.getBundle) return notConfigured('bundle-by-hash');
    return handled(200, await source.getBundle(bundleByHash));
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

function matchEpoch(path: string, pattern: RegExp): bigint | null {
  const match = pattern.exec(path);
  if (!match?.[1]) return null;
  return BigInt(match[1]);
}

