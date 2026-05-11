export type CoreTexEndpointName =
  | 'screen'
  | 'evaluate'
  | 'substrate-current'
  | 'substrate-by-root'
  | 'patch-by-hash'
  | 'eval-report-by-hash'
  | 'challenge-book-by-epoch'
  | 'corpus-delta-by-epoch'
  | 'client-bundle-by-hash'
  | 'corpus-record'
  | 'corpus-record-embedding'
  | 'coverage-hints'
  | 'bundle-by-hash'
  | 'health'
  // Sealed-eval flow (Phase S1 of CORETEX_SEALED_EPOCH_EVAL_HARDENING_PLAN.md).
  // Miner-facing commit/reveal endpoints replace the legacy interactive
  // hidden oracle. /coretex/evaluate stays sealed (Phase S0) during the
  // active mining window.
  | 'commit'
  | 'reveal'
  | 'commit-by-hash'
  | 'epoch-status';

export interface CoreTexEndpoint {
  readonly name: CoreTexEndpointName;
  readonly method: 'GET' | 'POST';
  readonly path: string;
}

export const CORETEX_ENDPOINTS: readonly CoreTexEndpoint[] = [
  { name: 'screen', method: 'POST', path: '/coretex/screen' },
  { name: 'evaluate', method: 'POST', path: '/coretex/evaluate' },
  { name: 'substrate-current', method: 'GET', path: '/coretex/substrate/current' },
  { name: 'substrate-by-root', method: 'GET', path: '/coretex/substrate/:stateRoot' },
  { name: 'patch-by-hash', method: 'GET', path: '/coretex/patch/:hash' },
  { name: 'eval-report-by-hash', method: 'GET', path: '/coretex/eval-report/:hash' },
  { name: 'challenge-book-by-epoch', method: 'GET', path: '/coretex/challenge-book/:epoch' },
  { name: 'corpus-delta-by-epoch', method: 'GET', path: '/coretex/corpus-delta/:epoch' },
  { name: 'client-bundle-by-hash', method: 'GET', path: '/coretex/client-bundle/:coreVersionHash' },
  { name: 'bundle-by-hash', method: 'GET', path: '/coretex/bundle/:bundleHash' },
  { name: 'corpus-record', method: 'GET', path: '/coretex/corpus/:recordId' },
  { name: 'corpus-record-embedding', method: 'GET', path: '/coretex/corpus/:recordId/embedding' },
  { name: 'coverage-hints', method: 'GET', path: '/coretex/coverage-hints' },
  { name: 'health', method: 'GET', path: '/coretex/health' },
  // Sealed-eval flow (Phase S1).
  { name: 'commit', method: 'POST', path: '/coretex/commit' },
  { name: 'reveal', method: 'POST', path: '/coretex/reveal' },
  { name: 'commit-by-hash', method: 'GET', path: '/coretex/commit/:commitmentHash' },
  { name: 'epoch-status', method: 'GET', path: '/coretex/epoch/:epochId/status' },
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
  readonly screen?: (body: unknown) => Promise<unknown> | unknown;
  readonly evaluate?: (body: unknown) => Promise<unknown> | unknown;
  readonly getCurrentSubstrate?: () => Promise<unknown> | unknown;
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  readonly getPatch?: (hash: string) => Promise<unknown> | unknown;
  readonly getEvalReport?: (hash: string) => Promise<unknown> | unknown;
  readonly getChallengeBook?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getCorpusDelta?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getClientBundle?: (coreVersionHash: string) => Promise<unknown> | unknown;
  readonly getBundle?: (bundleHash: string) => Promise<unknown> | unknown;
  readonly getCorpusRecord?: (recordId: string) => Promise<unknown> | unknown;
  readonly getCorpusRecordEmbedding?: (recordId: string) => Promise<unknown> | unknown;
  readonly getCoverageHints?: () => Promise<unknown> | unknown;
  readonly health?: () => Promise<unknown> | unknown;
  // Sealed-eval flow (Phase S1). Hosts wire persistence + on-chain
  // anchoring under these callbacks; the shim only does routing.
  readonly submitCommit?: (body: unknown) => Promise<unknown> | unknown;
  readonly submitReveal?: (body: unknown) => Promise<unknown> | unknown;
  readonly getCommit?: (commitmentHash: string) => Promise<unknown> | unknown;
  readonly getEpochStatus?: (epochId: bigint) => Promise<unknown> | unknown;
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
    return handled(200, source.health ? await source.health() : { ok: true, service: 'coretex' });
  }

  if (method === 'POST' && path === '/coretex/screen') {
    const denied = await guardRoute(req, source, 'screen');
    if (denied) return denied;
    if (!source.screen) return notConfigured('screen');
    return handled(200, await source.screen(req.body ?? null));
  }

  if (method === 'POST' && path === '/coretex/evaluate') {
    const denied = await guardRoute(req, source, 'evaluate');
    if (denied) return denied;
    if (!source.evaluate) return notConfigured('evaluate');
    return handled(200, await source.evaluate(req.body ?? null));
  }

  if (method === 'GET' && path === '/coretex/substrate/current') {
    const denied = await guardRoute(req, source, 'substrate-current');
    if (denied) return denied;
    if (!source.getCurrentSubstrate) return notConfigured('substrate-current');
    return handled(200, await source.getCurrentSubstrate());
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

  const evalReport = matchBytes32(path, /^\/coretex\/eval-report\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && evalReport) {
    const denied = await guardRoute(req, source, 'eval-report-by-hash');
    if (denied) return denied;
    if (!source.getEvalReport) return notConfigured('eval-report-by-hash');
    return handled(200, await source.getEvalReport(evalReport));
  }

  const challengeBookEpoch = matchEpoch(path, /^\/coretex\/challenge-book\/([0-9]+)$/);
  if (method === 'GET' && challengeBookEpoch !== null) {
    const denied = await guardRoute(req, source, 'challenge-book-by-epoch');
    if (denied) return denied;
    if (!source.getChallengeBook) return notConfigured('challenge-book-by-epoch');
    return handled(200, await source.getChallengeBook(challengeBookEpoch));
  }

  const corpusDeltaEpoch = matchEpoch(path, /^\/coretex\/corpus-delta\/([0-9]+)$/);
  if (method === 'GET' && corpusDeltaEpoch !== null) {
    const denied = await guardRoute(req, source, 'corpus-delta-by-epoch');
    if (denied) return denied;
    if (!source.getCorpusDelta) return notConfigured('corpus-delta-by-epoch');
    return handled(200, await source.getCorpusDelta(corpusDeltaEpoch));
  }

  const bundle = matchBytes32(path, /^\/coretex\/client-bundle\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && bundle) {
    const denied = await guardRoute(req, source, 'client-bundle-by-hash');
    if (denied) return denied;
    if (!source.getClientBundle) return notConfigured('client-bundle-by-hash');
    return handled(200, await source.getClientBundle(bundle));
  }

  const bundleByHash = matchBytes32(path, /^\/coretex\/bundle\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && bundleByHash) {
    const denied = await guardRoute(req, source, 'bundle-by-hash');
    if (denied) return denied;
    if (!source.getBundle) return notConfigured('bundle-by-hash');
    return handled(200, await source.getBundle(bundleByHash));
  }

  if (method === 'GET' && path === '/coretex/coverage-hints') {
    const denied = await guardRoute(req, source, 'coverage-hints');
    if (denied) return denied;
    if (!source.getCoverageHints) return notConfigured('coverage-hints');
    return handled(200, await source.getCoverageHints());
  }

  // Sealed-eval flow (Phase S1).
  if (method === 'POST' && path === '/coretex/commit') {
    const denied = await guardRoute(req, source, 'commit');
    if (denied) return denied;
    if (!source.submitCommit) return notConfigured('commit');
    return handled(200, await source.submitCommit(req.body ?? null));
  }

  if (method === 'POST' && path === '/coretex/reveal') {
    const denied = await guardRoute(req, source, 'reveal');
    if (denied) return denied;
    if (!source.submitReveal) return notConfigured('reveal');
    return handled(200, await source.submitReveal(req.body ?? null));
  }

  const commitHash = matchBytes32(path, /^\/coretex\/commit\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && commitHash) {
    const denied = await guardRoute(req, source, 'commit-by-hash');
    if (denied) return denied;
    if (!source.getCommit) return notConfigured('commit-by-hash');
    return handled(200, await source.getCommit(commitHash));
  }

  const epochStatusMatch = matchEpoch(path, /^\/coretex\/epoch\/([0-9]+)\/status$/);
  if (method === 'GET' && epochStatusMatch !== null) {
    const denied = await guardRoute(req, source, 'epoch-status');
    if (denied) return denied;
    if (!source.getEpochStatus) return notConfigured('epoch-status');
    return handled(200, await source.getEpochStatus(epochStatusMatch));
  }

  const corpusEmbed = matchRecordId(path, /^\/coretex\/corpus\/([A-Za-z0-9_:.-]+)\/embedding$/);
  if (method === 'GET' && corpusEmbed) {
    const denied = await guardRoute(req, source, 'corpus-record-embedding');
    if (denied) return denied;
    if (!source.getCorpusRecordEmbedding) return notConfigured('corpus-record-embedding');
    return handled(200, await source.getCorpusRecordEmbedding(corpusEmbed));
  }

  const corpusRec = matchRecordId(path, /^\/coretex\/corpus\/([A-Za-z0-9_:.-]+)$/);
  if (method === 'GET' && corpusRec) {
    const denied = await guardRoute(req, source, 'corpus-record');
    if (denied) return denied;
    if (!source.getCorpusRecord) return notConfigured('corpus-record');
    return handled(200, await source.getCorpusRecord(corpusRec));
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

function matchRecordId(path: string, pattern: RegExp): string | null {
  const match = pattern.exec(path);
  return match?.[1] ?? null;
}
