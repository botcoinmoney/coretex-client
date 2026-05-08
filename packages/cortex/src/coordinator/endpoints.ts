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
  | 'health';

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
  { name: 'health', method: 'GET', path: '/coretex/health' },
] as const;

export interface CoreTexHttpRequest {
  readonly method: string;
  readonly path: string;
  readonly body?: unknown;
}

export interface CoreTexHttpResponse {
  readonly handled: boolean;
  readonly status: number;
  readonly body: unknown;
}

export interface CoreTexCoordinatorDataSource {
  readonly screen?: (body: unknown) => Promise<unknown> | unknown;
  readonly evaluate?: (body: unknown) => Promise<unknown> | unknown;
  readonly getCurrentSubstrate?: () => Promise<unknown> | unknown;
  readonly getSubstrate?: (stateRoot: string) => Promise<unknown> | unknown;
  readonly getPatch?: (hash: string) => Promise<unknown> | unknown;
  readonly getEvalReport?: (hash: string) => Promise<unknown> | unknown;
  readonly getChallengeBook?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getCorpusDelta?: (epoch: bigint) => Promise<unknown> | unknown;
  readonly getClientBundle?: (coreVersionHash: string) => Promise<unknown> | unknown;
  readonly health?: () => Promise<unknown> | unknown;
}

export async function handleCoreTexCoordinatorRoute(
  req: CoreTexHttpRequest,
  source: CoreTexCoordinatorDataSource,
): Promise<CoreTexHttpResponse> {
  const method = req.method.toUpperCase();
  const path = stripTrailingSlash(req.path);

  if (method === 'GET' && path === '/coretex/health') {
    return handled(200, source.health ? await source.health() : { ok: true, service: 'coretex' });
  }

  if (method === 'POST' && path === '/coretex/screen') {
    if (!source.screen) return notConfigured('screen');
    return handled(200, await source.screen(req.body ?? null));
  }

  if (method === 'POST' && path === '/coretex/evaluate') {
    if (!source.evaluate) return notConfigured('evaluate');
    return handled(200, await source.evaluate(req.body ?? null));
  }

  if (method === 'GET' && path === '/coretex/substrate/current') {
    if (!source.getCurrentSubstrate) return notConfigured('substrate-current');
    return handled(200, await source.getCurrentSubstrate());
  }

  const substrate = matchBytes32(path, /^\/coretex\/substrate\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && substrate) {
    if (!source.getSubstrate) return notConfigured('substrate-by-root');
    return handled(200, await source.getSubstrate(substrate));
  }

  const patch = matchBytes32(path, /^\/coretex\/patch\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && patch) {
    if (!source.getPatch) return notConfigured('patch-by-hash');
    return handled(200, await source.getPatch(patch));
  }

  const evalReport = matchBytes32(path, /^\/coretex\/eval-report\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && evalReport) {
    if (!source.getEvalReport) return notConfigured('eval-report-by-hash');
    return handled(200, await source.getEvalReport(evalReport));
  }

  const challengeBookEpoch = matchEpoch(path, /^\/coretex\/challenge-book\/([0-9]+)$/);
  if (method === 'GET' && challengeBookEpoch !== null) {
    if (!source.getChallengeBook) return notConfigured('challenge-book-by-epoch');
    return handled(200, await source.getChallengeBook(challengeBookEpoch));
  }

  const corpusDeltaEpoch = matchEpoch(path, /^\/coretex\/corpus-delta\/([0-9]+)$/);
  if (method === 'GET' && corpusDeltaEpoch !== null) {
    if (!source.getCorpusDelta) return notConfigured('corpus-delta-by-epoch');
    return handled(200, await source.getCorpusDelta(corpusDeltaEpoch));
  }

  const bundle = matchBytes32(path, /^\/coretex\/client-bundle\/(0x[0-9a-fA-F]{64})$/);
  if (method === 'GET' && bundle) {
    if (!source.getClientBundle) return notConfigured('client-bundle-by-hash');
    return handled(200, await source.getClientBundle(bundle));
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
