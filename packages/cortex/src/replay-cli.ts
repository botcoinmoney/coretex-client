#!/usr/bin/env node
import { readFileSync } from 'node:fs';

import {
  loadPackedState,
  rangeLogs,
  receiptLogs,
  replayV4TransitionsFromLogs,
  replayV4TransitionFromLogs,
  rpcCall,
  type RpcLog,
} from './replay/v4.js';
import { coretexRangeLogs, replayCoreTexFromLogs } from './replay/coretex-registry.js';
import { unpack } from './state/codec.js';
import { hexToBytes } from './state/merkle.js';
import {
  compareSemverVersions,
  evaluateClientVersionPolicy,
  verifyBundleManifest,
  type CoreTexBundleManifest,
} from './bundle/index.js';
import { CORTEX_CLIENT_VERSION } from './version.js';

function die(message: string): never {
  process.stderr.write(message + '\n');
  process.exit(1);
}

function opt(args: readonly string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function required(args: readonly string[], name: string): string {
  return opt(args, name) ?? die(`missing ${name}`);
}

function parseLogsFile(path: string): RpcLog[] {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { logs?: RpcLog[] } | RpcLog[];
  return Array.isArray(parsed) ? parsed : parsed.logs ?? [];
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function print(value: unknown) {
  process.stdout.write(JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n');
}

function parseBlock(value: string): bigint {
  if (value === 'latest') throw new Error('latest must be resolved before parsing');
  return BigInt(value);
}

function blockHex(value: bigint): string {
  return '0x' + value.toString(16);
}

async function latestBlock(rpc: string): Promise<bigint> {
  return BigInt(await rpcCall<string>(rpc, 'eth_blockNumber', []));
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === '-h') {
    process.stderr.write(
      'usage: coretex-replay {tx|current|watch} --parent-state state.bin [--logs logs.json | --rpc url --tx hash]\n'
      + '       coretex-replay watch --rpc url --coretex-registry addr --parent-state state.bin --bundle-manifest manifest.json --expected-bundle-hash 0x... [--from-block n] [--to-block latest] [--once]\n'
      + '       canonical replay: --bundle-manifest manifest.json --expected-bundle-hash 0x... (or --core-version-hash 0x...) [--client-version x.y.z] [--allow-outdated-client]\n',
    );
    process.exit(cmd ? 0 : 1);
  }

  if (cmd === 'watch') {
    requireCanonicalWatchBundle(args);
  }

  let parentState = loadPackedState(required(args, '--parent-state'));
  verifyBundleIfRequested(args);

  if (cmd === 'tx') {
    const logs = opt(args, '--logs')
      ? parseLogsFile(required(args, '--logs'))
      : await receiptLogs(required(args, '--rpc'), required(args, '--tx'));
    const result = replayV4TransitionFromLogs(parentState, logs);
    print(result);
    if (!result.ok) process.exit(1);
    return;
  }

  if (cmd === 'current') {
    const logs = parseLogsFile(required(args, '--events'));
    const result = replayV4TransitionFromLogs(parentState, logs);
    print(result);
    if (!result.ok) process.exit(1);
    return;
  }

  if (cmd === 'watch') {
    const rpc = required(args, '--rpc');
    const fromBlockArg = opt(args, '--from-block') ?? 'latest';
    const toBlockArg = opt(args, '--to-block');
    const pollIntervalMs = Number(opt(args, '--poll-interval-ms') ?? '12000');
    const once = args.includes('--once') || toBlockArg !== undefined;
    // Canonical CoreTexRegistry replay; legacy --v4/--cortex-state addresses still accepted as aliases.
    const registry = opt(args, '--coretex-registry') ?? opt(args, '--registry');
    const addresses = [registry, opt(args, '--v4'), opt(args, '--cortex-state')].filter((v): v is string => v !== undefined);
    const expectedBundleHash = opt(args, '--expected-bundle-hash') ?? opt(args, '--core-version-hash');
    const expectedPins = expectedReplayPins(args);
    // r5 epochs: enforce the reserved-region / PolicyAtom grammar during canonical replay (same as scoring),
    // derived from the pinned bundle's pipelineVersion when a manifest is supplied. Default off (r4-safe).
    const replayManifestPath = opt(args, '--bundle-manifest');
    const policyAtomsMode = replayManifestPath
      ? (JSON.parse(readFileSync(replayManifestPath, 'utf8'))?.evaluator?.profile?.pipelineVersion === 'coretex-retrieval-v2-policy-r5')
      : false;
    const fromFixed = fromBlockArg === 'latest' ? await latestBlock(rpc) : parseBlock(fromBlockArg);

    for (;;) {
      const latest = toBlockArg ? (toBlockArg === 'latest' ? await latestBlock(rpc) : parseBlock(toBlockArg)) : await latestBlock(rpc);
      if (latest >= fromFixed) {
        // cumulative + idempotent: always replay the full range from the pinned start over the empty/parent state.
        const logs = await coretexRangeLogs(rpc, addresses.length > 0 ? addresses : undefined, blockHex(fromFixed), blockHex(latest));
        const result = replayCoreTexFromLogs(parentState, logs, { ...(expectedBundleHash ? { expectedBundleHash } : {}), ...expectedPins, policyAtomsMode });
        print({ fromBlock: blockHex(fromFixed), toBlock: blockHex(latest), logCount: logs.length, ...result });
        if (!result.ok) process.exit(1);
      }
      if (once) return;
      await sleep(pollIntervalMs);
    }
  }

  die(`unknown command ${cmd}`);
}

function expectedReplayPins(args: readonly string[]): {
  expectedCorpusRoot?: string;
  expectedActiveFrontierRoot?: string;
  expectedBaselineManifestHash?: string;
  expectedHiddenSeedCommit?: string;
} {
  const manifestPath = opt(args, '--bundle-manifest');
  const manifest = manifestPath ? JSON.parse(readFileSync(manifestPath, 'utf8')) as CoreTexBundleManifest : null;
  const out: {
    expectedCorpusRoot?: string;
    expectedActiveFrontierRoot?: string;
    expectedBaselineManifestHash?: string;
    expectedHiddenSeedCommit?: string;
  } = {};
  const corpusRoot = opt(args, '--expected-corpus-root') ?? opt(args, '--corpus-root') ?? manifest?.corpus?.root;
  const activeFrontierRoot = opt(args, '--expected-active-frontier-root') ?? opt(args, '--active-frontier-root');
  const baselineManifestHash = opt(args, '--expected-baseline-manifest-hash') ?? opt(args, '--baseline-manifest-hash');
  const hiddenSeedCommit = opt(args, '--expected-hidden-seed-commit') ?? opt(args, '--hidden-seed-commit');
  if (corpusRoot) out.expectedCorpusRoot = corpusRoot;
  if (activeFrontierRoot) out.expectedActiveFrontierRoot = activeFrontierRoot;
  if (baselineManifestHash) out.expectedBaselineManifestHash = baselineManifestHash;
  if (hiddenSeedCommit) out.expectedHiddenSeedCommit = hiddenSeedCommit;
  return out;
}

function verifyBundleIfRequested(args: readonly string[]): void {
  const manifestPath = opt(args, '--bundle-manifest');
  if (!manifestPath) return;
  const repoRoot = opt(args, '--repo-root') ?? process.cwd();
  const expectedHash = opt(args, '--expected-bundle-hash') ?? opt(args, '--core-version-hash');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as CoreTexBundleManifest;
  const errors = verifyBundleManifest(manifest, repoRoot);
  if (expectedHash && manifest.bundleHash.toLowerCase() !== expectedHash.toLowerCase()) {
    errors.push(`bundleHash mismatch: expected ${expectedHash} got ${manifest.bundleHash}`);
  }
  const suppliedClientVersion = opt(args, '--client-version');
  const clientVersion = suppliedClientVersion ?? process.env['CORETEX_CLIENT_VERSION'] ?? CORTEX_CLIENT_VERSION;
  const clientCheck = evaluateClientVersionPolicy(
    manifest.evaluator.profile.clientVersionPolicy,
    clientVersion,
  );
  if (!clientCheck.ok) {
    if (manifest.evaluator.profile.clientVersionPolicy?.hardFailOutdated && !args.includes('--allow-outdated-client')) {
      errors.push(`OUTDATED_CLIENT: ${clientCheck.message}`);
    } else {
      process.stderr.write(`warning: OUTDATED_CLIENT: ${clientCheck.message}\n`);
    }
  } else if (manifest.evaluator.profile.clientVersionPolicy?.recommendedVersion) {
    const recommended = manifest.evaluator.profile.clientVersionPolicy.recommendedVersion;
    if (recommended && compareSemverVersions(clientVersion, recommended) < 0) {
      process.stderr.write(`warning: bundle recommends client ${recommended}; running ${clientVersion}\n`);
    }
  } else if (!manifest.evaluator.profile.clientVersionPolicy) {
    process.stderr.write('warning: bundle has no clientVersionPolicy pinned; compatibility gating is disabled\n');
  }
  if (errors.length) {
    die(`bundle manifest verification failed: ${errors.join('; ')}`);
  }
}

function requireCanonicalWatchBundle(args: readonly string[]): void {
  if (args.includes('--allow-unverified-bundle')) return;
  if (!opt(args, '--bundle-manifest')) {
    die('coretex-replay watch requires --bundle-manifest for canonical replay (or --allow-unverified-bundle for local dev)');
  }
  if (!opt(args, '--expected-bundle-hash') && !opt(args, '--core-version-hash')) {
    die('coretex-replay watch requires --expected-bundle-hash or --core-version-hash for canonical replay');
  }
}

main().catch((error) => die(error instanceof Error ? error.message : String(error)));
