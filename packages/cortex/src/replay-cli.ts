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
import { unpack } from './state/codec.js';
import { hexToBytes } from './state/merkle.js';
import { verifyBundleManifest, type CoreTexBundleManifest } from './bundle/index.js';

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
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
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
      + '       coretex-replay watch --rpc url --parent-state state.bin [--v4 addr] [--cortex-state addr] [--from-block n] [--once]\n'
      + '       optional: --bundle-manifest manifest.json --expected-bundle-hash 0x...\n',
    );
    process.exit(cmd ? 0 : 1);
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
    const addresses = [opt(args, '--v4'), opt(args, '--cortex-state')].filter((v): v is string => v !== undefined);
    let cursor = fromBlockArg === 'latest' ? await latestBlock(rpc) : parseBlock(fromBlockArg);

    for (;;) {
      const latest = toBlockArg ? (toBlockArg === 'latest' ? await latestBlock(rpc) : parseBlock(toBlockArg)) : await latestBlock(rpc);
      if (latest >= cursor) {
        const logs = await rangeLogs(rpc, addresses.length > 0 ? addresses : undefined, blockHex(cursor), blockHex(latest));
        const result = replayV4TransitionsFromLogs(parentState, logs);
        print({ fromBlock: blockHex(cursor), toBlock: blockHex(latest), logCount: logs.length, ...result });
        if (!result.ok) process.exit(1);
        parentState = unpack(hexToBytes(result.finalStatePackedHex));
        cursor = latest + 1n;
      }
      if (once) return;
      await sleep(pollIntervalMs);
    }
  }

  die(`unknown command ${cmd}`);
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
  if (errors.length) {
    die(`bundle manifest verification failed: ${errors.join('; ')}`);
  }
}

main().catch((error) => die(error instanceof Error ? error.message : String(error)));
