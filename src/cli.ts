#!/usr/bin/env node
/**
 * botcoin-coretex — Phase 3 CLI dispatcher.
 *
 * Subcommands:
 *   decode        Parse a packed CortexState into typed slots (JSON output).
 *   apply-patch   Apply a patch to a state; print new state root.
 *   eval          Run a full patch eval and emit a deterministic eval report.
 *   reduce-epoch  Run the deterministic reducer over a set of patch files.
 *   verify-epoch  Reproduce newStateRoot from chain events alone.
 *   snapshot      Pack a decoded state back to wire bytes.
 *
 * All subcommands read stdin or file arguments; write stdout (JSON).
 * Exit 0 = success, 1 = user error, 2 = not yet implemented.
 *
 * Perf note: eval/reduce-epoch dispatch work to the worker pool (worker_threads).
 */

import * as fs from 'node:fs';

import { unpack, pack } from './state/codec.js';
import { merkleizeState, bytesToHex, hexToBytes } from './state/merkle.js';
import { applyPatch, decodePatch, encodePatch } from './state/patch.js';
import { decodeSubstrate } from './substrate/retrieval-decoder.js';
import { evalPatch, StubCorpusLoader } from './eval/index.js';
import { reduce, makeReducerInput, type ReducerInputPatch } from './reducer/reducer.js';
import { computePatchHash } from './eval/seed-derivation.js';
import { verifyEpoch } from './verify-epoch/index.js';
import type {
  PatchAcceptedEvent,
  EpochFinalizedEvent,
  StateSnapshotEvent,
} from './verify-epoch/index.js';
import {
  parseStatTranslationPatch,
  applyStatTranslationPatch,
  executeReset,
  encodeStatTranslationPatch,
} from './upgrade/index.js';
import {
  buildBundleManifest,
  verifyBundleManifest,
  type BiEncoderManifest,
  type RerankerManifest,
  type CoreTexBundleManifest,
} from './bundle/index.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function die(msg: string, code = 1): never {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

function readFileOrStdin(filePath: string | undefined): Buffer {
  if (!filePath || filePath === '-') {
    return fs.readFileSync('/dev/stdin');
  }
  return fs.readFileSync(filePath);
}

function bigIntReviver(_k: string, v: unknown): unknown {
  if (typeof v === 'string' && v.endsWith('n') && /^-?\d+n$/.test(v)) {
    return BigInt(v.slice(0, -1));
  }
  return v;
}

function bigIntReplacer(_k: string, v: unknown): unknown {
  if (typeof v === 'bigint') return v.toString() + 'n';
  return v;
}

function toJsonOutput(obj: unknown): string {
  return JSON.stringify(obj, bigIntReplacer, 2);
}

// ─── CLI entry point ──────────────────────────────────────────────────────────

const [, , cmd, ...args] = process.argv;

if (!cmd) {
  process.stderr.write(
    'usage: botcoin-coretex {decode|apply-patch|eval|reduce-epoch|verify-epoch|snapshot|upgrade|bundle-manifest}\n',
  );
  process.exit(1);
}

switch (cmd) {
  // ── decode ────────────────────────────────────────────────────────────────
  case 'decode': {
    // Usage: botcoin-coretex decode [state.bin] [--policy-atoms-mode|--r5]
    // Reads 32768-byte packed state; outputs JSON typed-slot decode.
    const policyAtomsMode = args.includes('--policy-atoms-mode') || args.includes('--r5');
    const statePath = args.find((arg) => !arg.startsWith('--'));
    const stateBytes = readFileOrStdin(statePath);
    if (stateBytes.length !== 32768) {
      die(`decode: expected 32768-byte state, got ${stateBytes.length}`);
    }
    const state = unpack(new Uint8Array(stateBytes));
    const decoded = decodeSubstrate(state, { policyAtomsMode });
    // Convert Maps/Sets to serializable forms
    const out = {
      ok: true,
      policyAtomsMode,
      memoryIndexCount: decoded.memoryIndex.length,
      memoryIndex: decoded.memoryIndex,
      retrievalKeyCount: decoded.retrievalKeys.length,
      retrievalKeys: decoded.retrievalKeys,
      relationsCount: decoded.relations.length,
      relations: decoded.relations,
      categoryLensCount: decoded.categoryLenses.length,
      categoryLenses: decoded.categoryLenses,
      temporalCount: decoded.temporal.length,
      temporal: decoded.temporal,
      codebookCount: decoded.codebook.length,
      codebook: decoded.codebook,
      decodedSlots: decoded.decodedSlots,
      decodeAttempts: decoded.decodeAttempts,
      decodeFailures: decoded.decodeFailures,
      relationsDroppedByDomainPredicate: decoded.relationsDroppedByDomainPredicate,
      evidenceBundleAtomCount: decoded.evidenceBundleAtoms.length,
      evidenceBundleAtoms: decoded.evidenceBundleAtoms,
      conflictLifecycleAtomCount: decoded.conflictLifecycleAtoms.length,
      conflictLifecycleAtoms: decoded.conflictLifecycleAtoms,
      abstentionAtomCount: decoded.abstentionAtoms.length,
      abstentionAtoms: decoded.abstentionAtoms,
      policyReservedNonZeroWords: decoded.policyReservedNonZeroWords,
      ...(decoded.lensDiversityCheck ? { lensDiversityCheck: decoded.lensDiversityCheck } : {}),
    };
    process.stdout.write(toJsonOutput(out) + '\n');
    break;
  }

  // ── apply-patch ───────────────────────────────────────────────────────────
  case 'apply-patch': {
    // Usage: botcoin-coretex apply-patch <state.bin> <patch.bin>
    const stateFile = args[0];
    const patchFile = args[1];
    if (!stateFile || !patchFile) {
      die('apply-patch: usage: botcoin-coretex apply-patch <state.bin> <patch.bin>');
    }
    const stateBytes = fs.readFileSync(stateFile);
    const patchBytes = fs.readFileSync(patchFile);
    const state = unpack(new Uint8Array(stateBytes));
    const patch = decodePatch(new Uint8Array(patchBytes));
    const result = applyPatch(state, patch);
    if (!result.ok) {
      process.stdout.write(toJsonOutput({ ok: false, code: result.code, message: result.message }) + '\n');
      process.exit(1);
    }
    const newRoot = bytesToHex(merkleizeState(result.state));
    process.stdout.write(toJsonOutput({
      ok: true,
      newStateRoot: newRoot,
      newStatePacked: Buffer.from(pack(result.state)).toString('hex'),
    }) + '\n');
    break;
  }

  // ── eval ──────────────────────────────────────────────────────────────────
  case 'eval': {
    // Usage: botcoin-coretex eval <state.bin> <patch.bin> [--corpus-root 0x...] [--corpus-file file.json]
    const stateFile = args[0];
    const patchFile = args[1];
    if (!stateFile || !patchFile) {
      die('eval: usage: botcoin-coretex eval <state.bin> <patch.bin>');
    }
    const stateBytes = fs.readFileSync(stateFile);
    const patchBytes = fs.readFileSync(patchFile);
    const state = unpack(new Uint8Array(stateBytes));
    const patchWire = new Uint8Array(patchBytes);
    const patch = decodePatch(patchWire);
    const corpusRootArg = args.indexOf('--corpus-root');
    const corpusRoot = corpusRootArg >= 0 ? (args[corpusRootArg + 1] ?? '0x' + '00'.repeat(32)) : '0x' + '00'.repeat(32);
    // The synchronous CLI eval uses StubCorpusLoader; production scoring is
    // async (bi-encoder + cross-encoder) and runs through the coordinator's
    // /coretex/evaluate endpoint, not this CLI. See evaluateRetrievalBenchmarkPatch.
    const loader = new StubCorpusLoader(corpusRoot);
    const report = evalPatch(state, patch, { loader, patchWireBytes: patchWire });
    process.stdout.write(toJsonOutput(report) + '\n');
    break;
  }

  // ── reduce-epoch ──────────────────────────────────────────────────────────
  case 'reduce-epoch': {
    // Usage: botcoin-coretex reduce-epoch <state.bin> <patches.json>
    // patches.json: array of { compactPatchBytesHex, patchHash, parentStateRoot, scoreDelta? }
    const stateFile = args[0];
    const patchesFile = args[1];
    if (!stateFile || !patchesFile) {
      die('reduce-epoch: usage: botcoin-coretex reduce-epoch <state.bin> <patches.json>');
    }
    const stateBytes = fs.readFileSync(stateFile);
    const patchesJson = JSON.parse(fs.readFileSync(patchesFile, 'utf8'), bigIntReviver) as unknown[];
    const state = unpack(new Uint8Array(stateBytes));
    const parentRoot = bytesToHex(merkleizeState(state));
    const policyAtomsMode = args.includes('--policy-atoms-mode') || args.includes('--r5');

    type PatchRecord = {
      compactPatchBytesHex: string;
      patchHash: string;
      parentStateRoot: string;
      scoreDelta?: bigint;
    };
    const records = patchesJson as PatchRecord[];
    // Delegate ordering + same-parent application to the canonical reducer
    // (applyPatchOntoCurrent + epoch-parent pre-pass + domain-prefixed
    // patchHash tiebreak). The previous inline loop re-validated each patch's
    // parent against the ALREADY-ADVANCED state, so it could only ever apply
    // one patch per epoch.
    const inputs: ReducerInputPatch[] = [];
    const recordByBytes = new Map<string, PatchRecord>();
    for (const r of records) {
      if (r.parentStateRoot.toLowerCase() !== parentRoot.toLowerCase()) continue;
      const wire = hexToBytes(r.compactPatchBytesHex.startsWith('0x') ? r.compactPatchBytesHex : '0x' + r.compactPatchBytesHex);
      const patch = decodePatch(wire);
      recordByBytes.set(Buffer.from(wire).toString('hex'), r);
      inputs.push({ ...makeReducerInput(patch, wire), scoreDelta: r.scoreDelta ?? patch.scoreDelta });
    }
    const output = reduce(state, inputs, 0n, policyAtomsMode);
    const applied = output.accepted.map((a) =>
      recordByBytes.get(Buffer.from(a.patchBytes).toString('hex'))?.patchHash
        ?? computePatchHash(a.patchBytes),
    );

    process.stdout.write(toJsonOutput({
      ok: true,
      newStateRoot: output.newStateRootHex,
      patchSetRoot: output.patchSetRootHex,
      patchesApplied: applied.length,
      acceptedPatchHashes: applied,
    }) + '\n');
    break;
  }

  // ── verify-epoch ──────────────────────────────────────────────────────────
  case 'verify-epoch': {
    // Usage: botcoin-coretex verify-epoch <events.json> [--genesis-state <state.bin>]
    // events.json: { epoch, finalizedEvent, patchEvents, snapshotEvent? }
    const eventsFile = args[0];
    if (!eventsFile) {
      die('verify-epoch: usage: botcoin-coretex verify-epoch <events.json> [--genesis-state state.bin]');
    }
    const eventsData = JSON.parse(fs.readFileSync(eventsFile, 'utf8'), bigIntReviver) as {
      epoch: bigint;
      finalizedEvent: EpochFinalizedEvent | null;
      patchEvents: PatchAcceptedEvent[];
      snapshotEvent: StateSnapshotEvent | null;
    };

    // Reconstruct Uint8Array fields from hex strings if necessary
    if (eventsData.snapshotEvent && typeof eventsData.snapshotEvent.fullStateBytes === 'string') {
      const hex = eventsData.snapshotEvent.fullStateBytes as string;
      (eventsData.snapshotEvent as unknown as Record<string, unknown>)['fullStateBytes'] = hexToBytes(hex);
    }
    for (const pe of eventsData.patchEvents) {
      if (typeof (pe as unknown as Record<string, unknown>)['compactPatchBytes'] === 'string') {
        const hex = (pe as unknown as Record<string, unknown>)['compactPatchBytes'] as string;
        (pe as unknown as Record<string, unknown>)['compactPatchBytes'] = hexToBytes(hex);
      }
    }

    const genesisStateFlag = args.indexOf('--genesis-state');
    let genesisState = undefined;
    if (genesisStateFlag >= 0) {
      const gsFile = args[genesisStateFlag + 1];
      if (gsFile) {
        genesisState = unpack(new Uint8Array(fs.readFileSync(gsFile)));
      }
    }

    const result = verifyEpoch({
      epoch: eventsData.epoch,
      finalizedEvent: eventsData.finalizedEvent,
      patchEvents: eventsData.patchEvents,
      snapshotEvent: eventsData.snapshotEvent,
      ...(genesisState ? { genesisState } : {}),
      // r5 epochs: enforce reserved-region / PolicyAtom grammar in canonical reconstruction (same as scoring).
      ...(args.includes('--policy-atoms-mode') ? { policyAtomsMode: true } : {}),
    });
    process.stdout.write(toJsonOutput(result) + '\n');
    if (result.ok && !result.match) process.exit(3);
    if (!result.ok) process.exit(1);
    break;
  }

  // ── snapshot ──────────────────────────────────────────────────────────────
  case 'snapshot': {
    // Usage: botcoin-coretex snapshot <state.bin>
    // Outputs: { stateRoot, fullStateBytesHex }
    const stateFile = args[0];
    if (!stateFile) {
      die('snapshot: usage: botcoin-coretex snapshot <state.bin>');
    }
    const stateBytes = fs.readFileSync(stateFile);
    const state = unpack(new Uint8Array(stateBytes));
    const stateRoot = bytesToHex(merkleizeState(state));
    const fullStateBytesHex = Buffer.from(pack(state)).toString('hex');
    process.stdout.write(toJsonOutput({ ok: true, stateRoot, fullStateBytesHex }) + '\n');
    break;
  }

  // ── upgrade ───────────────────────────────────────────────────────────────
  case 'upgrade': {
    // Usage: botcoin-coretex upgrade <state.bin> <translation.bin>
    // Or:    botcoin-coretex upgrade --reset <state.bin> <genesis.bin> --epoch N --old-cvh 0x.. --new-cvh 0x..
    if (args[0] === '--reset') {
      const stateFile = args[1];
      const genesisFile = args[2];
      const epochIdx = args.indexOf('--epoch');
      const oldCvhIdx = args.indexOf('--old-cvh');
      const newCvhIdx = args.indexOf('--new-cvh');
      if (!stateFile || !genesisFile || epochIdx < 0 || oldCvhIdx < 0 || newCvhIdx < 0) {
        die('upgrade --reset: requires <state.bin> <genesis.bin> --epoch N --old-cvh 0x.. --new-cvh 0x..');
      }
      const state = unpack(new Uint8Array(fs.readFileSync(stateFile)));
      const genesisState = unpack(new Uint8Array(fs.readFileSync(genesisFile)));
      const epoch = BigInt(args[epochIdx + 1] ?? '0');
      const oldCvh = args[oldCvhIdx + 1] ?? '0x' + '00'.repeat(32);
      const newCvh = args[newCvhIdx + 1] ?? '0x' + '00'.repeat(32);
      const { event, state: newState } = executeReset(state, genesisState, epoch, oldCvh, newCvh);
      const newRoot = bytesToHex(merkleizeState(newState));
      process.stdout.write(toJsonOutput({ ok: true, event, newStateRoot: newRoot }) + '\n');
    } else {
      const stateFile = args[0];
      const translationFile = args[1];
      if (!stateFile || !translationFile) {
        die('upgrade: usage: botcoin-coretex upgrade <state.bin> <translation.bin>');
      }
      const state = unpack(new Uint8Array(fs.readFileSync(stateFile)));
      const translationBytes = new Uint8Array(fs.readFileSync(translationFile));
      const parseResult = parseStatTranslationPatch(translationBytes);
      if (!parseResult.ok) {
        die(`upgrade: parse error: ${parseResult.code} — ${parseResult.message}`);
      }
      const applyResult = applyStatTranslationPatch(state, parseResult.translation);
      process.stdout.write(toJsonOutput(applyResult) + '\n');
      if (!applyResult.ok) process.exit(1);
    }
    break;
  }

  case 'bundle-manifest': {
    const subcmd = args[0];
    if (subcmd === 'build') {
      const repoRoot = flagValue(args, '--repo-root') ?? process.cwd();
      const corpusRoot = requireFlag(args, '--corpus-root');
      const corpusFiles = requireFlag(args, '--corpus-files').split(',').map((s) => s.trim()).filter(Boolean);
      const biEncoderFile = requireFlag(args, '--bi-encoder-manifest');
      const rerankerFile = requireFlag(args, '--reranker-manifest');
      const labelingFile = requireFlag(args, '--labeling-reranker-manifest');
      const snapshotFiles = (flagValue(args, '--snapshot-files') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
      const biEncoder = JSON.parse(fs.readFileSync(biEncoderFile, 'utf8')) as BiEncoderManifest;
      const reranker = JSON.parse(fs.readFileSync(rerankerFile, 'utf8')) as RerankerManifest;
      const labelingReranker = JSON.parse(fs.readFileSync(labelingFile, 'utf8')) as RerankerManifest;
      const manifest = buildBundleManifest({
        repoRoot, corpusRoot, corpusFiles, biEncoder, reranker, labelingReranker, snapshotFiles,
      });
      process.stdout.write(toJsonOutput(manifest) + '\n');
      break;
    }
    if (subcmd === 'verify') {
      const repoRoot = flagValue(args, '--repo-root') ?? process.cwd();
      const manifestFile = requireFlag(args, '--manifest');
      const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8')) as CoreTexBundleManifest;
      const errors = verifyBundleManifest(manifest, repoRoot);
      process.stdout.write(toJsonOutput({ ok: errors.length === 0, errors }) + '\n');
      if (errors.length) process.exit(1);
      break;
    }
    die('bundle-manifest: usage: botcoin-coretex bundle-manifest {build|verify} ...');
  }

  default:
    die(`botcoin-coretex: unknown command "${cmd}"\nusage: botcoin-coretex {decode|apply-patch|eval|reduce-epoch|verify-epoch|snapshot|upgrade|bundle-manifest}`, 1);
}

function flagValue(args: readonly string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

function requireFlag(args: readonly string[], name: string): string {
  return flagValue(args, name) ?? die(`missing ${name}`);
}
