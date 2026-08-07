/**
 * V5 rig-lane dispatch, beside the legacy V4 path — never instead of it.
 *
 * WHY THIS FILE EXISTS AT ALL, GIVEN `coretex-registry.ts` ALREADY DECODES THE ADVANCE.
 *
 * Descriptor-v3 collapsed the two context words into `epochContextRoot`, so the live rig
 * registry event signatures and topics moved. `coretex-registry.ts` remains the explicit
 * descriptor-v2/legacy decoder; this module owns the v3 live shapes and never dual-accepts them.
 *
 * The live addition here is deliberately separate from the historical decoder. It is:
 *
 *   1. `RIG_EVENT_TOPICS` plus the v3 advance/finalize decoders — the registry's live
 *      shapes, the mining contract's credit + epoch entropy events, and the VERIFIER's
 *      epoch-context and policy events. The rig lane's law lives on the verifier,
 *      not the registry, so a validator watching only the registry can never read
 *      the pins it is supposed to check an advance against.
 *   2. `routeRigLog()`     — address-scoped routing. A known topic0 from an address
 *      outside the deployment is "not ours" (the common case, because of the
 *      collision); a known topic0 from the WRONG one of our three addresses is an
 *      error, because something is emitting our events from a contract we did not
 *      expect and there is no safe way to guess which claim to believe.
 *   3. `assertLaneSeparation()` — the v3 topic separation, asserted rather than described.
 *
 * `v4.ts` is untouched. `coretex-registry.ts` is retained as the named descriptor-v2
 * historical decoder; this module imports its topic constants and re-exports its legacy
 * discriminator so a caller can hold both generations without silently dual-accepting them.
 *
 * PARITY WITH THE PYTHON VALIDATOR. Every topic0 below is derived here by hashing
 * the signature string with this package's own keccak — the same way
 * `python/coretex_validator/rig_events.py` derives it, and the same way
 * `coretex-registry.ts::eventTopic` already did. The two implementations are
 * cross-checked against each other by `test/unit/rig-dispatch.test.mjs`, which
 * shells the Python module and compares tables. Two independent derivations that
 * agree is worth more than one derivation copied twice.
 */
import { keccak256 } from '../state/keccak256.js';
import { bytesToHex, hexToBytes } from '../state/merkle.js';
import {
  CORETEX_EVENT_TOPICS,
  LEGACY_V2_RIG_TRANSITION_DESCRIPTOR_BYTES,
  LEGACY_V2_RIG_TRANSITION_DESCRIPTOR_VERSION,
  isLegacyV2RigLaneTransitionDescriptor,
} from './coretex-registry.js';
import { V4_EVENT_TOPICS, type RpcLog } from './v4.js';

/** Re-exported so a caller holding both dispatch tables can classify a payload without reaching
 *  into the V4 module, and so the two files cannot drift on what "a rig advance looks like". */
export {
  LEGACY_V2_RIG_TRANSITION_DESCRIPTOR_BYTES,
  LEGACY_V2_RIG_TRANSITION_DESCRIPTOR_VERSION,
  isLegacyV2RigLaneTransitionDescriptor,
};

/** Live `RigCoreTexVerifier.TRANSITION_DESCRIPTOR_BYTES`. */
export const RIG_TRANSITION_DESCRIPTOR_BYTES = 97;
/** Live opaque descriptor version tag. */
export const RIG_TRANSITION_DESCRIPTOR_VERSION = 0x21;

export function isRigLaneTransitionDescriptor(compactPatchBytes: Uint8Array): boolean {
  return compactPatchBytes.length === RIG_TRANSITION_DESCRIPTOR_BYTES
    && compactPatchBytes[0] === RIG_TRANSITION_DESCRIPTOR_VERSION;
}

function eventTopic(sig: string): string {
  return bytesToHex(keccak256(new TextEncoder().encode(sig)));
}

// ── signatures, transcribed from the exact rig sources ──
/** `BotcoinMiningRigsV1.sol:165-174` — join source B. */
const SIG_CORETEX_CREDIT_ACCEPTED =
  'RigCoreTexCreditAccepted(uint64,uint256,address,uint64,bytes32,bytes32,uint256,uint256)';
/** `BotcoinMiningRigsV1.sol:155-163` — the STANDARD receipt. It shares the rig's
 *  `rigNextIndex`/`rigLastReceiptHash` chain, so continuity replay must consume it
 *  too; a replay that saw only CoreTex receipts would report a gap at every one. */
const SIG_CREDIT_ACCEPTED =
  'RigCreditAccepted(uint64,uint256,address,uint64,bytes32,bytes32,uint256)';
const SIG_EPOCH_COMMIT_SET = 'EpochCommitSet(uint64,bytes32)';
const SIG_EPOCH_SECRET_REVEALED = 'EpochSecretRevealed(uint64,bytes32)';
/** `RigCoreTexVerifier.sol:82-89` — the epoch's law pins, on the VERIFIER. */
const SIG_EPOCH_CONTEXT_SET =
  'CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32)';
/** `RigCoreTexVerifier.sol:90-97` — scheduled by `effectiveEpoch`, never retroactive.
 *  This is what makes HISTORICAL law recoverable from logs alone. */
const SIG_POLICY_SCHEDULED =
  'CoreTexPolicyScheduled(uint32,uint64,bytes32,uint256,uint256[],uint256[])';

const SIG_STATE_ADVANCED =
  'CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint16,bytes)';
const SIG_EPOCH_FINALIZED =
  'CoreTexEpochFinalized(uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)';

/** Every live descriptor-v3 rig event. */
export const RIG_EVENT_TOPICS = {
  CoreTexStateAdvanced: eventTopic(SIG_STATE_ADVANCED),
  CoreTexEpochFinalized: eventTopic(SIG_EPOCH_FINALIZED),
  RigCoreTexCreditAccepted: eventTopic(SIG_CORETEX_CREDIT_ACCEPTED),
  RigCreditAccepted: eventTopic(SIG_CREDIT_ACCEPTED),
  EpochCommitSet: eventTopic(SIG_EPOCH_COMMIT_SET),
  EpochSecretRevealed: eventTopic(SIG_EPOCH_SECRET_REVEALED),
  CoreTexEpochContextSet: eventTopic(SIG_EPOCH_CONTEXT_SET),
  CoreTexPolicyScheduled: eventTopic(SIG_POLICY_SCHEDULED),
} as const;

/** Which of the three contracts each event is only ever legitimate from. */
export type RigEmitterRole = 'registry' | 'mining' | 'verifier';

export const RIG_EXPECTED_EMITTER: Readonly<Record<string, RigEmitterRole>> = {
  [RIG_EVENT_TOPICS.CoreTexStateAdvanced]: 'registry',
  [RIG_EVENT_TOPICS.CoreTexEpochFinalized]: 'registry',
  [RIG_EVENT_TOPICS.RigCoreTexCreditAccepted]: 'mining',
  [RIG_EVENT_TOPICS.RigCreditAccepted]: 'mining',
  [RIG_EVENT_TOPICS.EpochCommitSet]: 'mining',
  [RIG_EVENT_TOPICS.EpochSecretRevealed]: 'mining',
  [RIG_EVENT_TOPICS.CoreTexEpochContextSet]: 'verifier',
  [RIG_EVENT_TOPICS.CoreTexPolicyScheduled]: 'verifier',
} as const;

export const RIG_EVENT_NAMES: Readonly<Record<string, string>> = {
  [RIG_EVENT_TOPICS.CoreTexStateAdvanced]: 'CoreTexStateAdvanced',
  [RIG_EVENT_TOPICS.CoreTexEpochFinalized]: 'CoreTexEpochFinalized',
  [RIG_EVENT_TOPICS.RigCoreTexCreditAccepted]: 'RigCoreTexCreditAccepted',
  [RIG_EVENT_TOPICS.RigCreditAccepted]: 'RigCreditAccepted',
  [RIG_EVENT_TOPICS.EpochCommitSet]: 'EpochCommitSet',
  [RIG_EVENT_TOPICS.EpochSecretRevealed]: 'EpochSecretRevealed',
  [RIG_EVENT_TOPICS.CoreTexEpochContextSet]: 'CoreTexEpochContextSet',
  [RIG_EVENT_TOPICS.CoreTexPolicyScheduled]: 'CoreTexPolicyScheduled',
} as const;

/**
 * The `eth_getLogs` topic0 OR-set a rig validator subscribes to.
 *
 * It contains the descriptor-v3 registry, mining, and verifier topics only. The colliding
 * descriptor-v2/V4 topic is available through the explicit historical table below and is never
 * dual-accepted by this live subscription.
 */
export const RIG_LOG_TOPICS: readonly string[] = Object.freeze(
  Array.from(
    new Set([
      ...Object.values(RIG_EVENT_TOPICS),
    ]),
  ).sort(),
);

/** The V4 subscription, re-exported unchanged so both tables can be held at once. */
export const V4_LOG_TOPICS: readonly string[] = Object.freeze(
  Object.values(V4_EVENT_TOPICS).slice().sort(),
);

export interface RigDeploymentAddresses {
  readonly registry: string;
  readonly mining: string;
  readonly verifier: string;
}

export interface RigRoute {
  /** `null` when the log is not this deployment's — ignore it, do not error. */
  readonly event: string | null;
  readonly emitter: RigEmitterRole | null;
  readonly topic0: string;
}

export class RigDispatchError extends Error {}

function word(data: Uint8Array, index: number): string {
  const start = index * 32;
  if (start + 32 > data.length) throw new RigDispatchError(`ABI word ${index} is out of range`);
  return bytesToHex(data.subarray(start, start + 32));
}

function wordNum(data: Uint8Array, index: number): bigint {
  const raw = hexToBytes(word(data, index));
  let value = 0n;
  for (const byte of raw) value = (value << 8n) | BigInt(byte);
  return value;
}

function topicNum(log: RpcLog, index: number): bigint {
  const value = log.topics?.[index];
  if (!value) throw new RigDispatchError(`topic ${index} is absent`);
  return BigInt(value);
}

function topicAddress(log: RpcLog, index: number): string {
  const value = log.topics?.[index]?.replace(/^0x/, '') ?? '';
  if (value.length !== 64 || !/^0{24}[0-9a-fA-F]{40}$/.test(value)) {
    throw new RigDispatchError(`topic ${index} is not a canonically padded address`);
  }
  return `0x${value.slice(24).toLowerCase()}`;
}

export interface RigStateAdvancedEvent {
  readonly epoch: bigint;
  readonly transitionIndex: bigint;
  readonly miner: string;
  readonly parentStateRoot: string;
  readonly newStateRoot: string;
  readonly patchHash: string;
  readonly evalReportHash: string;
  readonly coreVersionHash: string;
  readonly epochContextRoot: string;
  readonly improvementCredits: bigint;
  readonly transitionFormatVersion: number;
  readonly compactPatchBytes: Uint8Array;
}

export function decodeRigStateAdvanced(log: RpcLog): RigStateAdvancedEvent | null {
  if ((log.topics?.[0] ?? '').toLowerCase() !== RIG_EVENT_TOPICS.CoreTexStateAdvanced) return null;
  if (log.topics.length !== 4) throw new RigDispatchError('CoreTexStateAdvanced needs 4 topics');
  const data = hexToBytes(log.data);
  const offset = wordNum(data, 8);
  if (offset !== 9n * 32n) throw new RigDispatchError(`compactPatchBytes offset ${offset} is not 288`);
  const length = wordNum(data, Number(offset / 32n));
  if (length > BigInt(Number.MAX_SAFE_INTEGER)) throw new RigDispatchError('descriptor length is too large');
  const start = Number(offset) + 32;
  const end = start + Number(length);
  const paddedEnd = start + Math.ceil(Number(length) / 32) * 32;
  if (paddedEnd !== data.length || data.subarray(end, paddedEnd).some((b) => b !== 0)) {
    throw new RigDispatchError('compactPatchBytes tail is truncated, padded non-zero, or has trailing data');
  }
  const version = wordNum(data, 7);
  if (version > 0xffffn) throw new RigDispatchError('transitionFormatVersion has dirty high bits');
  return {
    epoch: topicNum(log, 1), transitionIndex: topicNum(log, 2), miner: topicAddress(log, 3),
    parentStateRoot: word(data, 0), newStateRoot: word(data, 1), patchHash: word(data, 2),
    evalReportHash: word(data, 3), coreVersionHash: word(data, 4), epochContextRoot: word(data, 5),
    improvementCredits: wordNum(data, 6), transitionFormatVersion: Number(version),
    compactPatchBytes: data.subarray(start, end),
  };
}

export interface RigEpochFinalizedEvent {
  readonly epoch: bigint;
  readonly parentStateRoot: string;
  readonly finalStateRoot: string;
  readonly coreVersionHash: string;
  readonly epochContextRoot: string;
  readonly patchSetRoot: string;
  readonly scoreRoot: string;
}

export function decodeRigEpochFinalized(log: RpcLog): RigEpochFinalizedEvent | null {
  if ((log.topics?.[0] ?? '').toLowerCase() !== RIG_EVENT_TOPICS.CoreTexEpochFinalized) return null;
  if (log.topics.length !== 2) throw new RigDispatchError('CoreTexEpochFinalized needs 2 topics');
  const data = hexToBytes(log.data);
  if (data.length !== 6 * 32) throw new RigDispatchError('CoreTexEpochFinalized needs 6 data words');
  return {
    epoch: topicNum(log, 1), parentStateRoot: word(data, 0), finalStateRoot: word(data, 1),
    coreVersionHash: word(data, 2), epochContextRoot: word(data, 3),
    patchSetRoot: word(data, 4), scoreRoot: word(data, 5),
  };
}

function roleOf(address: string | undefined, d: RigDeploymentAddresses): RigEmitterRole | null {
  const target = (address ?? '').toLowerCase();
  if (target === d.registry.toLowerCase()) return 'registry';
  if (target === d.mining.toLowerCase()) return 'mining';
  if (target === d.verifier.toLowerCase()) return 'verifier';
  return null;
}

/**
 * Classify one log against a rig deployment.
 *
 * UNKNOWN topic0 is ignored, never an error: a registry that gains an
 * administrative event must not brick every validator in the field. A KNOWN
 * topic0 from the wrong one of our own addresses IS an error — see the header.
 */
export function routeRigLog(log: RpcLog, deployment: RigDeploymentAddresses): RigRoute {
  const topic0 = (log.topics?.[0] ?? '').toLowerCase();
  if (!topic0) return { event: null, emitter: null, topic0: '' };
  const name = RIG_EVENT_NAMES[topic0];
  const emitter = roleOf(log.address, deployment);
  if (!name || emitter === null) return { event: null, emitter: null, topic0 };
  const expected = RIG_EXPECTED_EMITTER[topic0];
  if (emitter !== expected) {
    throw new RigDispatchError(
      `${name} arrived from this deployment's ${emitter} (${log.address}) but only the ` +
        `${expected} emits it; topic0 is not an identity and this log cannot be attributed`,
    );
  }
  return { event: name, emitter, topic0 };
}

/**
 * The three advance generations this client can meet, and which two collide.
 *
 * There are THREE, not two, and conflating the first with the second is its own
 * quiet bug:
 *
 *   1. `CortexStateAdvanced(uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint16)`
 *      — the ORIGINAL v4 pair in `v4.ts`, alongside `CoretexPatchBytes`. Its own
 *      header calls it superseded. Distinct topic0; nothing collides with it.
 *   2. `CoreTexStateAdvanced(...)` from `coretex-registry.ts` — the canonical
 *      registry lane in production today.
 *   3. The RIG registry's advance — signature-identical to (2), so topic0-identical.
 *
 * (2) and (3) are what collide. The PRIMARY discriminator is the emitting address, and it is now
 * MANDATORY rather than advisory: `coretexRangeLogs` refuses a query with no address filter,
 * because a topic-only query returns both lanes interleaved and the result cannot be attributed
 * afterwards. The PAYLOAD discriminator is the backstop for a log that arrived anyway — a rig
 * descriptor-v2 used a 105-byte `0x20` discriminator in the colliding legacy decoder. Live
 * descriptor-v3 moved to a distinct event topic and carries a 97-byte descriptor beginning
 * `0x21`; the old payload classifier remains only in `coretex-registry.ts` for historical logs.
 *
 * Reported as data so a caller can assert on it rather than trust this comment.
 */
export function laneSeparation(): {
  legacyV4Advance: string;
  canonicalRegistryAdvance: string;
  rigRegistryAdvance: string;
  collidingLanes: readonly [];
  identical: boolean;
  discriminator: 'emitting address';
  addressFilterMandatory: true;
  payloadDiscriminator: { descriptorBytes: number; versionByte: number };
  consequence: string;
} {
  return {
    legacyV4Advance: V4_EVENT_TOPICS.CortexStateAdvanced,
    canonicalRegistryAdvance: CORETEX_EVENT_TOPICS.CoreTexStateAdvanced,
    rigRegistryAdvance: RIG_EVENT_TOPICS.CoreTexStateAdvanced,
    collidingLanes: [] as const,
    identical: false,
    discriminator: 'emitting address',
    addressFilterMandatory: true,
    payloadDiscriminator: {
      descriptorBytes: RIG_TRANSITION_DESCRIPTOR_BYTES,
      versionByte: RIG_TRANSITION_DESCRIPTOR_VERSION,
    },
    consequence:
      'descriptor-v3 moved the rig registry signature by replacing corpusRoot + ' +
      'activeFrontierRoot with epochContextRoot. The previous topic remains explicitly legacy ' +
      'and is not accepted by the live rig router',
  };
}

/**
 * Fail closed if the exact registry ever renames its advance event.
 *
 * That would be a GOOD change — but this module routes on the assumption that it
 * has not happened, and an assumption that quietly stops holding is worse than one
 * that breaks loudly.
 */
export function assertLaneSeparation(): void {
  const expected = eventTopic(SIG_STATE_ADVANCED);
  if (RIG_EVENT_TOPICS.CoreTexStateAdvanced !== expected) {
    throw new RigDispatchError(
      'the registry advance topic0 no longer matches its recorded signature; re-read ' +
        'routeRigLog and docs/V5-RIG-VALIDATOR.md before relaxing anything',
    );
  }
  if (RIG_EVENT_TOPICS.CoreTexStateAdvanced === CORETEX_EVENT_TOPICS.CoreTexStateAdvanced) {
    throw new RigDispatchError('the live descriptor-v3 advance topic collides with legacy v2');
  }
}
