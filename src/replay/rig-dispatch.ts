/**
 * V5 rig-lane dispatch, beside the legacy V4 path — never instead of it.
 *
 * WHY THIS FILE EXISTS AT ALL, GIVEN `coretex-registry.ts` ALREADY DECODES THE ADVANCE.
 *
 * It does, and that is not a coincidence: the rig registry emits
 * `CoreTexStateAdvanced(...)` with the SAME parameter types as the lane
 * `coretex-registry.ts` was written for, so its topic0 is byte-identical and its
 * decoder reads a rig advance correctly today. What that decoder cannot do is tell
 * you WHICH LANE a log belongs to, because topic0 does not say. Two registries
 * emitting one signature are distinguished only by their address.
 *
 * So the addition here is deliberately NOT another decoder. It is:
 *
 *   1. `RIG_EVENT_TOPICS`  — the events the rig lane emits that the registry does
 *      not: the mining contract's credit + epoch entropy events, and the VERIFIER's
 *      epoch-context and policy events. The rig lane's law lives on the verifier,
 *      not the registry, so a validator watching only the registry can never read
 *      the pins it is supposed to check an advance against.
 *   2. `routeRigLog()`     — address-scoped routing. A known topic0 from an address
 *      outside the deployment is "not ours" (the common case, because of the
 *      collision); a known topic0 from the WRONG one of our three addresses is an
 *      error, because something is emitting our events from a contract we did not
 *      expect and there is no safe way to guess which claim to believe.
 *   3. `assertLaneSeparation()` — the collision, asserted rather than described.
 *
 * V4 IS UNTOUCHED. Nothing in `v4.ts` or `coretex-registry.ts` changes; this module
 * imports their topic constants and re-exports them so a caller can hold both
 * dispatch tables at once and see that they overlap.
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
import { bytesToHex } from '../state/merkle.js';
import { CORETEX_EVENT_TOPICS, type RpcLog } from './coretex-registry.js';
import { V4_EVENT_TOPICS } from './v4.js';

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
  'CoreTexEpochContextSet(uint64,bytes32,bytes32,bytes32,bytes32,bytes32)';
/** `RigCoreTexVerifier.sol:90-97` — scheduled by `effectiveEpoch`, never retroactive.
 *  This is what makes HISTORICAL law recoverable from logs alone. */
const SIG_POLICY_SCHEDULED =
  'CoreTexPolicyScheduled(uint32,uint64,bytes32,uint256,uint256[],uint256[])';

/** The rig-lane events that are NOT already in `CORETEX_EVENT_TOPICS`. */
export const RIG_EVENT_TOPICS = {
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
  [CORETEX_EVENT_TOPICS.CoreTexStateAdvanced]: 'registry',
  [CORETEX_EVENT_TOPICS.CoreTexEpochFinalized]: 'registry',
  [RIG_EVENT_TOPICS.RigCoreTexCreditAccepted]: 'mining',
  [RIG_EVENT_TOPICS.RigCreditAccepted]: 'mining',
  [RIG_EVENT_TOPICS.EpochCommitSet]: 'mining',
  [RIG_EVENT_TOPICS.EpochSecretRevealed]: 'mining',
  [RIG_EVENT_TOPICS.CoreTexEpochContextSet]: 'verifier',
  [RIG_EVENT_TOPICS.CoreTexPolicyScheduled]: 'verifier',
} as const;

export const RIG_EVENT_NAMES: Readonly<Record<string, string>> = {
  [CORETEX_EVENT_TOPICS.CoreTexStateAdvanced]: 'CoreTexStateAdvanced',
  [CORETEX_EVENT_TOPICS.CoreTexEpochFinalized]: 'CoreTexEpochFinalized',
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
 * It INCLUDES the V4 advance topic0, and it has to: that is the topic the rig
 * registry actually emits. A filter built from "the rig's own new events" alone
 * retrieves zero advances, which looks exactly like a deployment that never mined.
 */
export const RIG_LOG_TOPICS: readonly string[] = Object.freeze(
  Array.from(
    new Set([
      CORETEX_EVENT_TOPICS.CoreTexStateAdvanced,
      CORETEX_EVENT_TOPICS.CoreTexEpochFinalized,
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
 * (2) and (3) are what collide, and the discriminator is the emitting address.
 * Reported as data so a caller can assert on it rather than trust this comment.
 */
export function laneSeparation(): {
  legacyV4Advance: string;
  canonicalRegistryAdvance: string;
  rigRegistryAdvance: string;
  collidingLanes: readonly ['canonical-registry', 'rig-registry'];
  identical: boolean;
  discriminator: 'emitting address';
  consequence: string;
} {
  return {
    legacyV4Advance: V4_EVENT_TOPICS.CortexStateAdvanced,
    canonicalRegistryAdvance: CORETEX_EVENT_TOPICS.CoreTexStateAdvanced,
    rigRegistryAdvance: CORETEX_EVENT_TOPICS.CoreTexStateAdvanced,
    collidingLanes: ['canonical-registry', 'rig-registry'] as const,
    identical: true,
    discriminator: 'emitting address',
    consequence:
      'the rig registry emits the same advance signature as the canonical registry lane, so a ' +
      'router that keys on topic0 alone will mix two lanes of confirmed history together. The ' +
      'original v4 pair in v4.ts is a third, distinct set and collides with neither',
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
  const expected = eventTopic(
    'CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,' +
      'bytes32,bytes32,uint256,uint16,bytes)',
  );
  if (CORETEX_EVENT_TOPICS.CoreTexStateAdvanced !== expected) {
    throw new RigDispatchError(
      'the registry advance topic0 no longer matches its recorded signature; re-read ' +
        'routeRigLog and docs/V5-RIG-VALIDATOR.md before relaxing anything',
    );
  }
}
