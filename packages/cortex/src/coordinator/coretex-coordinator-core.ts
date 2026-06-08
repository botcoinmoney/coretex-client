/**
 * v0 CoreTex production coordinator core — the hardened semantics that
 * `coretex_miner_testing/mainnet-coord-v16.mjs` prototyped, ported into a
 * production-shaped TypeScript module. NO sims, NO proxy scoring, NO local
 * shell-outs — those are the responsibility of the production server harness
 * that mounts this core via the dependency interfaces below.
 *
 * Hardened invariants enforced here:
 *   1. Chain-confirmed-only root tracking: `liveState` / `liveRoot` /
 *      `stateByRoot` only mutate from chain-confirmed
 *      `CoreTexStateAdvanced` events processed through `applyChainEvent`.
 *   2. Per-event verification: contiguous `transitionIndex`, event `parent ==
 *      coord.liveRoot`, event `coreVersionHash` / `corpusRoot` /
 *      `activeFrontierRoot` match configured pins, recomputed `patchHash`,
 *      r5-aware `applyPatch`, decoded `wordCount == event.wordCount`,
 *      recomputed `newStateRoot == event.newStateRoot`.
 *   3. Finality gate: events at `head − CONFIRMATION_DEPTH` are NOT applied.
 *   4. Snapshot-based reorg detection + rollback: per-event
 *      `{transitionIndex, blockNumber, blockHash, root, state}`; reorgs
 *      detected by re-verifying the deepest snapshot's `blockHash` against
 *      chain truth; rollback to the deepest still-canonical snapshot, replay
 *      forward.
 *   5. Pending receipt lifecycle: `pending` → `confirmed` on matching event;
 *      `pending` → `stale` if a different same-parent event lands first;
 *      `pending` → `expired` once `expiresAt` elapses. Live state never
 *      mutates from `stale` or `expired` records.
 *   6. Dual-hash receipt lookup: receipts are cached under BOTH the
 *      miner-submitted (original) `patchHash` AND the coordinator-rewritten
 *      signed `patchHash`. Expired records release the dedup key under the
 *      ORIGINAL hash so the miner can re-submit identical bytes.
 *   7. Stale receipt lookup: `/coretex/receipt/:hash` for a `stale` pending
 *      returns 409 + `PendingReceiptStale` + no transaction (no
 *      broadcastable calldata handed back).
 *   8. Parity gate: `registry.transitionCount(epoch) >=
 *      coord.lastTransitionIndex + 1`; when caught up,
 *      `registry.liveStateRoot(epoch) == coord.liveRoot`. Mismatch ->
 *      signing disabled + `acceptingSubmissions = false`.
 *
 * Designed for fork/mocked unit testing — every external dependency (chain
 * RPC, signer, parent-substrate loader, real eval/scoring path) is a typed
 * interface the test harness mocks. NO `cast` shellouts here.
 */

import { merkleizeState, bytesToHex, decodePatch, encodePatch, applyPatch, keccak256, computePatchHash } from '../index.js';
import {
  DEFAULT_CORETEX_WORK_POLICY,
  OUTCOME_CORETEX_SCREENER_PASS,
  OUTCOME_CORETEX_STATE_ADVANCE,
  computeCoreTexWorkUnitsBps,
  type CoreTexWorkPolicy,
} from '../rewards/work-units.js';
import type { CortexState } from '../state/types.js';

// ── chain log shape ────────────────────────────────────────────────────────
export interface CoreTexStateAdvancedEvent {
  readonly blockNumber: bigint;
  readonly blockHash: string;
  readonly logIndex: bigint;
  readonly epoch: bigint;
  readonly transitionIndex: bigint;
  readonly miner: string;
  readonly parent: string;
  readonly newRoot: string;
  readonly patchHash: string;
  readonly evalReportHash: string;
  readonly coreV: string;
  readonly corpus: string;
  readonly frontier: string;
  readonly credits: bigint;
  readonly wordCount: number;
  readonly compactPatchBytes: string;
}

// ── external dependencies (interface; production passes ethers/viem etc.) ──
export interface ChainClient {
  /** Latest block height. */
  getBlockNumber(): Promise<number>;
  /** Block hash at a specific height (or null if not canonical / missing). */
  getBlockHashAt(blockNumber: number): Promise<string | null>;
  /** Range-scan CoreTexStateAdvanced events. */
  getStateAdvancedEvents(fromBlock: number, toBlock: number): Promise<readonly CoreTexStateAdvancedEvent[]>;
  /** Block of the CoreTexEpochStarted event for `epoch`. */
  getEpochStartedBlock(epoch: bigint): Promise<number>;
  /** Registry's current liveStateRoot and transitionCount for `epoch`. */
  getRegistryEpoch(epoch: bigint): Promise<{ readonly liveStateRoot: string; readonly transitionCount: number }>;
  /** Registry's epoch pins (parentStateRoot, coreVersionHash, corpusRoot, etc.) */
  getRegistryEpochPins(epoch: bigint): Promise<RegistryEpochPins>;
  /** V4 currentEpoch (must mirror V3.currentEpoch). */
  getV4CurrentEpoch(): Promise<bigint>;
  /** V4.epochCommit for an epoch (zero = not set, blocks standard receipts). */
  getV4EpochCommit(epoch: bigint): Promise<string>;
  /** V4.coordinatorSigner address — production boot must equal configured signer. */
  getV4CoordinatorSigner(): Promise<string>;
  /** V4.coreTexRegistry address — production boot must equal configured registry. */
  getV4CoreTexRegistry(): Promise<string>;
  /** Configured Base chainId. */
  getChainId(): Promise<bigint>;
  /** V4 miner solve-chain cursor + screener cap state. */
  getMinerCoreTexCounters(epoch: bigint, miner: string): Promise<CoreTexMinerCounters>;
  /** V4 global CoreTex state-advance difficulty counter. */
  getQualifiedScreenerPassesSinceLastStateAdvance(epoch: bigint): Promise<number>;
}

export interface CoreTexMinerCounters {
  readonly screenersThisEpoch: number;
  readonly nextIndex: bigint;
  readonly lastReceiptHash: string;
}

export interface RegistryEpochPins {
  readonly parentStateRoot: string;
  readonly coreVersionHash: string;
  readonly corpusRoot: string;
  readonly activeFrontierRoot: string;
  readonly baselineManifestHash: string;
  readonly hiddenSeedCommit: string;
}

/** Production parent-substrate loader. Called once at boot.
 *  Returns the packed 1024-word state whose merkle root equals the registry's
 *  `epochParentStateRoot`. If the parent is genesis (all-zero), this may return
 *  the zero state directly. */
export type ParentSubstrateLoader = (parentRoot: string) => Promise<CortexState> | CortexState;

/** Production real eval / scoring path. NO proxy scoring. */
export interface RealEvaluator {
  scorePatch(input: {
    patchBytesHex: string;
    parentStateRoot: string;
    miner: string;
  }): Promise<EvalResult> | EvalResult;
}

export type EvalResult =
  | { readonly outcome: 'reject'; readonly code: string; readonly reason: string;
      readonly deterministicDeltaPpm?: number; readonly requiredDeltaPpm?: number }
  | { readonly outcome: 'screener_pass'; readonly deterministicDeltaPpm: number;
      readonly evalReportHash: string; readonly artifactHash: string }
  | { readonly outcome: 'state_advance'; readonly deterministicDeltaPpm: number;
      readonly evalReportHash: string; readonly artifactHash: string;
      readonly scoreBeforePpm: number; readonly scoreAfterPpm: number;
      /** Coord-rewritten patch bytes whose embedded scoreDelta matches scoreAfter - scoreBefore. */
      readonly rewrittenPatchBytesHex: string; };

export interface CoreTexReceiptPayload {
  readonly epochId: bigint;
  readonly solveIndex: bigint;
  readonly prevReceiptHash: string;
  readonly outcome: number;
  readonly challengeId: string;
  readonly parentStateRoot: string;
  readonly newStateRoot: string;
  readonly corpusRoot: string;
  readonly activeFrontierRoot: string;
  readonly coreVersionHash: string;
  readonly evalReportHash: string;
  readonly patchHash: string;
  readonly artifactHash: string;
  readonly worldSeed: bigint;
  readonly rulesVersion: number;
  readonly workPolicyHash: string;
  readonly workUnitsBps: bigint;
  readonly difficultyCountSnapshot: bigint;
  readonly stateWordCount: number;
  readonly scoreBeforePpm: number;
  readonly scoreAfterPpm: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly compactPatchBytes: string;
}

export interface CoreTexReceiptSigner {
  signCoreTexReceipt(input: {
    readonly miner: string;
    readonly receipt: CoreTexReceiptPayload;
  }): Promise<{ readonly signature: string; readonly transactionData: string; readonly receipt?: unknown }>
    | { readonly signature: string; readonly transactionData: string; readonly receipt?: unknown };
}

// ── configuration ──────────────────────────────────────────────────────────
export interface CoreTexCoordinatorConfig {
  readonly epoch: bigint;
  readonly expectedChainId: bigint;
  readonly v4Address: string;
  readonly registryAddress: string;
  readonly expectedCoordinatorSigner: string;
  readonly expectedEpochPins: RegistryEpochPins;
  readonly confirmationDepth: number;
  readonly receiptTtlSec: number;
  readonly perMinerScreenerCap?: number;
  readonly screenerThresholdPpm?: number;
  readonly minImprovementPpm?: number;
  readonly replayTolerancePpm?: number;
  readonly patchWordBudget?: number;
  readonly maxPatchBytes?: number;
  readonly allowedPatchTypes?: readonly unknown[];
  readonly activeSubstrateSurfaces?: readonly string[];
  readonly pipelineVersion?: string;
  readonly memoryIRSchemaVersion?: string;
  readonly runwayTelemetry?: Record<string, unknown>;
  readonly baselineScorePpm?: number;
  readonly recentNoiseFloorPpm?: number;
  readonly rulesVersion?: number;
  readonly workPolicyHash?: string;
  readonly workPolicy?: CoreTexWorkPolicy;
}

// ── coordinator state ──────────────────────────────────────────────────────
type PendingState = 'pending' | 'confirmed' | 'stale' | 'expired';

export interface PendingReceipt {
  readonly originalPatchHash: string;
  readonly signedPatchHash: string;
  readonly parentRoot: string;
  readonly expectedNewRoot: string;
  readonly compactPatchBytes: string;
  readonly miner: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  state: PendingState;
}

export interface ReceiptEnvelope {
  readonly status: 'accepted';
  readonly outcome: 'SCREENER_PASS' | 'STATE_ADVANCE';
  readonly patchHash: string;
  readonly evalReportHash: string;
  readonly receipt: unknown;
  readonly transaction: { readonly to: string; readonly chainId: number; readonly value: string; readonly data: string };
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface CoreTexCoordinatorMetrics {
  readonly reorgRollbackCount: number;
  readonly parityMismatchCount: number;
  readonly epochMismatchCount: number;
  readonly receiptExpiryCount: number;
  readonly staleReceiptCount: number;
  readonly evalFailureCount: number;
  readonly signerFailureCount: number;
  readonly watcherFaultCount: number;
  readonly submitRejectedByCode: Readonly<Record<string, number>>;
}

interface Snapshot {
  readonly transitionIndex: bigint;
  readonly blockNumber: bigint;
  readonly blockHash: string;
  readonly parent: string;
  readonly root: string;
  readonly patchHash: string;
  readonly state: CortexState;
}

/**
 * Production CoreTex coordinator core. Construct, call `boot()`, then handle
 * `tick()` from an external scheduler. Submit handling goes through `submit()`;
 * receipt lookup goes through `getReceiptByHash(hash)`.
 *
 * Mocked-RPC test pattern:
 *
 * ```ts
 * const chain = new MockChain({ epoch: 106n, events: [...] });
 * const evaluator = new MockEvaluator();
 * const coord = new CoreTexCoordinatorCore(config, chain, parentLoader, evaluator);
 * await coord.boot();
 * await coord.tick();  // simulates one watcher tick
 * ```
 */
export class CoreTexCoordinatorCore {
  // confirmed state
  private liveState: CortexState = { words: [] };
  private liveRoot = '';
  private parentState: CortexState = { words: [] };
  private parentRoot = '';
  private lastTransitionIndex = -1n;
  private readonly stateByRoot = new Map<string, CortexState>();
  private readonly snapshots: Snapshot[] = [];
  private static readonly MAX_SNAPSHOTS = 64;

  private signingEnabled = false;
  private unhealthyReason: string | null = 'startup-replay-pending';
  private chainLiveRoot = '';
  private chainTransitionCount = 0;
  private lastScannedBlock = 0;
  private epochStartBlock = 0;
  private finalityLagBlocks = 0;
  private lastEpochMismatch: bigint | null = null;

  private readonly pendingByPatchHash = new Map<string, PendingReceipt>();
  private readonly receiptCache = new Map<string, ReceiptEnvelope>();
  private readonly expiredReceiptTombstones = new Map<string, number>();
  private readonly submitDedup = new Map<string, number>();
  private readonly metrics = {
    reorgRollbackCount: 0,
    parityMismatchCount: 0,
    epochMismatchCount: 0,
    receiptExpiryCount: 0,
    staleReceiptCount: 0,
    evalFailureCount: 0,
    signerFailureCount: 0,
    watcherFaultCount: 0,
    submitRejectedByCode: {} as Record<string, number>,
  };

  constructor(
    private readonly config: CoreTexCoordinatorConfig,
    private readonly chain: ChainClient,
    private readonly parentLoader: ParentSubstrateLoader,
    private readonly evaluator: RealEvaluator,
    private readonly signer?: CoreTexReceiptSigner,
  ) {}

  // ── boot-time wiring gates (audit-3 R3 P5) ────────────────────────────────
  async boot(): Promise<void> {
    this.validateStaticConfig();
    const onChainChain = await this.chain.getChainId();
    if (onChainChain !== this.config.expectedChainId) {
      throw new Error(`coord: chainId ${onChainChain} ≠ expected ${this.config.expectedChainId}`);
    }
    const v4Epoch = await this.chain.getV4CurrentEpoch();
    if (v4Epoch !== this.config.epoch) {
      throw new Error(`coord: V4.currentEpoch ${v4Epoch} ≠ configured ${this.config.epoch}`);
    }
    const epochCommit = await this.chain.getV4EpochCommit(this.config.epoch);
    if (epochCommit === '0x' + '00'.repeat(32)) {
      throw new Error(`coord: V4.epochCommit(${this.config.epoch}) is zero — set it before booting`);
    }
    const onChainSigner = await this.chain.getV4CoordinatorSigner();
    if (onChainSigner.toLowerCase() !== this.config.expectedCoordinatorSigner.toLowerCase()) {
      throw new Error(`coord: V4.coordinatorSigner ${onChainSigner} ≠ configured ${this.config.expectedCoordinatorSigner}`);
    }
    const onChainRegistry = await this.chain.getV4CoreTexRegistry();
    if (onChainRegistry.toLowerCase() !== this.config.registryAddress.toLowerCase()) {
      throw new Error(`coord: V4.coreTexRegistry ${onChainRegistry} ≠ configured ${this.config.registryAddress}`);
    }
    const onChainPins = await this.chain.getRegistryEpochPins(this.config.epoch);
    for (const k of ['parentStateRoot', 'coreVersionHash', 'corpusRoot', 'activeFrontierRoot', 'baselineManifestHash', 'hiddenSeedCommit'] as const) {
      if (onChainPins[k].toLowerCase() !== this.config.expectedEpochPins[k].toLowerCase()) {
        throw new Error(`coord: registry.${k} ${onChainPins[k]} ≠ configured ${this.config.expectedEpochPins[k]}`);
      }
    }
    // Load parent substrate and verify merkle equality
    const parent = await this.parentLoader(onChainPins.parentStateRoot);
    const recomputed = bytesToHex(merkleizeState(parent));
    if (recomputed.toLowerCase() !== onChainPins.parentStateRoot.toLowerCase()) {
      throw new Error(`coord: parent substrate merkles to ${recomputed} ≠ registry pin ${onChainPins.parentStateRoot}`);
    }
    this.liveState = parent;
    this.liveRoot = onChainPins.parentStateRoot.toLowerCase();
    this.parentState = { words: [...parent.words] };
    this.parentRoot = this.liveRoot;
    this.stateByRoot.set(this.liveRoot, this.liveState);

    // Startup replay (audit-3 R2 #2 — replay from epoch start, NOT recent N blocks)
    const epochStartBlock = await this.chain.getEpochStartedBlock(this.config.epoch);
    this.epochStartBlock = epochStartBlock;
    const replayHead = await this.chain.getBlockNumber();
    // R3 audit-2: replay only through safeHead = head - depth
    const safeHead = Math.max(epochStartBlock, replayHead - this.config.confirmationDepth);
    const events = await this.chain.getStateAdvancedEvents(epochStartBlock, safeHead);
    const sorted = [...events].sort((a, b) => {
      const db = Number(a.blockNumber - b.blockNumber);
      if (db !== 0) return db;
      return Number(a.logIndex - b.logIndex);
    });
    for (const ev of sorted) this.applyChainEvent(ev);
    this.lastScannedBlock = safeHead; // R3 audit-2: start watcher from safeHead, not latest head
    const available = await this.parityCheck();
    if (!available && !this.isAwaitingFinality()) {
      throw new Error(`coord: HARD-FAIL post-replay parity (${this.unhealthyReason})`);
    }
    if (available) {
      this.signingEnabled = true;
      this.unhealthyReason = null;
    }
  }

  // ── watcher tick (called periodically) ────────────────────────────────────
  async tick(): Promise<void> {
    try {
      if (!(await this.checkEpochStillCurrent())) {
        this.gcPending(Math.floor(Date.now() / 1000));
        return;
      }
      const head = await this.chain.getBlockNumber();
      const safeHead = head - this.config.confirmationDepth;
      this.finalityLagBlocks = head - this.lastScannedBlock;
      // Reorg detection: re-verify deepest snapshot's blockHash
      if (this.snapshots.length > 0) {
        const deepest = this.snapshots[this.snapshots.length - 1]!;
        const canonical = await this.chain.getBlockHashAt(Number(deepest.blockNumber));
        if (canonical && canonical.toLowerCase() !== deepest.blockHash.toLowerCase()) {
          if (!(await this.handleReorg())) {
            this.signingEnabled = false;
            this.unhealthyReason = 'reorg-unrecoverable: no snapshot canonical';
            return;
          }
        }
      }
      if (safeHead > this.lastScannedBlock) {
        const events = await this.chain.getStateAdvancedEvents(this.lastScannedBlock + 1, safeHead);
        const sorted = [...events].sort((a, b) => {
          const db = Number(a.blockNumber - b.blockNumber);
          if (db !== 0) return db;
          return Number(a.logIndex - b.logIndex);
        });
        for (const ev of sorted) this.applyChainEvent(ev);
        this.lastScannedBlock = safeHead;
      }
      const available = await this.parityCheck();
      if (available) {
        this.auditReceiptCacheAgainstCanonicalRoots();
        this.signingEnabled = true;
        this.unhealthyReason = null;
      }
      this.gcPending(Math.floor(Date.now() / 1000));
    } catch (e) {
      this.signingEnabled = false;
      this.unhealthyReason = `watcher-fault: ${(e as Error).message}`;
      this.metrics.watcherFaultCount += 1;
    }
  }

  // ── chain-event verification + apply ─────────────────────────────────────
  private applyChainEvent(ev: CoreTexStateAdvancedEvent): void {
    if (ev.epoch !== this.config.epoch) {
      throw new Error(`watcher: event epoch ${ev.epoch} ≠ configured ${this.config.epoch}`);
    }
    if (ev.transitionIndex !== this.lastTransitionIndex + 1n) {
      throw new Error(`watcher: non-contiguous transitionIndex got=${ev.transitionIndex} want=${this.lastTransitionIndex + 1n}`);
    }
    if (ev.parent.toLowerCase() !== this.liveRoot.toLowerCase()) {
      throw new Error(`watcher: event parent ${ev.parent} ≠ coord liveRoot ${this.liveRoot}`);
    }
    if (ev.coreV.toLowerCase() !== this.config.expectedEpochPins.coreVersionHash.toLowerCase()) {
      throw new Error(`watcher: event coreVersionHash ${ev.coreV} ≠ configured ${this.config.expectedEpochPins.coreVersionHash}`);
    }
    if (ev.corpus.toLowerCase() !== this.config.expectedEpochPins.corpusRoot.toLowerCase()) {
      throw new Error(`watcher: event corpusRoot ${ev.corpus} ≠ configured ${this.config.expectedEpochPins.corpusRoot}`);
    }
    if (ev.frontier.toLowerCase() !== this.config.expectedEpochPins.activeFrontierRoot.toLowerCase()) {
      throw new Error(`watcher: event activeFrontierRoot ${ev.frontier} ≠ configured ${this.config.expectedEpochPins.activeFrontierRoot}`);
    }
    const recomputedPatchHash = computePatchHash(hexToBytes(ev.compactPatchBytes));
    if (recomputedPatchHash.toLowerCase() !== ev.patchHash.toLowerCase()) {
      throw new Error(`watcher: patchHash mismatch event=${ev.patchHash} computed=${recomputedPatchHash}`);
    }
    const decoded = decodePatch(hexToBytes(ev.compactPatchBytes));
    const next = applyPatch(this.liveState, decoded, true);
    if (!next.ok) throw new Error(`watcher: applyPatch failed ${(next as { code?: string }).code}`);
    if (ev.wordCount !== Number(decoded.wordCount)) {
      throw new Error(`watcher: event wordCount ${ev.wordCount} ≠ decoded patch wordCount ${decoded.wordCount}`);
    }
    const newRoot = bytesToHex(merkleizeState(next.state)).toLowerCase();
    if (newRoot !== ev.newRoot.toLowerCase()) {
      throw new Error(`watcher: newStateRoot mismatch replay=${newRoot} event=${ev.newRoot}`);
    }
    // Commit
    this.liveState = next.state;
    this.liveRoot = newRoot;
    this.lastTransitionIndex = ev.transitionIndex;
    this.stateByRoot.set(newRoot, this.liveState);
    this.snapshots.push({
      transitionIndex: ev.transitionIndex, blockNumber: ev.blockNumber, blockHash: ev.blockHash,
      parent: ev.parent.toLowerCase(), root: newRoot, patchHash: ev.patchHash.toLowerCase(),
      state: { words: [...next.state.words] },
    });
    if (this.snapshots.length > CoreTexCoordinatorCore.MAX_SNAPSHOTS) this.snapshots.shift();
    // Pending bookkeeping
    for (const p of this.pendingByPatchHash.values()) {
      if (p.state !== 'pending') continue;
      if (p.parentRoot.toLowerCase() === ev.parent.toLowerCase() &&
          p.signedPatchHash.toLowerCase() === ev.patchHash.toLowerCase()) {
        p.state = 'confirmed';
      } else if (p.parentRoot.toLowerCase() === ev.parent.toLowerCase()) {
        // Audit-3 R3 P3: stale pending receipts must reconcile receipt-cache states
        // — the cached envelope is marked stale via the pending lookup, AND it is
        // explicitly NOT returned as broadcastable from getReceiptByHash.
        this.markPendingStale(p);
      }
    }
  }

  // ── reorg rollback ─────────────────────────────────────────────────────────
  private async handleReorg(): Promise<boolean> {
    let keepIndex = -1;
    for (let i = this.snapshots.length - 1; i >= 0; i--) {
      const snap = this.snapshots[i]!;
      const canonical = await this.chain.getBlockHashAt(Number(snap.blockNumber));
      if (canonical && canonical.toLowerCase() === snap.blockHash.toLowerCase()) {
        keepIndex = i;
        break;
      }
    }

    if (keepIndex >= 0) {
      const snap = this.snapshots[keepIndex]!;
      this.snapshots.splice(keepIndex + 1);
      this.liveState = { words: [...snap.state.words] };
      this.liveRoot = snap.root.toLowerCase();
      this.lastTransitionIndex = snap.transitionIndex;
      this.lastScannedBlock = Number(snap.blockNumber);
    } else {
      this.snapshots.splice(0);
      this.liveState = { words: [...this.parentState.words] };
      this.liveRoot = this.parentRoot.toLowerCase();
      this.lastTransitionIndex = -1n;
      this.lastScannedBlock = Math.max(0, this.epochStartBlock - 1);
    }

    const keep = new Set(this.snapshots.map((s) => s.root.toLowerCase()));
    keep.add(this.parentRoot.toLowerCase());
    for (const key of [...this.stateByRoot.keys()]) {
      if (!keep.has(key)) this.stateByRoot.delete(key);
    }
    this.reconcilePendingFromCanonicalSnapshots();
    this.auditReceiptCacheAgainstCanonicalRoots();
    this.signingEnabled = false;
    this.unhealthyReason = 'reorg-reconciling';
    this.metrics.reorgRollbackCount += 1;
    return true;
  }

  private reconcilePendingFromCanonicalSnapshots(): void {
    for (const p of this.pendingByPatchHash.values()) {
      if (p.state !== 'expired') p.state = 'pending';
    }
    for (const snap of this.snapshots) {
      for (const p of this.pendingByPatchHash.values()) {
        if (p.state !== 'pending') continue;
        if (p.parentRoot.toLowerCase() !== snap.parent.toLowerCase()) continue;
        p.state = p.signedPatchHash.toLowerCase() === snap.patchHash.toLowerCase() ? 'confirmed' : 'stale';
      }
    }
  }

  // ── parity gate ────────────────────────────────────────────────────────────
  private async parityCheck(): Promise<boolean> {
    const reg = await this.chain.getRegistryEpoch(this.config.epoch);
    this.chainLiveRoot = reg.liveStateRoot.toLowerCase();
    this.chainTransitionCount = reg.transitionCount;
    const coordCount = Number(this.lastTransitionIndex + 1n);
    if (coordCount > reg.transitionCount) {
      this.signingEnabled = false;
      this.unhealthyReason = `parity-mismatch: coord transitionCount=${coordCount} > chain=${reg.transitionCount}`;
      this.metrics.parityMismatchCount += 1;
      return false;
    }
    if (coordCount < reg.transitionCount) {
      this.signingEnabled = false;
      this.unhealthyReason = `CoordAwaitingFinality: coord transitionCount=${coordCount} < chain=${reg.transitionCount}`;
      return false;
    }
    if (coordCount === reg.transitionCount && reg.liveStateRoot.toLowerCase() !== this.liveRoot.toLowerCase()) {
      this.signingEnabled = false;
      this.unhealthyReason = `parity-mismatch: chain=${reg.liveStateRoot} coord=${this.liveRoot}`;
      this.metrics.parityMismatchCount += 1;
      return false;
    }
    return true;
  }

  private async checkEpochStillCurrent(): Promise<boolean> {
    const v4Epoch = await this.chain.getV4CurrentEpoch();
    if (v4Epoch === this.config.epoch) {
      this.lastEpochMismatch = null;
      return true;
    }
    this.signingEnabled = false;
    this.unhealthyReason = `CoordEpochMismatch: V4.currentEpoch=${v4Epoch} configured=${this.config.epoch}; restart with fresh epoch pins`;
    if (this.lastEpochMismatch !== v4Epoch) {
      this.metrics.epochMismatchCount += 1;
      this.lastEpochMismatch = v4Epoch;
    }
    return false;
  }

  private isAwaitingFinality(): boolean {
    return this.unhealthyReason?.startsWith('CoordAwaitingFinality') ?? false;
  }

  // ── pending expiry sweep ───────────────────────────────────────────────────
  private gcPending(nowSec: number): void {
    for (const p of [...this.pendingByPatchHash.values()]) {
      if (p.state === 'pending' && p.expiresAt <= nowSec) {
        p.state = 'expired';
        this.metrics.receiptExpiryCount += 1;
        // Release dedup under ORIGINAL patchHash (audit-3 R2 #3)
        const dedupKey = `${p.parentRoot.toLowerCase()}|${p.originalPatchHash.toLowerCase()}|2`;
        this.submitDedup.delete(dedupKey);
        this.markExpiredReceiptHash(p.signedPatchHash, nowSec);
        this.markExpiredReceiptHash(p.originalPatchHash, nowSec);
        this.receiptCache.delete(p.signedPatchHash.toLowerCase());
        this.receiptCache.delete(p.originalPatchHash.toLowerCase());
        this.pendingByPatchHash.delete(p.signedPatchHash.toLowerCase());
      }
    }
    for (const [hash, envelope] of [...this.receiptCache.entries()]) {
      const pending = this.pendingByPatchHash.get(envelope.patchHash.toLowerCase());
      if (pending?.state === 'expired') {
        this.markExpiredReceiptHash(pending.signedPatchHash, nowSec);
        this.markExpiredReceiptHash(pending.originalPatchHash, nowSec);
        this.receiptCache.delete(pending.signedPatchHash.toLowerCase());
        this.receiptCache.delete(pending.originalPatchHash.toLowerCase());
      } else if (!pending && Number.isInteger(envelope.expiresAt) && envelope.expiresAt <= nowSec) {
        this.receiptCache.delete(hash);
        this.markExpiredReceiptHash(hash, nowSec);
        this.metrics.receiptExpiryCount += 1;
      }
    }
    for (const [key, expiresAt] of [...this.submitDedup.entries()]) {
      if (expiresAt <= nowSec) this.submitDedup.delete(key);
    }
    for (const [hash, tombstoneUntil] of [...this.expiredReceiptTombstones.entries()]) {
      if (tombstoneUntil <= nowSec) this.expiredReceiptTombstones.delete(hash);
    }
  }

  private markExpiredReceiptHash(hash: string, nowSec: number): void {
    this.expiredReceiptTombstones.set(hash.toLowerCase(), nowSec + this.config.receiptTtlSec);
  }

  private markPendingStale(p: PendingReceipt): void {
    if (p.state !== 'stale') {
      p.state = 'stale';
      this.metrics.staleReceiptCount += 1;
    }
  }

  private auditReceiptCacheAgainstCanonicalRoots(): void {
    for (const p of this.pendingByPatchHash.values()) {
      if (p.state !== 'pending') continue;
      if (!this.stateByRoot.has(p.parentRoot.toLowerCase())) this.markPendingStale(p);
    }
  }

  // ── public-facing handlers ─────────────────────────────────────────────────
  async getStatus(query: Record<string, string | readonly string[] | undefined> = {}): Promise<unknown> {
    await this.checkEpochStillCurrent();
    const minerRaw = firstQueryValue(query.miner);
    const miner = typeof minerRaw === 'string' && isAddress(minerRaw) ? minerRaw.toLowerCase() : null;
    const qualified = await this.chain.getQualifiedScreenerPassesSinceLastStateAdvance(this.config.epoch);
    const workPolicy = this.config.workPolicy ?? DEFAULT_CORETEX_WORK_POLICY;
    const nextStateAdvanceWorkBps = computeCoreTexWorkUnitsBps({
      outcome: OUTCOME_CORETEX_STATE_ADVANCE,
      qualifiedScreenerPassesSinceLastStateAdvance: qualified,
      policy: workPolicy,
    });
    const cap = this.config.perMinerScreenerCap ?? 50;
    const perMiner = miner
      ? await this.perMinerStatus(miner, cap)
      : null;
    return {
      lane: 'coretex',
      epochId: Number(this.config.epoch),
      currentStateRoot: this.liveRoot,
      confirmedTransitionCount: Number(this.lastTransitionIndex + 1n),
      chainTransitionCount: this.chainTransitionCount,
      bundleHash: this.config.expectedEpochPins.coreVersionHash,
      coreVersionHash: this.config.expectedEpochPins.coreVersionHash,
      corpusRoot: this.config.expectedEpochPins.corpusRoot,
      activeFrontierRoot: this.config.expectedEpochPins.activeFrontierRoot,
      baselineManifestHash: this.config.expectedEpochPins.baselineManifestHash,
      rulesVersion: this.config.rulesVersion ?? DEFAULT_CORETEX_WORK_POLICY.rulesVersion,
      workPolicyHash: this.config.workPolicyHash,
      patchWordBudget: this.config.patchWordBudget ?? 4,
      minImprovementPpm: this.config.minImprovementPpm ?? Number(DEFAULT_CORETEX_WORK_POLICY.stateAdvance.minDeterministicDeltaPpm),
      replayTolerancePpm: this.config.replayTolerancePpm ?? 0,
      screenerThresholdPpm: this.config.screenerThresholdPpm ?? Number(DEFAULT_CORETEX_WORK_POLICY.screenerPass.calibration.minDeltaPpm),
      baselineScorePpm: this.config.baselineScorePpm ?? 0,
      recentNoiseFloorPpm: this.config.recentNoiseFloorPpm ?? 0,
      perMinerScreenerCap: cap,
      qualifiedScreenerPassesSinceLastStateAdvance: qualified,
      nextStateAdvanceWorkBps: Number(nextStateAdvanceWorkBps),
      activeSubstrateSurfaces: [...(this.config.activeSubstrateSurfaces ?? [])],
      allowedPatchTypes: [...(this.config.allowedPatchTypes ?? [])],
      substrate: { uri: `/coretex/substrate/${this.liveRoot}` },
      acceptingSubmissions: this.signingEnabled,
      ...(this.unhealthyReason ? { reason: this.unhealthyReason } : {}),
      ...(this.config.pipelineVersion ? { pipelineVersion: this.config.pipelineVersion } : {}),
      ...(this.config.memoryIRSchemaVersion ? { memoryIRSchemaVersion: this.config.memoryIRSchemaVersion } : {}),
      ...(this.config.runwayTelemetry ? { runwayTelemetry: this.config.runwayTelemetry } : {}),
      hiddenEvalWarning: 'hidden qrels / eval pack / epochSecret are NOT public',
      perMiner,
    };
  }

  async submit(body: unknown): Promise<unknown> {
    const now = Math.floor(Date.now() / 1000);
    this.gcPending(now);
    if (!(await this.checkEpochStillCurrent())) {
      return this.rejectSubmission('CoordEpochMismatch', this.unhealthyReason ?? 'epoch mismatch');
    }
    if (!this.signingEnabled) {
      const code = this.isAwaitingFinality() ? 'CoordAwaitingFinality' : 'CoordUnhealthy';
      return this.rejectSubmission(code, this.unhealthyReason ?? 'signing disabled');
    }
    if (!this.signer) {
      return this.rejectSubmission('CoordSignerUnavailable', 'CoreTex receipt signer is not configured');
    }
    const parsed = parseSubmitBody(body, this.config.maxPatchBytes ?? 256);
    if (!parsed.ok) return this.rejectSubmission(String(parsed.body.code ?? 'BODY'), String(parsed.body.reason ?? 'malformed body'), parsed.body);
    if (parsed.parentStateRoot !== this.liveRoot.toLowerCase()) {
      return this.rejectSubmission('E01', 'parentStateRoot != confirmed live root', { currentStateRoot: this.liveRoot });
    }

    let decoded;
    try {
      decoded = decodePatch(parsed.patchBytes);
    } catch (e) {
      return this.rejectSubmission('DECODE', `decode failed: ${(e as Error).message}`);
    }
    const wireParent = bytesToHex(decoded.parentStateRoot).toLowerCase();
    if (wireParent !== parsed.parentStateRoot) {
      return this.rejectSubmission('E01', 'wire parentStateRoot != request parentStateRoot', { currentStateRoot: this.liveRoot });
    }
    const originalPatchHash = computePatchHash(parsed.patchBytes).toLowerCase();
    let evalResult: EvalResult;
    try {
      evalResult = await this.evaluator.scorePatch({
        patchBytesHex: parsed.patchBytesHex,
        parentStateRoot: parsed.parentStateRoot,
        miner: parsed.miner,
      });
    } catch {
      this.metrics.evalFailureCount += 1;
      return this.rejectSubmission('EvalFailure', 'evaluator failed');
    }
    if (evalResult.outcome === 'reject') {
      return this.rejectSubmission(evalResult.code, evalResult.reason, {
        ...(evalResult.deterministicDeltaPpm !== undefined ? { deterministicDeltaPpm: evalResult.deterministicDeltaPpm } : {}),
        ...(evalResult.requiredDeltaPpm !== undefined ? { requiredDeltaPpm: evalResult.requiredDeltaPpm } : {}),
      });
    }
    const evalInvalid = validateAcceptedEvalResult(evalResult);
    if (evalInvalid) return this.rejectSubmission(evalInvalid.code, evalInvalid.reason);

    const outcome = evalResult.outcome === 'state_advance'
      ? OUTCOME_CORETEX_STATE_ADVANCE
      : OUTCOME_CORETEX_SCREENER_PASS;
    const dedupKey = `${parsed.parentStateRoot}|${originalPatchHash}|${outcome}`;
    if (this.submitDedup.has(dedupKey)) {
      return this.rejectSubmission('DuplicateCoreTexPatch', '(parent, patchHash, outcome) already signed');
    }

    const counters = await this.chain.getMinerCoreTexCounters(this.config.epoch, parsed.miner);
    const cap = this.config.perMinerScreenerCap ?? 50;
    if (outcome === OUTCOME_CORETEX_SCREENER_PASS && counters.screenersThisEpoch >= cap) {
      return this.rejectSubmission('CoreTexScreenerCapExceeded', 'per-miner screener cap exceeded', {
        perMinerScreenerCap: cap,
        current: counters.screenersThisEpoch,
      });
    }

    const applied = applyPatch(this.liveState, decoded, true);
    if (!applied.ok) {
      return this.rejectSubmission(applied.code, `apply: ${applied.code}`);
    }

    let compactPatchBytes = parsed.patchBytesHex;
    let signedPatchHash = originalPatchHash;
    let newStateRoot = parsed.parentStateRoot;
    let stateWordCount = 0;
    let scoreBeforePpm = 0;
    let scoreAfterPpm = 0;
    if (evalResult.outcome === 'state_advance') {
      const scoreDelta = evalResult.scoreAfterPpm - evalResult.scoreBeforePpm;
      if (scoreDelta < (this.config.minImprovementPpm ?? Number(DEFAULT_CORETEX_WORK_POLICY.stateAdvance.minDeterministicDeltaPpm))) {
        return this.rejectSubmission('W03_DETERMINISTIC_DELTA_TOO_LOW', 'below state-advance minimum', { deterministicDeltaPpm: scoreDelta });
      }
      const rewrittenPatchBytes = normalizeHexBytes(evalResult.rewrittenPatchBytesHex);
      if (!rewrittenPatchBytes || rewrittenPatchBytes.bytes.length > (this.config.maxPatchBytes ?? 256)) {
        return this.rejectSubmission('EVAL_REWRITE_INVALID', 'evaluator returned malformed rewrittenPatchBytesHex');
      }
      let rewrittenDecoded;
      try {
        rewrittenDecoded = decodePatch(rewrittenPatchBytes.bytes);
      } catch {
        return this.rejectSubmission('EVAL_REWRITE_INVALID', 'evaluator returned undecodable rewrittenPatchBytesHex');
      }
      if (rewrittenDecoded.scoreDelta !== BigInt(scoreDelta)) {
        compactPatchBytes = bytesToHex(encodePatch({ ...decoded, scoreDelta: BigInt(scoreDelta) })).toLowerCase();
      } else {
        compactPatchBytes = rewrittenPatchBytes.hex;
      }
      const finalDecoded = decodePatch(hexToBytes(compactPatchBytes));
      const finalApplied = applyPatch(this.liveState, finalDecoded, true);
      if (!finalApplied.ok) {
        return this.rejectSubmission(finalApplied.code, `rewritten apply: ${finalApplied.code}`);
      }
      newStateRoot = bytesToHex(merkleizeState(finalApplied.state)).toLowerCase();
      signedPatchHash = computePatchHash(hexToBytes(compactPatchBytes)).toLowerCase();
      stateWordCount = Number(finalDecoded.wordCount);
      scoreBeforePpm = evalResult.scoreBeforePpm;
      scoreAfterPpm = evalResult.scoreAfterPpm;
    } else if (evalResult.deterministicDeltaPpm < (this.config.screenerThresholdPpm ?? Number(DEFAULT_CORETEX_WORK_POLICY.screenerPass.calibration.minDeltaPpm))) {
      return this.rejectSubmission('W03_DETERMINISTIC_DELTA_TOO_LOW', 'below screener threshold', { deterministicDeltaPpm: evalResult.deterministicDeltaPpm });
    }

    const difficultyCount = await this.chain.getQualifiedScreenerPassesSinceLastStateAdvance(this.config.epoch);
    const workUnitsBps = computeCoreTexWorkUnitsBps({
      outcome,
      qualifiedScreenerPassesSinceLastStateAdvance: difficultyCount,
      policy: this.config.workPolicy ?? DEFAULT_CORETEX_WORK_POLICY,
    });
    const issuedAt = now;
    const expiresAt = issuedAt + this.config.receiptTtlSec;
    const receipt: CoreTexReceiptPayload = {
      epochId: this.config.epoch,
      solveIndex: counters.nextIndex,
      prevReceiptHash: counters.lastReceiptHash.toLowerCase(),
      outcome,
      challengeId: hashText('coretex-challenge-v1', String(this.config.epoch), parsed.parentStateRoot, signedPatchHash),
      parentStateRoot: parsed.parentStateRoot,
      newStateRoot,
      corpusRoot: this.config.expectedEpochPins.corpusRoot.toLowerCase(),
      activeFrontierRoot: this.config.expectedEpochPins.activeFrontierRoot.toLowerCase(),
      coreVersionHash: this.config.expectedEpochPins.coreVersionHash.toLowerCase(),
      evalReportHash: evalResult.evalReportHash.toLowerCase(),
      patchHash: signedPatchHash,
      artifactHash: evalResult.artifactHash.toLowerCase(),
      worldSeed: worldSeed(parsed.miner, counters.nextIndex, signedPatchHash),
      rulesVersion: this.config.rulesVersion ?? DEFAULT_CORETEX_WORK_POLICY.rulesVersion,
      workPolicyHash: this.config.workPolicyHash!.toLowerCase(),
      workUnitsBps,
      difficultyCountSnapshot: BigInt(difficultyCount),
      stateWordCount,
      scoreBeforePpm,
      scoreAfterPpm,
      issuedAt,
      expiresAt,
      compactPatchBytes,
    };
    if (!receipt.evalReportHash.match(/^0x[0-9a-f]{64}$/) || !receipt.artifactHash.match(/^0x[0-9a-f]{64}$/)) {
      return this.rejectSubmission('EVAL_HASH_INVALID', 'evaluator returned malformed evalReportHash/artifactHash');
    }
    let signed;
    try {
      signed = await this.signer.signCoreTexReceipt({ miner: parsed.miner, receipt });
    } catch {
      this.metrics.signerFailureCount += 1;
      return this.rejectSubmission('SignerFailure', 'signer failed');
    }
    if (!isHex(signed.signature) || !isHex(signed.transactionData)) {
      return this.rejectSubmission('SIGNER_INVALID', 'signer returned malformed signature or transactionData');
    }

    const publicReceipt = signed.receipt ?? serializeReceipt(receipt, signed.signature);
    const envelope: ReceiptEnvelope & Record<string, unknown> = {
      status: 'accepted',
      outcome: outcome === OUTCOME_CORETEX_STATE_ADVANCE ? 'STATE_ADVANCE' : 'SCREENER_PASS',
      patchHash: signedPatchHash,
      evalReportHash: receipt.evalReportHash,
      deterministicDeltaPpm: evalResult.deterministicDeltaPpm,
      workUnitsBps: Number(workUnitsBps),
      newStateRoot,
      perMinerScreenerCount: outcome === OUTCOME_CORETEX_SCREENER_PASS ? counters.screenersThisEpoch + 1 : counters.screenersThisEpoch,
      perMinerScreenerRemaining: Math.max(0, cap - (outcome === OUTCOME_CORETEX_SCREENER_PASS ? counters.screenersThisEpoch + 1 : counters.screenersThisEpoch)),
      receipt: publicReceipt,
      transaction: { to: this.config.v4Address.toLowerCase(), chainId: Number(this.config.expectedChainId), value: '0', data: signed.transactionData.toLowerCase() },
      issuedAt,
      expiresAt,
    };

    this.submitDedup.set(dedupKey, expiresAt);
    if (outcome === OUTCOME_CORETEX_STATE_ADVANCE) {
      this.pendingByPatchHash.set(signedPatchHash, {
        originalPatchHash,
        signedPatchHash,
        parentRoot: parsed.parentStateRoot,
        expectedNewRoot: newStateRoot,
        compactPatchBytes,
        miner: parsed.miner,
        issuedAt,
        expiresAt,
        state: 'pending',
      });
    }
    this.cacheReceipt(envelope, originalPatchHash);
    return envelope;
  }

  async health(): Promise<unknown> {
    return {
      ok: this.signingEnabled,
      version: 'v0',
      epoch: Number(this.config.epoch),
      chainId: Number(this.config.expectedChainId),
      confirmationDepth: this.config.confirmationDepth,
      chainLiveRoot: this.chainLiveRoot,
      confirmedLiveRoot: this.liveRoot,
      finalityLagBlocks: this.finalityLagBlocks,
      acceptingSubmissions: this.signingEnabled,
      ...(this.unhealthyReason ? { reason: this.unhealthyReason } : {}),
      epochPins: this.config.expectedEpochPins,
    };
  }

  getSubstrate(stateRoot: string): { stateRoot: string; wordCount: number; packedHex: string } | null {
    const cached = this.stateByRoot.get(stateRoot.toLowerCase());
    if (!cached) return null;
    return { stateRoot: stateRoot.toLowerCase(), wordCount: 1024, packedHex: this.statePackedHex(cached) };
  }

  getReceiptByHash(hash: string): { status: number; body: unknown } {
    this.gcPending(Math.floor(Date.now() / 1000));
    const now = Math.floor(Date.now() / 1000);
    const normalizedHash = hash.toLowerCase();
    const cached = this.receiptCache.get(normalizedHash);
    if (!cached) {
      const tombstoneUntil = this.expiredReceiptTombstones.get(normalizedHash);
      if (tombstoneUntil && tombstoneUntil > now) {
        return { status: 404, body: { status: 'rejected', reason: 'receipt expired; re-submit to get a fresh receipt' } };
      }
      return { status: 404, body: { status: 'rejected', reason: 'unknown patchHash (not signed by this coordinator)' } };
    }
    // Inspect pending state
    const signed = cached.patchHash.toLowerCase();
    const pending = this.pendingByPatchHash.get(signed);
    if (pending?.state === 'stale') {
      return { status: 409, body: { status: 'rejected', code: 'PendingReceiptStale',
        reason: 'a competing state advance landed first; this receipt is no longer usable',
        patchHash: cached.patchHash, state: 'stale' } };
    }
    if (pending?.state === 'expired') {
      this.receiptCache.delete(pending.signedPatchHash.toLowerCase());
      this.receiptCache.delete(pending.originalPatchHash.toLowerCase());
      return { status: 404, body: { status: 'rejected', reason: 'receipt expired; re-submit to get a fresh receipt' } };
    }
    if (!pending && cached.expiresAt <= now) {
      this.receiptCache.delete(normalizedHash);
      this.markExpiredReceiptHash(normalizedHash, now);
      return { status: 404, body: { status: 'rejected', reason: 'receipt expired; re-submit to get a fresh receipt' } };
    }
    return { status: 200, body: { ...cached, pendingState: pending?.state, confirmedOnChain: pending?.state === 'confirmed' } };
  }

  private async perMinerStatus(miner: string, cap: number): Promise<unknown> {
    const counters = await this.chain.getMinerCoreTexCounters(this.config.epoch, miner);
    return {
      address: miner,
      screenersThisEpoch: counters.screenersThisEpoch,
      remaining: Math.max(0, cap - counters.screenersThisEpoch),
      cap,
      nextIndex: Number(counters.nextIndex),
      lastReceiptHash: counters.lastReceiptHash.toLowerCase(),
    };
  }

  private validateStaticConfig(): void {
    if (!Number.isInteger(this.config.confirmationDepth) || this.config.confirmationDepth < 0) {
      throw new Error('coord: confirmationDepth must be a non-negative integer');
    }
    if (!Number.isInteger(this.config.receiptTtlSec) || this.config.receiptTtlSec <= 0) {
      throw new Error('coord: receiptTtlSec must be a positive integer');
    }
    if (!Number.isInteger(this.config.rulesVersion) || (this.config.rulesVersion ?? 0) <= 0) {
      throw new Error('coord: rulesVersion must be configured');
    }
    if (!this.config.workPolicyHash || !isBytes32(this.config.workPolicyHash)) {
      throw new Error('coord: workPolicyHash bytes32 must be configured');
    }
    if (this.config.perMinerScreenerCap !== undefined &&
        (!Number.isInteger(this.config.perMinerScreenerCap) || this.config.perMinerScreenerCap < 1)) {
      throw new Error('coord: perMinerScreenerCap must be positive when configured');
    }
    if (this.config.maxPatchBytes !== undefined &&
        (!Number.isInteger(this.config.maxPatchBytes) || this.config.maxPatchBytes < 42)) {
      throw new Error('coord: maxPatchBytes must be at least the minimum patch size');
    }
  }

  private cacheReceipt(envelope: ReceiptEnvelope, originalPatchHash: string): void {
    const signed = envelope.patchHash.toLowerCase();
    this.receiptCache.set(signed, envelope);
    if (originalPatchHash.toLowerCase() !== signed) this.receiptCache.set(originalPatchHash.toLowerCase(), envelope);
  }

  getMetrics(): CoreTexCoordinatorMetrics {
    return {
      reorgRollbackCount: this.metrics.reorgRollbackCount,
      parityMismatchCount: this.metrics.parityMismatchCount,
      epochMismatchCount: this.metrics.epochMismatchCount,
      receiptExpiryCount: this.metrics.receiptExpiryCount,
      staleReceiptCount: this.metrics.staleReceiptCount,
      evalFailureCount: this.metrics.evalFailureCount,
      signerFailureCount: this.metrics.signerFailureCount,
      watcherFaultCount: this.metrics.watcherFaultCount,
      submitRejectedByCode: { ...this.metrics.submitRejectedByCode },
    };
  }

  private rejectSubmission(code: string, reason: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    this.metrics.submitRejectedByCode[code] = (this.metrics.submitRejectedByCode[code] ?? 0) + 1;
    return { status: 'rejected', code, reason, ...extra };
  }

  // Internal accessors for tests
  getState(): { liveRoot: string; transitionCount: number; signingEnabled: boolean; unhealthyReason: string | null; snapshotCount: number; pendingCount: number; receiptCacheSize: number; stateByRootSize: number; lastScannedBlock: number } {
    return {
      liveRoot: this.liveRoot,
      transitionCount: Number(this.lastTransitionIndex + 1n),
      signingEnabled: this.signingEnabled,
      unhealthyReason: this.unhealthyReason,
      snapshotCount: this.snapshots.length,
      pendingCount: this.pendingByPatchHash.size,
      receiptCacheSize: this.receiptCache.size,
      stateByRootSize: this.stateByRoot.size,
      lastScannedBlock: this.lastScannedBlock,
    };
  }

  /** Test-only: register a pending STATE_ADVANCE record. Production submit path
   *  populates the same data after running the real evaluator + signer. */
  registerPending(p: PendingReceipt, envelope: ReceiptEnvelope): void {
    this.pendingByPatchHash.set(p.signedPatchHash.toLowerCase(), p);
    this.cacheReceipt(envelope, p.originalPatchHash);
    const dedupKey = `${p.parentRoot.toLowerCase()}|${p.originalPatchHash.toLowerCase()}|2`;
    this.submitDedup.set(dedupKey, p.expiresAt);
  }

  /** Test-only: force unhealthy. */
  forceUnhealthy(reason: string): void {
    this.signingEnabled = false;
    this.unhealthyReason = reason;
  }

  private statePackedHex(state: CortexState): string {
    const u = new Uint8Array(32768);
    for (let i = 0; i < 1024; i++) {
      let v = state.words[i] ?? 0n;
      for (let j = 31; j >= 0; j--) { u[i * 32 + j] = Number(v & 0xffn); v >>= 8n; }
    }
    return '0x' + Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
}

// ── helpers ────────────────────────────────────────────────────────────────
function hexToBytes(h: string): Uint8Array {
  const s = h.replace(/^0x/, '');
  const padded = s.length % 2 ? '0' + s : s;
  const o = new Uint8Array(padded.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  return o;
}

function normalizeHexBytes(value: unknown): { hex: string; bytes: Uint8Array } | null {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]*$/.test(value)) return null;
  const hex = value.toLowerCase();
  if ((hex.length - 2) % 2 !== 0) return null;
  return { hex, bytes: hexToBytes(hex) };
}

function isHex(value: unknown): value is string {
  return typeof value === 'string' && /^0x[0-9a-fA-F]*$/.test(value);
}

function isAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isBytes32(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function firstQueryValue(value: string | readonly string[] | undefined): string | undefined {
  if (typeof value === 'string') return value;
  return value && value.length > 0 ? value[0] : undefined;
}

type ParsedSubmitBody =
  | { ok: true; patchBytesHex: string; patchBytes: Uint8Array; parentStateRoot: string; miner: string }
  | { ok: false; body: Record<string, unknown> };

function parseSubmitBody(body: unknown, maxPatchBytes: number): ParsedSubmitBody {
  if (!body || typeof body !== 'object') {
    return { ok: false, body: { status: 'rejected', code: 'BODY', reason: 'malformed body' } };
  }
  const r = body as Record<string, unknown>;
  const allowed = new Set(['patchBytesHex', 'parentStateRoot', 'minerAddress']);
  const unknown = Object.keys(r).filter((k) => !allowed.has(k));
  if (unknown.length > 0) {
    return { ok: false, body: { status: 'rejected', code: 'BODY_UNKNOWN_KEY', reason: `unknown submit body key: ${unknown[0]}` } };
  }
  const patch = normalizeHexBytes(r.patchBytesHex);
  if (!patch || patch.bytes.length === 0) {
    return { ok: false, body: { status: 'rejected', code: 'BODY', reason: 'patchBytesHex malformed' } };
  }
  if (patch.bytes.length > maxPatchBytes) {
    return { ok: false, body: { status: 'rejected', code: 'PATCH_TOO_LARGE', reason: `patchBytesHex exceeds ${maxPatchBytes} bytes` } };
  }
  if (typeof r.parentStateRoot !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(r.parentStateRoot)) {
    return { ok: false, body: { status: 'rejected', code: 'BODY', reason: 'parentStateRoot malformed' } };
  }
  if (typeof r.minerAddress !== 'string' || !isAddress(r.minerAddress)) {
    return { ok: false, body: { status: 'rejected', code: 'BODY', reason: 'minerAddress malformed' } };
  }
  return {
    ok: true,
    patchBytesHex: patch.hex,
    patchBytes: patch.bytes,
    parentStateRoot: r.parentStateRoot.toLowerCase(),
    miner: r.minerAddress.toLowerCase(),
  };
}

function validateAcceptedEvalResult(result: EvalResult): { code: string; reason: string } | null {
  if (result.outcome === 'reject') return null;
  if (!Number.isSafeInteger(result.deterministicDeltaPpm) || result.deterministicDeltaPpm < 0) {
    return { code: 'EVAL_DELTA_INVALID', reason: 'evaluator returned invalid deterministicDeltaPpm' };
  }
  if (!isBytes32(result.evalReportHash) || !isBytes32(result.artifactHash)) {
    return { code: 'EVAL_HASH_INVALID', reason: 'evaluator returned malformed evalReportHash/artifactHash' };
  }
  if (result.outcome === 'state_advance') {
    if (!Number.isSafeInteger(result.scoreBeforePpm) || result.scoreBeforePpm < 0 ||
        !Number.isSafeInteger(result.scoreAfterPpm) || result.scoreAfterPpm < 0) {
      return { code: 'EVAL_SCORE_INVALID', reason: 'evaluator returned invalid scoreBeforePpm/scoreAfterPpm' };
    }
    const scoreDelta = result.scoreAfterPpm - result.scoreBeforePpm;
    if (scoreDelta <= 0) {
      return { code: 'EVAL_SCORE_INVALID', reason: 'evaluator returned non-improving state-advance scores' };
    }
    if (result.deterministicDeltaPpm !== scoreDelta) {
      return { code: 'EVAL_DELTA_INVALID', reason: 'deterministicDeltaPpm must equal scoreAfterPpm - scoreBeforePpm' };
    }
  }
  return null;
}

function hashText(...parts: readonly string[]): string {
  return bytesToHex(keccak256(new TextEncoder().encode(parts.join('|')))).toLowerCase();
}

function worldSeed(miner: string, solveIndex: bigint, patchHash: string): bigint {
  const h = hashText('coretex-world-v1', miner.toLowerCase(), solveIndex.toString(), patchHash.toLowerCase());
  return BigInt('0x' + h.slice(2, 34));
}

function serializeReceipt(receipt: CoreTexReceiptPayload, signature: string): Record<string, string | number> {
  return {
    epochId: receipt.epochId.toString(),
    solveIndex: receipt.solveIndex.toString(),
    prevReceiptHash: receipt.prevReceiptHash,
    outcome: receipt.outcome,
    challengeId: receipt.challengeId,
    parentStateRoot: receipt.parentStateRoot,
    newStateRoot: receipt.newStateRoot,
    corpusRoot: receipt.corpusRoot,
    activeFrontierRoot: receipt.activeFrontierRoot,
    coreVersionHash: receipt.coreVersionHash,
    evalReportHash: receipt.evalReportHash,
    patchHash: receipt.patchHash,
    artifactHash: receipt.artifactHash,
    worldSeed: receipt.worldSeed.toString(),
    rulesVersion: receipt.rulesVersion,
    workPolicyHash: receipt.workPolicyHash,
    workUnitsBps: receipt.workUnitsBps.toString(),
    difficultyCountSnapshot: receipt.difficultyCountSnapshot.toString(),
    stateWordCount: receipt.stateWordCount,
    scoreBeforePpm: receipt.scoreBeforePpm,
    scoreAfterPpm: receipt.scoreAfterPpm,
    issuedAt: receipt.issuedAt,
    expiresAt: receipt.expiresAt,
    compactPatchBytes: receipt.compactPatchBytes,
    signature: signature.toLowerCase(),
  };
}
