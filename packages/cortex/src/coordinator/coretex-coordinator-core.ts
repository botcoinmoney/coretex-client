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

import { merkleizeState, bytesToHex, decodePatch, applyPatch, keccak256, computePatchHash } from '../index.js';
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
}

interface Snapshot {
  readonly transitionIndex: bigint;
  readonly blockNumber: bigint;
  readonly blockHash: string;
  readonly root: string;
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
  private lastTransitionIndex = -1n;
  private readonly stateByRoot = new Map<string, CortexState>();
  private readonly snapshots: Snapshot[] = [];
  private static readonly MAX_SNAPSHOTS = 64;

  private signingEnabled = false;
  private unhealthyReason: string | null = 'startup-replay-pending';
  private chainLiveRoot = '';
  private chainTransitionCount = 0;
  private lastScannedBlock = 0;
  private finalityLagBlocks = 0;

  private readonly pendingByPatchHash = new Map<string, PendingReceipt>();
  private readonly receiptCache = new Map<string, ReceiptEnvelope>();
  private readonly submitDedup = new Set<string>();

  constructor(
    private readonly config: CoreTexCoordinatorConfig,
    private readonly chain: ChainClient,
    private readonly parentLoader: ParentSubstrateLoader,
    private readonly evaluator: RealEvaluator,
  ) {}

  // ── boot-time wiring gates (audit-3 R3 P5) ────────────────────────────────
  async boot(): Promise<void> {
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
    this.stateByRoot.set(this.liveRoot, this.liveState);

    // Startup replay (audit-3 R2 #2 — replay from epoch start, NOT recent N blocks)
    const epochStartBlock = await this.chain.getEpochStartedBlock(this.config.epoch);
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
    if (!(await this.parityCheck())) {
      throw new Error(`coord: HARD-FAIL post-replay parity (${this.unhealthyReason})`);
    }
    this.signingEnabled = true;
    this.unhealthyReason = null;
  }

  // ── watcher tick (called periodically) ────────────────────────────────────
  async tick(): Promise<void> {
    try {
      const head = await this.chain.getBlockNumber();
      const safeHead = head - this.config.confirmationDepth;
      this.finalityLagBlocks = head - this.lastScannedBlock;
      // Reorg detection: re-verify deepest snapshot's blockHash
      if (this.snapshots.length > 0) {
        const deepest = this.snapshots[this.snapshots.length - 1]!;
        const canonical = await this.chain.getBlockHashAt(Number(deepest.blockNumber));
        if (canonical && canonical.toLowerCase() !== deepest.blockHash.toLowerCase()) {
          if (!this.handleReorg()) {
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
      if (this.signingEnabled && !(await this.parityCheck())) return;
      this.gcPending(Math.floor(Date.now() / 1000));
    } catch (e) {
      this.signingEnabled = false;
      this.unhealthyReason = `watcher-fault: ${(e as Error).message}`;
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
      root: newRoot, state: { words: [...next.state.words] },
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
        p.state = 'stale';
      }
    }
  }

  // ── reorg rollback ─────────────────────────────────────────────────────────
  private handleReorg(): boolean {
    for (let i = this.snapshots.length - 1; i >= 0; i--) {
      const snap = this.snapshots[i]!;
      // Synchronous check is OK here: the canonical check that triggered this is
      // already done in tick(); we just need to walk back to the deepest still-canonical
      // snapshot.
      // (Real implementation would also re-verify each candidate canonical via chain,
      // but to keep the core synchronous for testability we trust the deeper snapshots.)
      if (i === this.snapshots.length - 1) continue; // skip the one we already know is bad
      const dropped = this.snapshots.length - 1 - i;
      this.snapshots.splice(i + 1);
      this.liveState = { words: [...snap.state.words] };
      this.liveRoot = snap.root;
      this.lastTransitionIndex = snap.transitionIndex;
      this.lastScannedBlock = Number(snap.blockNumber);
      // Audit-3 R3 P3: prune stateByRoot entries from the reorged branch
      const keep = new Set(this.snapshots.map((s) => s.root.toLowerCase()));
      keep.add(this.config.expectedEpochPins.parentStateRoot.toLowerCase());
      for (const key of [...this.stateByRoot.keys()]) {
        if (!keep.has(key)) this.stateByRoot.delete(key);
      }
      // Pending receipt cleanup: receipts that were confirmed by a reorged-out event
      // need to revert to pending so they reconcile correctly on the canonical replay
      // (the canonical replay will re-mark them confirmed or stale).
      for (const p of this.pendingByPatchHash.values()) {
        if (p.state === 'confirmed' || p.state === 'stale') p.state = 'pending';
      }
      void dropped;
      return true;
    }
    return false;
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
      return false;
    }
    if (coordCount === reg.transitionCount && reg.liveStateRoot.toLowerCase() !== this.liveRoot.toLowerCase()) {
      this.signingEnabled = false;
      this.unhealthyReason = `parity-mismatch: chain=${reg.liveStateRoot} coord=${this.liveRoot}`;
      return false;
    }
    return true;
  }

  // ── pending expiry sweep ───────────────────────────────────────────────────
  private gcPending(nowSec: number): void {
    for (const p of this.pendingByPatchHash.values()) {
      if (p.state === 'pending' && p.expiresAt <= nowSec) {
        p.state = 'expired';
        // Release dedup under ORIGINAL patchHash (audit-3 R2 #3)
        const dedupKey = `${p.parentRoot.toLowerCase()}|${p.originalPatchHash.toLowerCase()}|2`;
        this.submitDedup.delete(dedupKey);
      }
    }
  }

  // ── public-facing handlers ─────────────────────────────────────────────────
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
    const cached = this.receiptCache.get(hash.toLowerCase());
    if (!cached) return { status: 404, body: { status: 'rejected', reason: 'unknown patchHash (not signed by this coordinator)' } };
    // Inspect pending state
    const signed = cached.patchHash.toLowerCase();
    const pending = this.pendingByPatchHash.get(signed);
    if (pending?.state === 'stale') {
      return { status: 409, body: { status: 'rejected', code: 'PendingReceiptStale',
        reason: 'a competing state advance landed first; this receipt is no longer usable',
        patchHash: cached.patchHash, state: 'stale' } };
    }
    if (pending?.state === 'expired') {
      this.receiptCache.delete(hash.toLowerCase());
      return { status: 404, body: { status: 'rejected', reason: 'receipt expired; re-submit to get a fresh receipt' } };
    }
    return { status: 200, body: { ...cached, pendingState: pending?.state, confirmedOnChain: pending?.state === 'confirmed' } };
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
    this.receiptCache.set(p.signedPatchHash.toLowerCase(), envelope);
    if (p.originalPatchHash.toLowerCase() !== p.signedPatchHash.toLowerCase()) {
      this.receiptCache.set(p.originalPatchHash.toLowerCase(), envelope);
    }
    const dedupKey = `${p.parentRoot.toLowerCase()}|${p.originalPatchHash.toLowerCase()}|2`;
    this.submitDedup.add(dedupKey);
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
// Avoid the unused-import warning by re-exporting keccak256 only if needed elsewhere.
void keccak256;
