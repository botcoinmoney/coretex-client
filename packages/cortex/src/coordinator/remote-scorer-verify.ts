/**
 * Canonical verify-before-sign for the keyless remote scorer.
 *
 * MOVED here from the coordinator integration so the adapter CANNOT
 * under-verify: the eight checks (outstanding jobId, live-context staleness,
 * schema, model fingerprint, proof pins, threshold/policy echo,
 * coordinator-owned threshold decision, artifact-bytes rehash + context pins)
 * live next to the wire types they protect. The integration repo imports and
 * re-exports these; tests on both sides exercise the same function.
 */
import type { ScorerJobRequest, ScorerJobResult } from '../scorer-server-cli.js';
import type { EvalResult } from './coretex-coordinator-core.js';
import { bytesToHex, keccak256 } from '../index.js';
import {
  hashPostRevealEvalReportArtifact,
  type CoreTexPostRevealEvalReportArtifact,
} from '../replay/eval-report-artifact.js';

// ─── Active context the coordinator verifies the result against ──────────────

export interface RemoteScorerActiveContext {
  readonly epochId: number;
  readonly parentStateRoot: string;
  readonly corpusRoot: string;
  readonly bundleHash: string;
  readonly coreVersionHash: string;
  /** Live screener threshold (ppm) — min(gate, confirm) must clear this for an
   *  accepted result. The coordinator owns this number, NOT the scorer. */
  readonly thresholdPpm: number;
}

export interface RemoteScorerExpectedHealth {
  readonly modelId: string;
  readonly revision: string;
  readonly promptTemplateHash: string;
}

/** §8 the coordinator-drawn future-blockhash seed (pinned before dispatch). */
export interface RemoteScorerSeedContext {
  readonly receivedAtBlock: number;
  readonly targetBlock: number;
  readonly blockhash: string;
}

// ─── Verify-before-sign (pure; unit-tested directly) ─────────────────────────

export type VerifyScorerResult =
  | {
      readonly ok: true;
      readonly evalResult: Exclude<EvalResult, { readonly outcome: "reject" }>;
      /** The verified canonical artifact bytes the coordinator must spool
       *  atomically (tmp+rename) BEFORE signing — identical to what the local
       *  publishArtifact hook writes. */
      readonly artifact: CoreTexPostRevealEvalReportArtifact;
    }
  | { readonly ok: false; readonly code: string; readonly reason: string };

function hexEq(a: string | undefined, b: string | undefined): boolean {
  return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
}

/**
 * §8 seed-echo check: the accepted artifact's `seedDerivation` MUST equal the
 * seed the coordinator pinned + shipped — proof the keyless scorer INJECTED the
 * coordinator-authoritative seed instead of drawing its own future blockhash.
 * Returns a mismatch reason, or null when the seed echoes exactly. Only checked
 * for accepted results (the artifact is present); a reject carries no artifact.
 */
export function checkArtifactSeedEcho(
  artifact: CoreTexPostRevealEvalReportArtifact | undefined,
  pinned: RemoteScorerSeedContext,
  expectedSeeds?: { readonly gateSeed: string; readonly confirmSeed: string },
): string | null {
  if (!artifact) return null; // no artifact ⇒ not accepted ⇒ verifyScorerResult handles it
  const sd = (artifact as { seedDerivation?: { receivedAtBlock?: number; targetBlock?: number; blockhash?: string } }).seedDerivation;
  if (!sd || typeof sd !== "object") return "artifact seedDerivation missing — cannot confirm the scorer injected the pinned seed";
  if (sd.receivedAtBlock !== pinned.receivedAtBlock) {
    return `artifact seedDerivation.receivedAtBlock ${sd.receivedAtBlock} != coordinator-pinned ${pinned.receivedAtBlock}`;
  }
  if (sd.targetBlock !== pinned.targetBlock) {
    return `artifact seedDerivation.targetBlock ${sd.targetBlock} != coordinator-pinned ${pinned.targetBlock}`;
  }
  if (!hexEq(sd.blockhash, pinned.blockhash)) {
    return `artifact seedDerivation.blockhash ${sd.blockhash} != coordinator-pinned ${pinned.blockhash}`;
  }
  // §8 secretless scorer: the artifact's receipt must echo the EXACT seeds the
  // coordinator derived + shipped (proof the scorer injected, not invented).
  if (expectedSeeds) {
    const receipt = (artifact as { receipt?: { gateSeed?: string; confirmSeed?: string } }).receipt;
    if (!receipt || typeof receipt !== "object") return "artifact receipt missing — cannot confirm the scorer used the shipped eval seeds";
    if (!hexEq(receipt.gateSeed, expectedSeeds.gateSeed)) {
      return `artifact receipt.gateSeed ${receipt.gateSeed} != coordinator-derived ${expectedSeeds.gateSeed}`;
    }
    if (!hexEq(receipt.confirmSeed, expectedSeeds.confirmSeed)) {
      return `artifact receipt.confirmSeed ${receipt.confirmSeed} != coordinator-derived ${expectedSeeds.confirmSeed}`;
    }
  }
  return null;
}

function isBytes32(v: unknown): v is string {
  return typeof v === "string" && /^0x[0-9a-fA-F]{64}$/.test(v);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) throw new Error("hexToBytes: malformed hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function seedCommit(seed: string | undefined): string | null {
  if (!isBytes32(seed)) return null;
  return bytesToHex(keccak256(hexToBytes(seed))).toLowerCase();
}

/**
 * The six checks. Returns the reconstructed EvalResult on success (the
 * coordinator core then re-validates the dual-pack proof, applies the
 * state-advance/screener thresholds again, runs the §9 stale-root re-check,
 * and signs), or a distinct reject code on any failure.
 */
export function verifyScorerResult(args: {
  readonly result: ScorerJobResult;
  readonly job: ScorerJobRequest;
  /** (1) The set of jobIds the coordinator has outstanding. */
  readonly outstandingJobIds: ReadonlySet<string>;
  /** (2)+(6) live context re-read AT result time. */
  readonly active: RemoteScorerActiveContext;
  /** (5) expected model fingerprint (from the boot attestation). */
  readonly expectedHealth: RemoteScorerExpectedHealth;
}): VerifyScorerResult {
  const { result, job, outstandingJobIds, active, expectedHealth } = args;

  // (1) jobId matches an outstanding queued job.
  if (!result || typeof result !== "object") {
    return { ok: false, code: "SCORER_RESULT_MALFORMED", reason: "result is not an object" };
  }
  if (result.jobId !== job.jobId) {
    return { ok: false, code: "SCORER_JOB_ID_MISMATCH", reason: `result.jobId ${result.jobId} != job ${job.jobId}` };
  }
  if (!outstandingJobIds.has(job.jobId)) {
    return { ok: false, code: "SCORER_JOB_NOT_OUTSTANDING", reason: `jobId ${job.jobId} is not an outstanding queued job` };
  }

  // (3) result schema valid.
  const schema = validateResultSchema(result);
  if (schema) return { ok: false, code: "SCORER_RESULT_MALFORMED", reason: schema };

  // (2) parent/state-root/epoch/bundle/corpus context STILL matches active
  //     chain/coordinator state at result time. A result whose job was scored
  //     against a now-stale root is REFUSED (never transplanted onto the
  //     advanced root). The core re-checks the live root again before signing.
  if (job.epochId !== active.epochId) {
    return { ok: false, code: "SCORER_STALE_CONTEXT", reason: `job epoch ${job.epochId} != active ${active.epochId}` };
  }
  if (!hexEq(job.parentStateRoot, active.parentStateRoot)) {
    return { ok: false, code: "SCORER_STALE_CONTEXT", reason: `job parentStateRoot != active ${active.parentStateRoot}` };
  }
  if (!hexEq(job.corpusRoot, active.corpusRoot)) {
    return { ok: false, code: "SCORER_STALE_CONTEXT", reason: `job corpusRoot != active ${active.corpusRoot}` };
  }
  if (!hexEq(job.bundleHash, active.bundleHash)) {
    return { ok: false, code: "SCORER_STALE_CONTEXT", reason: `job bundleHash != active ${active.bundleHash}` };
  }
  if (!hexEq(job.coreVersionHash, active.coreVersionHash)) {
    return { ok: false, code: "SCORER_STALE_CONTEXT", reason: `job coreVersionHash != active ${active.coreVersionHash}` };
  }

  // (5) scorerHealth reports the expected model/revision/promptTemplateHash and
  //     dtype=fp32 / tf32=false / cuda=true.
  const h = result.scorerHealth;
  if (h.modelId !== expectedHealth.modelId) {
    return { ok: false, code: "SCORER_HEALTH_MISMATCH", reason: `modelId ${h.modelId} != expected ${expectedHealth.modelId}` };
  }
  if (h.revision !== expectedHealth.revision) {
    return { ok: false, code: "SCORER_HEALTH_MISMATCH", reason: `revision ${h.revision} != expected ${expectedHealth.revision}` };
  }
  if (!hexEq(h.promptTemplateHash, expectedHealth.promptTemplateHash)) {
    return { ok: false, code: "SCORER_HEALTH_MISMATCH", reason: `promptTemplateHash != expected ${expectedHealth.promptTemplateHash}` };
  }
  if (h.dtype !== "fp32") return { ok: false, code: "SCORER_HEALTH_MISMATCH", reason: `dtype ${h.dtype} != fp32` };
  if (h.tf32 !== false) return { ok: false, code: "SCORER_HEALTH_MISMATCH", reason: `tf32 ${h.tf32} != false` };
  if (h.cuda !== true) return { ok: false, code: "SCORER_HEALTH_MISMATCH", reason: `cuda ${h.cuda} != true` };

  // (6) the result's pins (corpusRoot / bundleHash / coreVersionHash) match
  //     active. The scorer echoes the pins it loaded via expectedScorerPins on
  //     the job + its proof; cross-check the proof's pins against active.
  if (result.evaluationProof) {
    const p = result.evaluationProof;
    if (!hexEq(p.corpusRoot, active.corpusRoot)) {
      return { ok: false, code: "SCORER_PIN_MISMATCH", reason: `proof corpusRoot != active ${active.corpusRoot}` };
    }
    if (!hexEq(p.coreVersionHash, active.coreVersionHash)) {
      return { ok: false, code: "SCORER_PIN_MISMATCH", reason: `proof coreVersionHash != active ${active.coreVersionHash}` };
    }
    if (!hexEq(p.parentStateRoot, active.parentStateRoot)) {
      return { ok: false, code: "SCORER_PIN_MISMATCH", reason: `proof parentStateRoot != active ${active.parentStateRoot}` };
    }
    const expectedGateSeedCommit = seedCommit(job.publicEvalContext?.gateSeed);
    const expectedConfirmSeedCommit = seedCommit(job.publicEvalContext?.confirmSeed);
    if (!expectedGateSeedCommit || !expectedConfirmSeedCommit) {
      return { ok: false, code: "SCORER_SEED_COMMIT_MISMATCH", reason: "job publicEvalContext missing valid gateSeed/confirmSeed" };
    }
    if (!hexEq(p.gate?.seedCommit, expectedGateSeedCommit)) {
      return { ok: false, code: "SCORER_SEED_COMMIT_MISMATCH", reason: "proof gate seedCommit != coordinator-derived gate seed commit" };
    }
    if (!hexEq(p.confirm?.seedCommit, expectedConfirmSeedCommit)) {
      return { ok: false, code: "SCORER_SEED_COMMIT_MISMATCH", reason: "proof confirm seedCommit != coordinator-derived confirm seed commit" };
    }
  }

  // (7) threshold/policy echo (§2 no-env-drift): the scorer must report the
  //     EXACT threshold + policy the coordinator shipped in the job. A drifted
  //     CORETEX_SCREENER_THRESHOLD_PPM env on the scorer can no longer silently
  //     change the advisory accept/reject or the committed artifact threshold —
  //     a mismatch is refused before the coordinator's own re-derivation.
  if (result.thresholdPpmUsed !== job.thresholdPpm) {
    return {
      ok: false,
      code: "SCORER_THRESHOLD_ECHO_MISMATCH",
      reason: `scorer used threshold ${result.thresholdPpmUsed} != job threshold ${job.thresholdPpm}`,
    };
  }
  if (!hexEq(result.policyHash, job.policyHash)) {
    return {
      ok: false,
      code: "SCORER_POLICY_ECHO_MISMATCH",
      reason: `scorer echoed policyHash ${result.policyHash} != job policyHash ${job.policyHash}`,
    };
  }

  // (4) threshold logic on the RETURNED scores. The coordinator owns the
  //     accept/reject decision — the scorer's `accepted` flag is advisory and
  //     does NOT bypass this. A rejected result short-circuits to a reject (no
  //     sign), and a result that does not clear min(gate,confirm) >= threshold
  //     is treated as a reject regardless of what the scorer claimed.
  if (!result.accepted) {
    return { ok: false, code: "SCORER_REJECTED", reason: result.rejectionReason ?? "scorer rejected patch" };
  }
  const minDual = Math.min(result.gateScorePpm, result.confirmScorePpm);
  if (minDual < active.thresholdPpm) {
    return {
      ok: false,
      code: "SCORER_BELOW_THRESHOLD",
      reason: `min(gate=${result.gateScorePpm}, confirm=${result.confirmScorePpm}) < live threshold ${active.thresholdPpm}`,
    };
  }

  // (8) artifact-bytes integrity (§3). An accepted result MUST carry the full
  //     canonical artifact whose recomputed hash equals BOTH artifactHash and
  //     evalReportHash, and whose context pins match active. The coordinator
  //     spools THESE bytes before signing, so a tampered/absent artifact is
  //     refused here (no spool, no sign).
  if (!result.artifact || typeof result.artifact !== "object") {
    return { ok: false, code: "SCORER_ARTIFACT_MISSING", reason: "accepted result must carry the canonical eval-report artifact" };
  }
  let recomputed: string;
  try {
    recomputed = hashPostRevealEvalReportArtifact(result.artifact);
  } catch (err) {
    return { ok: false, code: "SCORER_ARTIFACT_MALFORMED", reason: err instanceof Error ? err.message : String(err) };
  }
  if (!hexEq(recomputed, result.artifactHash) || !hexEq(recomputed, result.evalReportHash)) {
    return {
      ok: false,
      code: "SCORER_ARTIFACT_HASH_MISMATCH",
      reason: `recomputed artifact hash ${recomputed} != artifactHash ${result.artifactHash} / evalReportHash ${result.evalReportHash}`,
    };
  }
  const ctx = result.artifact.context;
  if (!ctx || typeof ctx !== "object") {
    return { ok: false, code: "SCORER_ARTIFACT_CONTEXT_MISMATCH", reason: "artifact context missing" };
  }
  if (!hexEq(ctx.parentStateRoot, active.parentStateRoot)) {
    return { ok: false, code: "SCORER_ARTIFACT_CONTEXT_MISMATCH", reason: `artifact parentStateRoot != active ${active.parentStateRoot}` };
  }
  if (!hexEq(ctx.corpusRoot, active.corpusRoot)) {
    return { ok: false, code: "SCORER_ARTIFACT_CONTEXT_MISMATCH", reason: `artifact corpusRoot != active ${active.corpusRoot}` };
  }
  if (!hexEq(ctx.coreVersionHash, active.coreVersionHash)) {
    return { ok: false, code: "SCORER_ARTIFACT_CONTEXT_MISMATCH", reason: `artifact coreVersionHash != active ${active.coreVersionHash}` };
  }

  // Reconstruct the EvalResult the coordinator core consumes. The core then
  // re-validates the dual-pack proof + re-applies the state-advance/screener
  // thresholds + §9 re-check before signing. A state_advance requires the
  // rewritten bytes + before/after scores; otherwise it is a screener_pass.
  const stateAdvance =
    result.scoreBeforePpm !== null &&
    result.scoreAfterPpm !== null &&
    typeof result.rewrittenPatchBytesHex === "string";
  if (stateAdvance) {
    return {
      ok: true,
      artifact: result.artifact,
      evalResult: {
        outcome: "state_advance",
        deterministicDeltaPpm: result.deltaPpm,
        evalReportHash: result.evalReportHash as string,
        artifactHash: result.artifactHash as string,
        scoreBeforePpm: result.scoreBeforePpm as number,
        scoreAfterPpm: result.scoreAfterPpm as number,
        rewrittenPatchBytesHex: result.rewrittenPatchBytesHex as string,
        ...(result.evaluationProof ? { evaluationProof: result.evaluationProof } : {}),
      },
    };
  }
  return {
    ok: true,
    artifact: result.artifact,
    evalResult: {
      outcome: "screener_pass",
      deterministicDeltaPpm: result.deltaPpm,
      evalReportHash: result.evalReportHash as string,
      artifactHash: result.artifactHash as string,
      ...(result.evaluationProof ? { evaluationProof: result.evaluationProof } : {}),
    },
  };
}

function validateResultSchema(result: ScorerJobResult): string | null {
  if (typeof result.accepted !== "boolean") return "accepted must be boolean";
  if (typeof result.deltaPpm !== "number" || !Number.isFinite(result.deltaPpm)) return "deltaPpm invalid";
  if (typeof result.gateScorePpm !== "number" || typeof result.confirmScorePpm !== "number") return "gate/confirm score invalid";
  if (!Number.isSafeInteger(result.thresholdPpmUsed) || result.thresholdPpmUsed < 0) return "thresholdPpmUsed invalid";
  if (!isBytes32(result.policyHash)) return "policyHash must be bytes32";
  if (typeof result.pairTraceHash !== "string" || typeof result.scoreArrayHash !== "string") return "trace hashes missing";
  if (!result.scorerHealth || typeof result.scorerHealth !== "object") return "scorerHealth missing";
  if (result.accepted) {
    if (!isBytes32(result.evalReportHash)) return "accepted result missing evalReportHash";
    if (!isBytes32(result.artifactHash)) return "accepted result missing artifactHash";
    if (result.evaluationProof && result.evaluationProof.kind !== "coretex-dual-pack-v1") return "evaluationProof kind invalid";
  }
  return null;
}
