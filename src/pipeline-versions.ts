/**
 * Pipeline-version law routing (BMU_SPEC.md §3, §9).
 *
 * LEAF MODULE — no imports. Every STATE-LAYOUT decision that used to
 * string-compare `pipelineVersion === 'coretex-retrieval-v2-policy-r5'`
 * MUST use `isR5StateLaw(...)` instead (spec §9 implementers' rule), so
 * the ONLY place the r5 and BMU laws diverge is SCORING-LAW routing
 * (`isBmuScoringLaw`, consumed at spec §9 site 1 and the evaluator wiring).
 *
 * `coretex-bmu-v1-r5state` (spec §3.1): the name is normative — the DECODE
 * LAW IS THE R5 DECODE LAW (invariant I2). One law change per transition:
 * BMU changes the scoring law only, never the state layout.
 *
 * Fail-closed asymmetry (spec §9): a site that still literal-compares the
 * r5 string treats a BMU bundle as unknown and REFUSES it — never a silent
 * misdecode. That is why BMU pins the r5 state law.
 */

/** The r5 PolicyAtom scoring+state law (live production law). */
export const CORETEX_PIPELINE_VERSION_R5 = 'coretex-retrieval-v2-policy-r5';

/** BMU v1: Budgeted Memory Utility scoring law over the UNCHANGED r5 state
 *  layout/decode law (BMU_SPEC.md §3.1; exact name is normative). */
export const CORETEX_PIPELINE_VERSION_BMU_V1 = 'coretex-bmu-v1-r5state';

/** BMU v2: generic bounded public-path scoring over the unchanged r5 state
 * layout. A separate pin keeps v1 artifacts replayable under v1 semantics. */
export const CORETEX_PIPELINE_VERSION_BMU_V2 = 'coretex-bmu-v2-r5state';

/** Pipeline versions whose STATE LAYOUT / decode / patch-grammar law is the
 *  r5 law (spec §3.2): r5 itself plus BMU v1 (r5state by construction). */
export const R5_STATE_LAW_PIPELINE_VERSIONS: ReadonlySet<string> = new Set([
  CORETEX_PIPELINE_VERSION_R5,
  CORETEX_PIPELINE_VERSION_BMU_V1,
  CORETEX_PIPELINE_VERSION_BMU_V2,
]);

/** STATE-LAYOUT routing (spec §9 [STATE] sites): true iff `pipelineVersion`
 *  pins the r5 state law — r5 PolicyAtom decode, policyAtomsMode=true,
 *  KEY_UPDATE/CODEBOOK_UPDATE/HEADER_UPDATE suppression, reserved-zero 896-991. */
export function isR5StateLaw(pipelineVersion: string | undefined): boolean {
  return pipelineVersion !== undefined && R5_STATE_LAW_PIPELINE_VERSIONS.has(pipelineVersion);
}

/** SCORING-LAW routing (spec §9 [LAW] sites): true iff `pipelineVersion`
 *  routes scoring to the BMU v1 deterministic budgeted-utility judge. */
export function isBmuScoringLaw(pipelineVersion: string | undefined): boolean {
  return pipelineVersion === CORETEX_PIPELINE_VERSION_BMU_V1
    || pipelineVersion === CORETEX_PIPELINE_VERSION_BMU_V2;
}

export function isBmuV2ScoringLaw(pipelineVersion: string | undefined): boolean {
  return pipelineVersion === CORETEX_PIPELINE_VERSION_BMU_V2;
}
