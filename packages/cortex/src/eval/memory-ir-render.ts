/**
 * Protocol-owned Memory-IR render grammar — the SINGLE renderer shared by every consumer of MemoryOps
 * training/serving data (exporter, trainer, full-benchmark probe, scorer serve-time path). The field set
 * and ordering are fixed by the protocol; miners do not control the grammar. JS consumers import THIS
 * compiled function (so JS≡TS by construction); the Python trainer replicates the grammar and a golden test
 * (`scripts/test-memory-ir-render-golden.mjs`) asserts byte-equality across all three.
 *
 * The header renders only RESOLVED-STATE-DERIVED / PUBLIC-STRUCTURE fields and OMITS defaults (none / empty /
 * null / false / 0) so lifecycle=none / no-structure docs get raw text (no off-family noise header). No doc
 * IDs, query IDs, or hidden qrels ever enter the rendered text. `subject_scope` is an entity token and is
 * NOT rendered (kept only as split provenance), which also keeps the served text ID-free.
 *
 * Field order (fixed): lifecycle ; role ; path ; conflict ; scope ; evidence ; density
 *   [memory_ir lifecycle=current; role=support; path=supports; conflict=candidate; scope=match; evidence=true; density=2]
 */

export interface MemoryIR {
  /** resolved-state lifecycle from decoded.temporal (current/superseded) or 'none'. */
  lifecycle?: 'current' | 'superseded' | 'none';
  /** evidence role from PUBLIC relation structure (answer/support/context) or 'none'. */
  evidence_role?: 'answer' | 'support' | 'context' | 'none';
  /** public relation-edge types from candidate to the query subject. */
  relation_path?: string[];
  /** contradicts-edge role (resolved=source / candidate=target) or 'none'. */
  conflict_state?: 'resolved' | 'candidate' | 'none';
  /** query-scope vs candidate-text scope: true=match, false=differs, null/undefined=not applicable. */
  scope_match?: boolean | null;
  /** candidate sits on a public evidence path (supports/causes/…). */
  has_public_evidence_path?: boolean;
  /** supports-in-degree (public answer-density signal). */
  answer_density?: number;
  /** entity bucket — PROVENANCE ONLY, never rendered into served/trained text. */
  subject_scope?: string;
}

/** Render the protocol header, or null when no field carries non-default signal (→ raw text). */
export function renderMemoryIRHeader(ir: MemoryIR | null | undefined): string | null {
  if (!ir) return null;
  const parts: string[] = [];
  if (ir.lifecycle && ir.lifecycle !== 'none') parts.push(`lifecycle=${ir.lifecycle}`);
  if (ir.evidence_role && ir.evidence_role !== 'none') parts.push(`role=${ir.evidence_role}`);
  const path = (ir.relation_path ?? []).filter((p) => typeof p === 'string' && p.length > 0);
  if (path.length > 0) parts.push(`path=${[...new Set(path)].sort().join(',')}`);
  if (ir.conflict_state && ir.conflict_state !== 'none') parts.push(`conflict=${ir.conflict_state}`);
  if (ir.scope_match === true) parts.push('scope=match');
  else if (ir.scope_match === false) parts.push('scope=differs');
  if (ir.has_public_evidence_path === true) parts.push('evidence=true');
  if (typeof ir.answer_density === 'number' && ir.answer_density > 0) parts.push(`density=${ir.answer_density}`);
  if (parts.length === 0) return null;
  return `[memory_ir ${parts.join('; ')}]`;
}

/** Render the full served/trained document: header + newline + candidate text, or raw text if no header. */
export function renderMemoryIRDoc(ir: MemoryIR | null | undefined, candidateText: string): string {
  const header = renderMemoryIRHeader(ir);
  return header ? `${header}\n${candidateText}` : candidateText;
}
