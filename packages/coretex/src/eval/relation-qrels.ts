import type {
  GradedRelevance,
  QrelEntry,
  RelationAnnotation,
  TruthDocument,
} from './retrieval-corpus.js';

export function canonicalAnswerText(text: string): string {
  return String(text)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

export interface RelationAnswerAliasInput {
  readonly family: string;
  readonly truthDocuments: readonly TruthDocument[];
  readonly relations?: readonly RelationAnnotation[];
  readonly relationTruthDocumentsByEventId?: ReadonlyMap<string, readonly TruthDocument[]>;
}

export interface RelationAnswerAliasStats {
  readonly candidateTruthDocs: number;
  readonly added: number;
  readonly upgraded: number;
  readonly duplicates: number;
  readonly fullCredit: number;
  readonly partialCredit: number;
}

const ZERO_ALIAS_STATS: RelationAnswerAliasStats = {
  candidateTruthDocs: 0,
  added: 0,
  upgraded: 0,
  duplicates: 0,
  fullCredit: 0,
  partialCredit: 0,
};

export function addRelationAnswerAliasQrels(
  qrels: readonly QrelEntry[],
  input: RelationAnswerAliasInput,
): { readonly qrels: readonly QrelEntry[]; readonly stats: RelationAnswerAliasStats } {
  if (
    input.family !== 'multi_hop_relation' ||
    !input.relations ||
    input.relations.length === 0 ||
    !input.relationTruthDocumentsByEventId
  ) {
    return { qrels, stats: ZERO_ALIAS_STATS };
  }

  const currentTruthTexts = input.truthDocuments
    .filter((doc) => doc.isCurrent)
    .map((doc) => canonicalAnswerText(doc.text))
    .filter(Boolean);
  const answerTexts = new Set(
    currentTruthTexts.length > 0
      ? currentTruthTexts
      : input.truthDocuments.map((doc) => canonicalAnswerText(doc.text)).filter(Boolean),
  );

  const out: QrelEntry[] = qrels.map((q) => ({ documentId: q.documentId, relevance: q.relevance }));
  const byId = new Map<string, number>();
  for (let i = 0; i < out.length; i++) byId.set(out[i]!.documentId, i);

  let candidateTruthDocs = 0;
  let added = 0;
  let upgraded = 0;
  let duplicates = 0;
  let fullCredit = 0;
  let partialCredit = 0;

  function upsert(documentId: string, relevance: GradedRelevance): void {
    const existingIdx = byId.get(documentId);
    if (existingIdx === undefined) {
      byId.set(documentId, out.length);
      out.push({ documentId, relevance });
      added++;
      return;
    }
    const existing = out[existingIdx]!;
    if (relevance > existing.relevance) {
      out[existingIdx] = { documentId, relevance };
      upgraded++;
    } else {
      duplicates++;
    }
  }

  for (const rel of input.relations) {
    const targetTruths = input.relationTruthDocumentsByEventId.get(rel.other_id);
    if (!targetTruths) continue;
    for (const targetTruth of targetTruths) {
      if (!targetTruth.isCurrent) continue;
      candidateTruthDocs++;
      const canonicalTarget = canonicalAnswerText(targetTruth.text);
      const relevance = (answerTexts.has(canonicalTarget) ? 1.0 : 0.8) as GradedRelevance;
      if (relevance === 1.0) fullCredit++;
      else partialCredit++;
      upsert(targetTruth.id, relevance);
    }
  }

  return {
    qrels: out,
    stats: { candidateTruthDocs, added, upgraded, duplicates, fullCredit, partialCredit },
  };
}
