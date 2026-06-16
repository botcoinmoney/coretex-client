# CoreTex Memory Control Plane Minimal Spec

Status: launch-direction draft.  
Scope: smallest tracked spec for making CoreTex an installable external memory policy sidecar. This is not a reranker
tuning plan and not a replacement for the DGEN-1 longevity path.

## Goal

CoreTex should sit between arbitrary memory backends and an agent/model:

```text
memory adapters -> normalized Memory IR -> CoreTex substrate policy -> retrieval plan -> evidence bundle -> reranker -> agent packet
```

The main model stays clean. Storage backends and reranker versions can vary, but they compile into the same operational
memory interface.

## Minimal Memory IR

Each memory candidate must be representable as:

```json
{
  "memoryId": "string",
  "text": "string",
  "entityIds": ["string"],
  "ownerScope": "string",
  "timestamp": "iso8601|string|number",
  "validFrom": "iso8601|string|number|null",
  "validUntil": "iso8601|string|number|null",
  "revoked": false,
  "supersededBy": "memoryId|null",
  "source": "string",
  "provenance": {
    "sourceId": "string",
    "sourceHash": "string|null",
    "writer": "string|null"
  },
  "relationEdges": [
    {
      "to": "memoryId",
      "type": "supersedes|supports|causes|coreference_of|belongs_to_project|decision_reason|decision_outcome|fixes|depends_on|context_of|other",
      "label": "string|null"
    }
  ],
  "retrievalPath": ["dense|sparse|temporal|relation|retrieval_key|manual|other"],
  "evidenceRole": "direct|bridge|stale|conflict|context|negative|unknown",
  "confidence": 0.0,
  "permissions": ["string"]
}
```

Adapters may provide more fields, but the benchmark/runtime must not require backend-specific structure beyond this IR.

## Retrieval Plan

A CoreTex policy run should emit a retrieval plan before final reranking:

```json
{
  "queryId": "string",
  "ownerScope": "string",
  "activePolicyState": "stateRootOrHash",
  "candidateSources": ["dense", "sparse", "temporal", "relation", "retrieval_key"],
  "suppressionRules": ["stale", "revoked", "wrong_scope", "permission_denied"],
  "routingHints": [
    {
      "type": "temporal|relation|retrieval_key|evidence_policy",
      "reason": "string",
      "stateRegion": "MemoryIndex|Relations|Temporal|RetrievalKeys|Codebook|Future"
    }
  ]
}
```

## Evidence Bundle

The packet passed to the reranker/agent should be small and inspectable:

```json
{
  "queryId": "string",
  "answerCandidate": "memoryId",
  "bundle": [
    { "memoryId": "string", "role": "direct|bridge|stale|conflict|context" }
  ],
  "whyIncluded": "string",
  "whySuppressed": [
    { "memoryId": "string", "reason": "stale|revoked|wrong_scope|low_evidence_density|conflict" }
  ]
}
```

## Trace Receipt

Every scored answer packet should produce a trace receipt:

```json
{
  "queryId": "string",
  "stateRoot": "string",
  "corpusRoot": "string",
  "profileHash": "string",
  "rerankerRevision": "string",
  "baselineEpoch": "string",
  "retrieved": ["memoryId"],
  "suppressed": ["memoryId"],
  "bundled": ["memoryId"],
  "rerankedTop10": ["memoryId"],
  "sourceAttribution": {
    "temporal": 0,
    "relation": 0,
    "retrievalKey": 0,
    "dense": 0
  },
  "accepted": false,
  "deltaPpm": 0
}
```

## Acceptance Tests

This spec becomes real only when the runtime can:

1. Convert at least one DGEN-1 corpus/query pack into Memory IR.
2. Produce retrieval plans and evidence bundles for temporal and relation families.
3. Emit trace receipts with source attribution for accepted and rejected patches.
4. Keep scorer/operator knobs separate from miner-written substrate regions.
5. Replay the same IR + state + profile + reranker revision deterministically inside one epoch.

## Epoch Rule

If the reranker, corpus, hidden eval, or IR semantics change, start a new epoch:

```text
new reranker/corpus/IR -> rerun baseline -> recalibrate difficulty -> revalidate substrate families
```

Do not compare miner patches across epochs as if they share one baseline.
