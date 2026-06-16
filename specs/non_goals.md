# CoreTex Non-Goals

> Phase 0 deliverable. Verified and tightened by Research subagent, 2026-05-05.
> The list of things CoreTex explicitly does NOT ship, so the design does not sprawl.

CoreTex is a pre-launch retrieval-substrate improvement lane that pays through the existing receipt path**. Not a
model-training lane.

---

## Hard Rejected for CoreTex

The following items are explicitly out of scope for CoreTex. Each entry includes the rejection rationale
and, where applicable, the V1 tracked path.

### 1. Weights on-chain
**Rejected because:** Full model weights are orders of magnitude too large for on-chain storage
and defeat the purpose of a compact codec. The organism is a 32 KB memory codec, not a model.
CortexState stores *how to find, route, update, and invalidate memory* — not model parameters.

### 2. LoRA mining
**Rejected because:** LoRA mining turns Cortex into a model-training lane and introduces
subjective quality judgments (which model is better?). The canonical verifier cannot
deterministically evaluate model quality without an API model in consensus — which is explicitly
rejected by the deterministic-verifier design.

### 3. Arbitrary memory text stored on-chain
**Rejected because:** Raw text storage on-chain is expensive, non-deterministic in value, and
breaks the codec design. CortexState stores compact binary representations (keys, routing weights,
validity intervals), not prose. The `experienceCorpusRoot` commits the off-chain corpus hash; the
corpus itself is not stored on-chain.

### 4. Miner-to-miner mandatory coordination
**Rejected because:** Mandatory coordination creates a cartel vector and reintroduces the
centralization the tier system is designed to prevent. Miners compete independently; the
deterministic reducer handles conflict resolution without requiring miners to communicate.

### 5. Subjective AI judging in canonical scoring
**Rejected because:** Any API model in the canonical verification path breaks determinism. Two
machines running the same Core version with the same state and same benchmark seed must produce
byte-identical results. A frontier model API cannot guarantee this. Miners may use any LLM
externally to *propose* patches; the canonical *verifier* is fully deterministic.

### 6. Constantly mutable Botcoin Core (ambiguous upgrade semantics)
**Rejected because:** Core upgrades without a defined migration path create a moving-target that
rewards tracking Core versions rather than improving the codec. CoreTex requires that every Core upgrade
either (a) publishes a `state_translation_patch` mapping V_n → V_{n+1}, or (b) explicitly resets
the organism with documented rationale. Ambiguity is a hard non-goal.

### 7. Separate Cortex reward currency
**Rejected because:** A separate token fragments the economic spine and adds regulatory/liquidity
complexity. Cortex credits are denominated in the existing Botcoin tier system and paid through
normal state-advance receipts. No new token, no new claim flow.

### 8. New EIP-712 domain
**Rejected because:** A new signing domain requires new contract audit surface and new miner SDK
changes. Cortex receipts ride the existing `BotcoinMining` EIP-712 domain with the §6 receipt
field mapping (`rulesVersion = 0xC0` as the Cortex discriminator). Auditors and explorers
disambiguate via `rulesVersion`. Soft-coupling is explicitly acknowledged and is acceptable for CoreTex
because the contract does not introspect field semantics — only the signature.
**V1 path:** `BotcoinMining.submitCortexReceipt(...)` sister function with explicit Cortex field
names, tracked in Phase 9 release notes.

### 9. Editing BotcoinMiningV3
**Rejected because:** `BotcoinMiningV3` is deployed and unchanged. All Cortex mechanics are
additive (the live-state anchor is `CortexRegistry`; `CortexMergeBonus` remains only as a previous
compatibility rail). The existing `claim()` math reads `epochReward × minerCredits / totalCredits`
directly from on-chain state, so CoreTex pays useful Cortex improvements as normal credits instead of a
separate multiplier.

### 10. On-chain fraud proofs for CoreTex scoring
**Rejected because:** The EVM cannot re-run Botcoin Core. A full ZK or bond-based fraud proof
system requires substantial additional engineering and is out of scope for CoreTex. Launch accountability
comes from open coordinator code, independent validator replay, public roots, signed artifacts, and
operator/governance response if validators expose cheating.
**V1 path:** Bond-based or ZK scoring fraud proofs, tracked in Phase 9 release notes.

### 11. `?lane=coretex` query-string routing
**Rejected because:** Query-string lane selection creates a misroute risk where a deliberately or
accidentally malformed query string could silently fall through to the SWCP handler. Cortex routing
is path-prefix only: `/coretex/*` → coordinator upstream (nginx path-prefix routing). No
`?lane=` parameter exists anywhere in the system.

### 12. Score-threshold-free screener (any patch earns credits)
**Rejected because:** Without a score threshold, random mutation and no-op patches pass and earn
credits. The screener enforces `candidateScore > baselineScore + threshold`, non-noop, non-overfit,
non-protected-regression, within-budget. This is the core anti-gaming mechanism.

---

## Tracked V1 Paths (Not Blocking CoreTex)

These are not rejections — they are deferred improvements that are explicitly out of CoreTex scope and
tracked for V1.

| V1 Path | Rationale for CoreTex deferral | Where tracked |
|---------|--------------------------|---------------|
| `BotcoinMining.submitCortexReceipt(...)` sister function with explicit Cortex field names | current field-alias approach is acceptable because the contract only checks the signature; V1 adds clarity for explorers and removes the soft-coupling. | §9 Phase 9 release notes |
| Bond-based or ZK scoring fraud proofs | Requires significant additional engineering; launch relies on independent replay and operator/governance response. | §9 Phase 9 release notes |
| Adaptive compression across ECS levels (memory ↔ skills ↔ rules) | The ECS "missing diagonal" is the research frontier; CoreTex encodes all three levels in the state layout but does not implement adaptive cross-level compression. | Research brief §2.8 |
| Per-subset BEIR license verification and automated per-subset loader | current loader uses manually verified subsets; V1 automates the per-subset license check in CI. | `specs/license_audit.md` Phase 4 note |

---

## What CoreTex IS

To make the non-goals concrete, here is the positive definition:

CoreTex Botcoin Cortex is:
- A **compact on-chain-rooted memory codec** (1024 uint256 words = 32 KB active state)
- A **deterministic proof-of-improvement verifier** (Botcoin Core, pinned version, no API model)
- A **credit-unified mining lane** (state-advance receipts via existing `BotcoinMining.submitReceipt`)
- An **anchored benchmark** (LIMIT + MTEB/BEIR for near-collision; LoCoMo + MemoryAgentBench for
  temporal; MemoryArena for long-horizon)
- A **parallel lane** (coordinator-mounted CoreTex route handler with shared coordinator lifecycle;
  SWCP unchanged and unaffected)

Done when: all subagents agree CoreTex is a memory-codec improvement lane that pays through the existing
receipt path, not a model-training lane.
