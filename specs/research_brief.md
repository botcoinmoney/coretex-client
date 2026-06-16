# CoreTex Research Brief

> Phase 0 research snapshot. Historical weights and pass-rate targets are preserved here for
> traceability; record concerns in-line instead of changing this baseline.

---

## 1. One-Page Thesis

**Title:** Proof-of-Cortex over Compact On-Chain Memory Codec, Credit-Unified with SWCP

### Core claim

Botcoin Cortex turns mining into public proof-of-memory-improvement, paid through the same economic
spine the protocol already runs on. The organism is not a model and not a text database. It is a
compact, on-chain-rooted memory codec (1024 uint256 words = 32 KB active state) that becomes better
only when miners prove improvements under the deterministic Botcoin Core verifier.

### What "proof-of-improvement" means

A miner submits a candidate patch — a small set of word-level mutations to the CortexState. The
canonical verifier (Botcoin Core, pinned version) runs the patch against a deterministic CoreTex benchmark
suite anchored to public benchmark families. The patch is accepted iff:
- `candidateScore > baselineScore + threshold`
- No protected-regression anchor drops
- Patch is within budget (CoreTex: 1–4 words)
- Evaluation is byte-reproducible on a clean machine

This is "proof-of-Cortex": a verifiable, on-chain-rooted certificate that the shared memory
substrate improved.

### Credit unification with SWCP

State-advance Cortex receipts flow through the same `BotcoinMining.submitReceipt` EIP-712 path that
SWCP already uses. No new reward currency, no new tier table. The miner's current on-chain tier
(from `BotcoinMiningV3.getTier()`) determines the base credit value. A candidate must advance the
live state to earn credits; screener-only candidates do not get paid. The merge-bonus rail is
set to 1.0× / no uplift in production launch.

### Why this state shape is research-backed

Single-vector retrieval has proven structural limits as corpus size grows (LIMIT, Weller et al.
2025/2026). The 1024-word CortexState is designed as many tiny interaction points: binary keys,
multi-vector slots, relation codes, routing weights, validity intervals, revocation bits, small
codebook entries. The Experience Compression Spectrum (Zhang et al., arXiv:2604.15877) frames
memory, skills, and rules as different compression levels; Botcoin Cortex is exactly that
experiment — a living codec operating across all three levels simultaneously.

### Why this is the right test

The three benchmark families are chosen because each tests a distinct property that cannot be
faked:
- **Near-collision retrieval** (20%): Tests whether the codec's binary/multi-vector keys actually
  discriminate similar-but-distinct items. Anchored to LIMIT + MTEB/BEIR — hardest at low
  dimensions, exactly where a 32 KB codec operates.
- **Temporal update / revocation** (20%): Tests whether the codec can track what is stale.
  Anchored to LoCoMo + MemoryAgentBench temporal subset — real conversational records with
  stale-vs-current ground truth.
- **Long-horizon compression** (60%): Tests whether the codec survives capacity pressure over many
  sessions. Anchored to MemoryArena multi-session loops plus a synthetic stream-and-evict generator.
  This family does not saturate as the codec improves — that is why it carries the dominant weight.

### Clean summary

> Cortex mining proves: I improved the shared memory substrate that future Botcoin agents read
> through Core — and I get paid through the same receipt path I already use, plus a sister-contract
> bonus when my patch is merged.

---

## 2. Source Review

### 2.1 LIMIT — Near-Collision Anchor

**Full citation:** Orion Weller, Michael Boratko, Iftekhar Naim, Jinhyuk Lee. "On the Theoretical
Limitations of Embedding-Based Retrieval." arXiv:2508.21038. Accepted ICLR 2026.

**What it is:** A benchmark and theoretical analysis demonstrating that the number of top-k document
subsets retrievable by any embedding-based system is bounded by the embedding dimension. The LIMIT
dataset contains 50,000 documents, 1,000 queries, and 2,000 relevant query-document mappings,
available in both full and small-sample variants.

**Why it anchors Family 1:** LIMIT directly proves that near-collision failure is structural and
dimension-limited — exactly the failure mode the binary/multi-vector key design of CortexState
addresses. Using LIMIT as the near-collision benchmark family means CoreTex benchmark is testing a
property that has formal grounding, not an ad hoc perturbation.

**Configuration for CoreTex benchmark:** Public query/passage pairs from the LIMIT dataset, standard
Recall@K and MRR@10 metrics, with perturbation operators: bit-flip distance d ∈ {1, 2, 4} on
derived binary keys, and controlled cosine-distance ε on dense-key variants. Supplemented by
selected MTEB Retrieval / BEIR subsets (see §2.2).

**License:** Apache-2.0 (code); CC-BY-4.0 (dataset/materials). Both are redistribution-OK with
attribution. See `specs/license_audit.md` for full attribution requirements.

**Repository:** https://github.com/google-deepmind/limit

---

### 2.2 MTEB Retrieval / BEIR — Near-Collision Supplementary

**MTEB full citation:** Niklas Muennighoff et al. "MTEB: Massive Text Embedding Benchmark."
GitHub: embeddings-benchmark/mteb, Apache-2.0.

**BEIR full citation:** Nandan Thakur et al. "BEIR: A Heterogeneous Benchmark for Zero-shot
Evaluation of Information Retrieval Models." GitHub: beir-cellar/beir, Apache-2.0.

**What it is:** MTEB is the comprehensive embedding benchmark suite (retrieval, classification,
clustering, etc.). BEIR is the underlying heterogeneous IR dataset collection used by MTEB
Retrieval tasks — 15+ diverse datasets covering biomedical, question-answering, entity, and news
retrieval.

**Why it supplements Family 1:** MTEB/BEIR provides the broadest coverage of retrieval task
diversity and is the de-facto standard for embedding evaluation. Anchoring to specific BEIR subsets
(NQ, HotpotQA, TREC-COVID recommended for CoreTex) gives CoreTex benchmark near-collision tasks with known
difficulty calibration.

**License:** BEIR code Apache-2.0; MTEB code Apache-2.0. Individual BEIR dataset subsets carry
their upstream dataset licenses (varying; cc-by-sa-4.0 for HF-hosted preprocessed versions). CoreTex
must verify and use only subsets with redistribution-compatible licenses — see `specs/license_audit.md`.

**Repositories:** https://github.com/embeddings-benchmark/mteb | https://github.com/beir-cellar/beir

---

### 2.3 WARP — Late-Interaction Multi-Vector Retrieval Efficiency

**Full citation:** Jan Luca Scheerer, Matei Zaharia, Christopher Potts, Gustavo Alonso, Omar
Khattab. "WARP: An Efficient Engine for Multi-Vector Retrieval." arXiv:2501.17788. Accepted
SIGIR 2025.

**What it is:** WARP is an efficient retrieval engine for XTR-based ColBERT models combining
innovations: WARP_SELECT (dynamic similarity imputation), implicit decompression, and two-stage
reduction. Achieves 41× latency reduction over XTR reference and 3× speedup over ColBERTv2/PLAID
while preserving retrieval quality.

**Why it is research context, not a data source:** WARP informs the multi-vector slot design in
CortexState. The existence of efficient late-interaction retrieval (WARP, ColBERTv2) justifies
representing state as many tiny interaction points (binary keys, multi-vector slots) rather than
one dense vector. CoreTex benchmark does not directly load WARP task data — WARP is the architectural
motivation for the state layout.

**Implementation reference:** https://github.com/jlscheerer/xtr-warp (MIT license, code only).
Upstream XTR: https://github.com/google-deepmind/xtr (Apache-2.0/CC-BY-4.0 dual).

---

### 2.4 LoCoMo — Temporal Update / Revocation Anchor

**Full citation:** Adyasha Maharana et al. "Evaluating Very Long-Term Conversational Memory of LLM
Agents." arXiv:2402.17753. ACL 2024.

**What it is:** LoCoMo is a long-conversational-memory benchmark with synthetic dialogues spanning
up to 300 turns (~16,000 tokens). Records carry stale-vs-current ground-truth labels for persona,
facts, and events. Tasks include question answering, event summarization, and multi-hop reasoning
across time.

**Why it anchors Family 2:** LoCoMo's stale-vs-current labels are the ground truth for the
temporal update / revocation family. A CortexState patch that correctly evicts stale records and
surfaces current ones against real LoCoMo records earns Family 2 score; one that keeps stale
entries earns a penalty. The public records are re-encoded into Cortex event format under
`experienceCorpusRoot`.

**License:** CC-BY-NC-4.0 (NonCommercial). **IMPORTANT: This is a redistribution constraint.**
The NonCommercial clause applies to data redistribution. Botcoin Cortex Phase 4 loader must not
redistribute LoCoMo data directly; it must fetch from the canonical source at runtime or check with
authors for commercial use terms. Marked as requiring manual review before Phase 4 lock — see
`specs/license_audit.md`.

**Repository:** https://github.com/snap-research/LoCoMo

---

### 2.5 MemoryAgentBench — Temporal Subset Anchor

**Full citation:** Yuanzhe Hu, Yu Wang, Julian McAuley. "Evaluating Memory in LLM Agents via
Incremental Multi-Turn Interactions." arXiv:2507.05257. Accepted ICLR 2026.

**What it is:** MemoryAgentBench evaluates memory in LLM agents via incremental multi-turn
interactions. Includes tasks drawn from RULER, InfBench, HELMET, and LongmemEval, plus two
newly constructed tasks: EventQA and FactConsolidation. The temporal subset specifically tests
stale-vs-current truth labels across incremental memory updates.

**Why it anchors Family 2 (supplementary):** MemoryAgentBench's temporal tasks provide incremental
multi-turn scenarios where the correct answer changes over time — exactly the revocation scenario
CortexState's validity-interval and revocation-bit design must handle. It complements LoCoMo with a
more structured, agentic framing.

**License:** MIT (HuggingFace dataset card: `license: mit`; confirmed via
https://huggingface.co/datasets/ai-hyz/MemoryAgentBench). Redistribution OK with attribution.

**Repository:** https://github.com/HUST-AI-HYZ/MemoryAgentBench
**HuggingFace dataset:** https://huggingface.co/datasets/ai-hyz/MemoryAgentBench

---

### 2.6 MemoryArena — Long-Horizon Compression Anchor

**Full citation:** Zexue He, Yu Wang, Churan Zhi, Yuanzhe Hu, Tzu-Ping Chen, Lang Yin, Ze Chen,
Tong Arthur Wu, Siru Ouyang, Zihan Wang, Jiaxin Pei, Julian McAuley, Yejin Choi, Alex Pentland.
"MemoryArena: Benchmarking Agent Memory in Interdependent Multi-Session Agentic Tasks."
arXiv:2602.16313. February 2026.

**What it is:** MemoryArena is a unified evaluation gym for multi-session Memory-Agent-Environment
loops. It consists of human-crafted agentic tasks with explicitly interdependent subtasks across:
bundled shopping, progressive search, group travel planning, formal reasoning (math and physics).
Agents must distill experiences from earlier sessions into memory, then use that memory to solve
later tasks. A key finding: agents with near-saturated performance on LoCoMo perform poorly here —
exposing a gap in existing long-context evaluations.

**Why it anchors Family 3:** MemoryArena's multi-session interdependence creates genuine capacity
pressure on the 1024-word CortexState. An agent (or miner's codec patch) that can compress
earlier-session experience correctly while retaining what later sessions need earns Family 3 score.
This is the only family that does not saturate as the codec improves — compression pressure scales
with session count, which can be parameterized beyond MemoryArena's default configurations using
the synthetic stream-and-evict generator.

**License:** CC-BY-4.0 (HuggingFace dataset `ZexueHe/memoryarena`). Redistribution-OK with
attribution. Note: the project website (memoryarena.github.io) uses CC-BY-SA-4.0 for site content;
dataset license is CC-BY-4.0.

**Website:** https://memoryarena.github.io/
**HuggingFace dataset:** https://huggingface.co/datasets/ZexueHe/memoryarena
**arXiv:** https://arxiv.org/abs/2602.16313

> **Note on GitHub code repo:** As of May 2026, the MemoryArena project website links to
> `https://github.com` (placeholder) without a resolved specific repository. Phase 4 loader must
> confirm the canonical code repo URL with the authors (contact: zexueh@stanford.edu) before
> pinning. Marked "manual review required" in `specs/license_audit.md`.

---

### 2.7 ERM — Correctness-Gated Key Updates

**What it is in the Cortex design context:** "ERM" in the CoreTex design refers to
the *principle* of correctness-gated key updates — the idea that memory keys should only be updated
when the new value is demonstrably more correct, not on every new experience. This informs the
validity-interval and revocation-bit design in CortexState words 800–895.

**Research basis:** This principle emerges from the broader agent memory literature, particularly
work on episodic memory gating and empirical studies of experience-following behavior in LLM
agents (see: "How Memory Management Impacts LLM Agents: An Empirical Study of
Experience-Following Behavior," arXiv:2505.16067; A-MEM, arXiv:2502.12110). The shared finding:
indiscriminate memory updates propagate errors; correctness-gating (adding/updating only when
confidence in correctness is high) yields up to 10% performance gains in long-horizon tasks.

**CoreTex benchmark implication:** The protected-regression set (≥50 anchored items per family) operationalizes
correctness-gating: a patch that causes any protected-anchor retrieval to drop is vetoed regardless
of weighted score. This is the on-chain enforcement of correctness-gating — a miner cannot improve
the codec on new items by degrading it on known-correct ones.

**No separate dataset to license:** ERM is a design principle, not a benchmark dataset. No
additional license audit entry required.

---

### 2.8 Experience Compression Spectrum (ECS)

**Full citation:** Xing Zhang, Guanghui Wang, Yanwei Cui, Wei Qiu, Ziyuan Li, Bing Zhu, Peiyang
He. "Experience Compression Spectrum: Unifying Memory, Skills, and Rules in LLM Agents."
arXiv:2604.15877. April 2026.

**What it is:** ECS reveals that every existing agent memory system operates at a fixed,
predetermined compression level. It frames memory (5–20× compression), skills (50–500×), and
rules (1,000×+) as points on a single compression axis. The "missing diagonal" — no system
supports adaptive cross-level compression — is identified as the key gap.

**Why it frames the Cortex design:** CortexState's 1024-word layout explicitly encodes all three
compression levels simultaneously: memory-object index slots (raw episodic), multi-vector retrieval
keys (skill-level), and codebook/operator table (rule-level). The Cortex organism is a living test
of whether a miner can improve across all three levels — not just one — under a fixed budget.

**License:** CC-BY-NC-SA-4.0 (per arXiv paper page). This applies to the arXiv preprint text.
CoreTex benchmark does not use ECS as a data source — only as theoretical framing. No dataset
redistribution issue. Attribution required in research materials.

**arXiv:** https://arxiv.org/abs/2604.15877

---

### 2.9 Proof-of-Improvement Logic

**What it is:** The economic and game-theoretic logic justifying why "improvement-only credit"
creates the right incentive structure.

**Core argument:**
1. **Anti-gaming:** A purely additive score (any patch earns credits) rewards spam. A
   threshold-gated improvement score (`candidateScore > baselineScore + threshold`) filters random
   mutation to ~0% pass rate.
2. **Anti-saturation:** Long-horizon compression (60% weight, MemoryArena-anchored) does not
   saturate because capacity pressure scales with session count. The synthetic stream-and-evict
   generator parameterizes this beyond the dataset's native scope.
3. **Anti-overfit:** Hidden shards (per-epoch `H_e` commit/reveal) prevent a miner from learning
   the specific test items and gaming them. Protected-regression on K=4 random other shards at
   merge time catches epoch-specific overfit.
4. **Anti-centralization:** State-advance credits at tier rate mean broad participation without an
   end-of-epoch multiplier jackpot. Non-overlapping improvements can all advance in the same epoch.

**Pass-rate calibration:** The 5–10% weak / 20–30% strong targets are derived from the benchmark
family difficulty under the 1024-word constraint. A random/no-op patch fails because:
- It cannot improve near-collision discrimination without intentional key design
- It cannot improve temporal validity without understanding the revocation bit semantics
- It cannot survive capacity pressure without real compression logic

A weak heuristic miner can pass 5–10% by finding low-hanging codec improvements (e.g., simple
revocation of obviously stale entries). A strong miner reaches 20–30% by optimizing multi-vector
slot layouts. No miner should hit 40%+ without the codec itself improving — that would indicate
shard-quirk exploitation rather than genuine improvement.

---

## 3. CoreTex Non-Goals

See `specs/non_goals.md` — verified and tightened in this Phase 0 pass.

---

## 4. Benchmark Family Weights (LOCKED — §9 Phase 0)

| Family                        | Weight | Anchor Sources                              |
|-------------------------------|--------|---------------------------------------------|
| Long-horizon compression      | 0.60   | MemoryArena + synthetic stream-and-evict    |
| Near-collision retrieval      | 0.20   | LIMIT + MTEB Retrieval / BEIR subsets       |
| Temporal update / revocation  | 0.20   | LoCoMo + MemoryAgentBench temporal subset   |

**Weight rationale:** Long-horizon carries 60% because it is the only family that does not saturate
as the codec improves — compression pressure scales with session count. Near-collision and temporal
are equally weighted at 20% each; both are necessary anti-gaming properties but are bounded by the
fixed public dataset scope.

**Note on alternative weighting:** The MemoryArena paper's finding (near-saturated LoCoMo
performance → poor multi-session performance) could be read as an argument for an even higher
long-horizon weight (70–80%). However, §9 Phase 0 locks the weights at 60/20/20. This concern is
documented here; do not change the weights without a new Phase 0 pass.

---

## 5. Pass-Rate Targets (LOCKED — §9 Phase 0)

| Miner type         | Target    |
|--------------------|-----------|
| Random / no-op     | ~0%       |
| Weak heuristic     | 5–10%     |
| Strong             | 20–30%    |

**Rationale:** A 40–60% target across the board rewards finding shard quirks, not improving the
substrate. The 0/5–10/20–30 staircase creates a meaningful skill gradient where improvement
requires understanding the codec's semantics, not just randomized search.

**Note on calibration:** These targets are set for the 1024-word CortexState under CoreTex benchmark
configuration. Phase 7 local iteration will verify the bands on internal miner simulations before
Phase 4 lock. If simulation shows strong miners consistently below 15% or above 35%, a difficulty
adjustment (score threshold, patch budget, or family mix) is needed — not a change to the target
bands themselves.

---

## 6. Score Formula (Historical Phase 0 Baseline)

Per-component score ∈ [0,1]; weights frozen before Phase 4 lock:

```
+ exact retrieval                w = 0.30
+ stale-memory rejection         w = 0.15
+ temporal update correctness    w = 0.15
+ compression survival           w = 0.30
+ routing accuracy               w = 0.05
- latency penalty                w = 0.025  (subtracted)
state-size compliance            hard veto
protected-regression set         hard veto on any drop
```

Note: these sub-component weights map onto the family weights as follows:
- Near-collision (20%): exact retrieval (0.30) driven primarily by near-collision tasks
- Temporal (20%): stale rejection (0.15) + temporal update (0.15) = 0.30 of total, modulated by
  family weight
- Long-horizon (60%): compression survival (0.30) + routing accuracy (0.05) as primary drivers

The formula is owned by the Benchmark subagent (Phase 4) and is not changed here.

---

## 7. Failure Modes (Research Perspective)

The following are research-identified failure modes that CoreTex benchmark must guard against. The
Adversarial subagent owns the full adversarial battery; this section provides the research basis.

**7.1 Benchmark overfit via hidden shard enumeration**
Risk: a miner that submits many patches across epochs builds a map of the hidden-shard space.
Mitigation: each epoch's `H_e` is fresh; shard IDs are `keccak(H_e || miner || solveIndex ||
parentStateRoot)`. The space cannot be enumerated because each `H_e` is independent. Protected-
regression on K=4 random shards at merge time catches epoch-specific overfit even if screener
shards are learned.

**7.2 Single-family saturation**
Risk: miners converge on the easiest family (likely near-collision at low dimensions) and stop
improving long-horizon. The codec improves on Family 1 and stagnates on Families 2 and 3.
Mitigation: long-horizon carries 60% weight. A patch that maxes out near-collision retrieval but
does nothing for compression survival gets at most 0.30 composite score — below the screener
threshold.

**7.3 Random-mutation mining**
Risk: random 4-word patches pass occasionally by luck.
Mitigation: the `~0%` pass-rate target for random/no-op is enforced via score threshold. Random
mutations cannot improve exact retrieval (which requires intentional key design) and almost always
cause protected-regression failures. Screener rejects no-op, random mutation, public-test overfit,
and protected-regression patches explicitly.

**7.4 Merge gaming / withholding**
Risk: a miner submits weak screener passes for rewards, or withholds a stronger patch to preserve a
future merge multiplier.
Mitigation: CoreTex pays only state advances and sets the previous multiplier rail to 1.0× / no uplift.
Useful patches are best submitted immediately because another miner can advance the live root first.

**7.5 Core version instability**
Risk: Core upgrades invalidate previously-good patches, creating a moving-target that rewards
miners who track Core version rather than improving the codec.
Mitigation: Core upgrades publish a `state_translation_patch` mapping V_n -> V_{n+1} or an
explicit reset with documented rationale. Ambiguity is a hard non-goal. `coreVersionHash` is
committed on-chain per epoch so all participants know which version scored which patches.

---

## 8. License Summary and Phase 4 Prerequisites

All data sources must pass license verification before the Phase 4 loader fetches them. Summary:

| Source              | License        | Redistribution OK? | Phase 4 Action Required          |
|---------------------|----------------|--------------------|----------------------------------|
| LIMIT               | Apache-2.0 (code) / CC-BY-4.0 (data) | Yes | Attribute; see license_audit.md |
| MTEB                | Apache-2.0     | Yes                | Attribute                        |
| BEIR (code)         | Apache-2.0     | Yes                | Attribute; verify per-subset     |
| BEIR (subsets)      | Per-subset (see license_audit.md) | Varies | Manual per-subset check |
| LoCoMo              | CC-BY-NC-4.0   | **NO (NonCommercial)** | **Blocker — see §8.1**       |
| MemoryAgentBench    | MIT            | Yes                | Attribute                        |
| MemoryArena         | CC-BY-4.0 (dataset) | Yes           | Attribute; confirm code repo URL |
| WARP / XTR          | MIT / Apache-2.0 | Yes (code only)  | No data redistribution           |
| ECS                 | CC-BY-NC-SA 4.0 | No (NonCommercial) | No data redistribution; cite only |

### 8.1 LoCoMo CC-BY-NC-4.0 — Potential Blocker

LoCoMo's CC-BY-NC-4.0 license restricts commercial use of the data. Botcoin Cortex is a
commercial mining protocol; redistribution or embedding of LoCoMo data in a commercial context
likely falls under the NonCommercial restriction.

**Phase 4 options (not a Phase 0 decision):**
1. Contact Snap Research / paper authors to request a commercial use license for the LoCoMo corpus.
2. Replace LoCoMo with a fully permissive alternative for the temporal anchor (e.g., use only
   MemoryAgentBench MIT data for Family 2, or find a CC-BY or Apache-2.0 long-conversational-memory
   dataset).
3. Use LoCoMo only via its public API/evaluation server without redistributing the data, if such
   an interface exists.

This is documented as a **potential Phase 4 blocker** in `specs/license_audit.md`. Phase 0 scope
ends here; the resolution is a Phase 4 decision.

### 8.2 BEIR Per-Subset Licenses

BEIR is a meta-benchmark aggregating many upstream datasets. Each subset has its own license. The
HuggingFace-hosted preprocessed versions carry `cc-by-sa-4.0` as the stated umbrella license.
CoreTex must verify and use only subsets compatible with the Cortex commercial use context. Recommended
subsets for Phase 4 evaluation: MSMARCO (custom Microsoft license, research OK), NQ (Apache-2.0),
HotpotQA (CC-BY-SA-4.0). Manual per-subset check required.
