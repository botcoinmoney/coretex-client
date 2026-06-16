# CoreTex pre-launch — License Audit

> Phase 0 deliverable — Research subagent, 2026-05-05.
> This file is the authoritative record of license SPDX identifiers, redistribution constraints,
> attribution requirements, and citation pins for every data source anchoring CoreTex pre-launch.
> It is the input to the Phase 4 loader's license gate.

**Status key:**
- OK — redistribution permitted with attribution in a commercial context
- REVIEW — NonCommercial or ShareAlike clause; manual review required before Phase 4 data loading
- CODE-ONLY — license covers code; no data redistribution needed

---

## 1. LIMIT

| Field               | Value |
|---------------------|-------|
| Full name           | On the Theoretical Limitations of Embedding-Based Retrieval |
| Authors             | Orion Weller, Michael Boratko, Iftekhar Naim, Jinhyuk Lee |
| Paper DOI / arXiv   | arXiv:2508.21038 (ICLR 2026) |
| Repository          | https://github.com/google-deepmind/limit |
| Code SPDX           | Apache-2.0 |
| Data/materials SPDX | CC-BY-4.0 |
| Pinned commit       | `90c5dd3a7c3c0d68bc6cc7a0c5b0f4ca124dfdcb` (main, 2025-09-15) |
| Redistribution OK?  | **YES** (CC-BY-4.0 permits commercial use with attribution) |
| Attribution req.    | Cite Weller et al. arXiv:2508.21038; include "© Google DeepMind, CC-BY-4.0" in dataset docs |
| Subset used (CoreTex)    | Full LIMIT dataset (50k docs, 1k queries, 2k qrels) or limit-small (46 docs) — Phase 4 decides |
| Notes               | Repository footer states "not an official Google product." Dual license (Apache-2.0 code + CC-BY-4.0 materials) confirmed by README `License and disclaimer` section. |

---

## 2. MTEB (Massive Text Embedding Benchmark)

| Field               | Value |
|---------------------|-------|
| Full name           | MTEB: Massive Text Embedding Benchmark |
| Authors             | Niklas Muennighoff et al. |
| Repository          | https://github.com/embeddings-benchmark/mteb |
| Code SPDX           | Apache-2.0 |
| Data SPDX           | N/A (MTEB is an evaluation framework; individual task datasets have their own licenses) |
| Pinned commit       | `bf25520040bd528d76aaa37c36c682123ef74201` (main, 2026-05-04) |
| Redistribution OK?  | **YES** (Apache-2.0 framework; data varies per task — see BEIR entry below) |
| Attribution req.    | Cite MTEB paper; individual task datasets require their own attributions |
| Subset used (CoreTex)    | MTEB Retrieval tasks backed by BEIR subsets — see §3 below |
| Notes               | Latest release v2.12.38 (2026-05-03). MTEB code is clean Apache-2.0; the license complexity lives in the underlying task data. |

---

## 3. BEIR (Heterogeneous Benchmark for Information Retrieval)

| Field               | Value |
|---------------------|-------|
| Full name           | BEIR: A Heterogeneous Benchmark for Zero-shot Evaluation of IR Models |
| Authors             | Nandan Thakur et al. |
| Repository          | https://github.com/beir-cellar/beir |
| Code SPDX           | Apache-2.0 |
| Data SPDX           | **Per-subset — see table below** |
| Pinned commit       | `ef83d29307061c65d04b035b4f4e7c18bd8374af` (main, 2025-10-16) |
| Redistribution OK?  | **VARIES — per-subset manual review required** |
| Attribution req.    | Cite BEIR paper + original dataset paper for each subset used |
| Subset used (CoreTex)    | Recommended: MSMARCO, NQ, HotpotQA (see per-subset table) |
| Notes               | BEIR README states: "It remains the user's responsibility to determine whether you have permission to use the dataset under the dataset's license." HuggingFace-hosted preprocessed versions carry CC-BY-SA-4.0 umbrella. |

### BEIR Per-Subset License Status (CoreTex Recommended Subsets)

| Subset      | Upstream license         | HF hosted license | Phase 4 action           |
|-------------|--------------------------|-------------------|--------------------------|
| MSMARCO     | Microsoft Research License (research use) | cc-by-sa-4.0 | Verify commercial use terms with MS; flagged for review |
| NQ          | Apache-2.0 (Google)      | cc-by-sa-4.0      | OK with attribution       |
| HotpotQA    | CC-BY-SA-4.0             | cc-by-sa-4.0      | OK; ShareAlike applies to redistributed derivative datasets |
| TREC-COVID  | CORD-19 (free for research) | cc-by-sa-4.0   | Research use OK; commercial review needed |

> **Phase 4 note:** Phase 4 loader must confirm per-subset licensing before including any BEIR
> subset. Use only Apache-2.0 or CC-BY/CC-BY-SA subsets (HotpotQA, NQ) to avoid blockers. MSMARCO
> and TREC-COVID require separate commercial-use review.

---

## 4. LoCoMo — REMOVED FROM CoreTex (Path B chosen, 2026-05-05)

**Decision**: LoCoMo (CC-BY-NC-4.0, NonCommercial) is **incompatible with the
commercial mining context** of Botcoin Cortex and was removed from CoreTex ahead
of any data loading. The temporal family ships with two operative sources:

1. `MemoryAgentBenchLoader` — MIT, EventQA + FactConsolidation tasks
2. `SyntheticTemporalLoader` — Apache-2.0, deterministic stale-vs-current
   templated grammar (LoCoMo Path B fill)

Combined coverage ≈ 90% of the original §5 design intent. The remaining
~10% (long multi-session conversational cadence) was documented as a V1
follow-up in the archived CoreTex pre-launch roadmap. Current CoreTex launch
authority is `docs/README.md`.

**Implication for the §11 thesis**: family weights (60/20/20) unchanged.
Pass-rate targets unchanged. The temporal family's structural property
(stale-vs-current discrimination) is still tested; the source has just
shifted from CC-BY-NC LoCoMo to an MIT + Apache-2.0 stack.

For historical record, the LoCoMo source (Maharana et al., arXiv:2402.17753,
ACL 2024) is **not** redistributed in this repo and the loader stub at
`benchmark/generators/temporal/LoCoMoSourceLoader.ts` has been deleted.

---

## 5. MemoryAgentBench

| Field               | Value |
|---------------------|-------|
| Full name           | Evaluating Memory in LLM Agents via Incremental Multi-Turn Interactions |
| Authors             | Yuanzhe Hu, Yu Wang, Julian McAuley |
| Paper DOI / arXiv   | arXiv:2507.05257 (ICLR 2026) |
| Repository          | https://github.com/HUST-AI-HYZ/MemoryAgentBench |
| HuggingFace dataset | https://huggingface.co/datasets/ai-hyz/MemoryAgentBench |
| Code / Data SPDX    | **MIT** (confirmed via HF dataset card: `license: mit`) |
| Pinned commit       | `569241d877899d5c36d7d3b789de6c2489ea6cba` (main, 2026-01-27) |
| Redistribution OK?  | **YES** (MIT permits commercial use with attribution) |
| Attribution req.    | Cite Hu et al. arXiv:2507.05257; include MIT license notice |
| Subset used (CoreTex)    | Temporal subset (EventQA, FactConsolidation tasks) for stale-vs-current evaluation |
| Notes               | Repository README does not mention a LICENSE file; MIT license confirmed via HuggingFace dataset card only. Phase 4 loader should verify a LICENSE file exists in the repo; if absent, treat as "manual review required." |

---

## 6. MemoryArena

| Field               | Value |
|---------------------|-------|
| Full name           | MemoryArena: Benchmarking Agent Memory in Interdependent Multi-Session Agentic Tasks |
| Authors             | Zexue He, Yu Wang, Churan Zhi, Yuanzhe Hu, Tzu-Ping Chen, Lang Yin, Ze Chen, Tong Arthur Wu, Siru Ouyang, Zihan Wang, Jiaxin Pei, Julian McAuley, Yejin Choi, Alex Pentland |
| Paper DOI / arXiv   | arXiv:2602.16313 (February 2026) |
| Website             | https://memoryarena.github.io/ |
| HuggingFace dataset | https://huggingface.co/datasets/ZexueHe/memoryarena |
| Code SPDX           | **UNRESOLVED — code repo URL not confirmed** (see notes) |
| Data SPDX           | **CC-BY-4.0** (HuggingFace dataset card confirmed) |
| Pinned commit       | N/A — no confirmed code repo hash; pinned via HF dataset revision |
| Redistribution OK?  | **YES for dataset** (CC-BY-4.0 permits commercial use with attribution) |
| Attribution req.    | Cite He et al. arXiv:2602.16313; include "CC-BY-4.0" notice with dataset use |
| Subset used (CoreTex)    | Long-horizon compression family: bundled_shopping, progressive_search, group_travel_planner, formal_reasoning_math, formal_reasoning_phys |
| **STATUS**          | **Dataset OK. Code repo: MANUAL REVIEW REQUIRED** |

### MemoryArena Code Repository

As of 2026-05-05, the MemoryArena project website (memoryarena.github.io) links to
`https://github.com` (the GitHub homepage, not a specific repository). The corresponding author
is Zexue He (zexueh@stanford.edu). 

**Phase 4 action required:**
- Confirm the canonical code repository URL (email or GitHub search for `ZexueHe` repositories)
- Pin the commit hash of the code repo for the Phase 4 loader
- Verify the code license (dataset is CC-BY-4.0; code license may differ)
- If no code repo is found, the Phase 4 loader uses only the HuggingFace dataset

---

## 7. WARP (XTR-WARP)

| Field               | Value |
|---------------------|-------|
| Full name           | WARP: An Efficient Engine for Multi-Vector Retrieval |
| Authors             | Jan Luca Scheerer, Matei Zaharia, Christopher Potts, Gustavo Alonso, Omar Khattab |
| Paper DOI / arXiv   | arXiv:2501.17788 (SIGIR 2025) |
| Repository          | https://github.com/jlscheerer/xtr-warp |
| Code SPDX           | **MIT** |
| Data SPDX           | N/A (WARP is a retrieval engine; no standalone dataset) |
| Pinned commit       | `cca97613e6f969ac89f259946b976f8c5a6f1399` (main, 2025-05-03) |
| Redistribution OK?  | **YES — CODE-ONLY** (MIT code license; no data redistribution needed) |
| Attribution req.    | Cite Scheerer et al. arXiv:2501.17788 in architectural notes |
| Subset used (CoreTex)    | None — WARP is architectural motivation only, not a data source |
| Notes               | WARP is research context for the multi-vector slot design in CortexState. CoreTex benchmark does not load WARP task data. Upstream XTR (google-deepmind/xtr): Apache-2.0 code / CC-BY-4.0 materials (pinned `52d5b5ec796f51a8eb76aa727873545a58ce8b80`, 2024-06-20). |

---

## 8. Experience Compression Spectrum (ECS)

| Field               | Value |
|---------------------|-------|
| Full name           | Experience Compression Spectrum: Unifying Memory, Skills, and Rules in LLM Agents |
| Authors             | Xing Zhang, Guanghui Wang, Yanwei Cui, Wei Qiu, Ziyuan Li, Bing Zhu, Peiyang He |
| Paper DOI / arXiv   | arXiv:2604.15877 (April 2026) |
| Repository          | None (preprint only as of 2026-05-05) |
| Code / Data SPDX    | CC-BY-NC-SA-4.0 (arXiv paper license) |
| Redistribution OK?  | N/A — no data redistribution needed |
| Attribution req.    | Cite Zhang et al. arXiv:2604.15877 in research brief and any public-facing docs that reference the ECS framing |
| Subset used (CoreTex)    | None — ECS is theoretical framing only, not a data source |
| Notes               | CC-BY-NC-SA applies to the preprint text; no dataset or code is distributed. No Phase 4 action required. |

---

## Summary Table

| Source              | SPDX (code)     | SPDX (data)       | Redistribution | Phase 4 Status          |
|---------------------|-----------------|-------------------|----------------|-------------------------|
| LIMIT               | Apache-2.0      | CC-BY-4.0         | OK             | Attribute; pin hash     |
| MTEB                | Apache-2.0      | N/A (framework)   | OK             | Per-task data varies    |
| BEIR (code)         | Apache-2.0      | Per-subset        | Varies         | **Per-subset review**   |
| ~~LoCoMo~~          | (removed CoreTex)    | (removed CoreTex)      | n/a            | RESOLVED via Path B (§4) |
| SyntheticTemporal   | Apache-2.0      | Apache-2.0        | YES            | OK (in-tree generator)   |
| MemoryAgentBench    | MIT (HF card)   | MIT               | OK             | Verify repo LICENSE     |
| MemoryArena         | Unresolved      | CC-BY-4.0         | OK (data)      | Confirm code repo URL   |
| WARP / XTR-WARP     | MIT             | N/A               | OK (code only) | No data redistribution  |
| ECS                 | CC-BY-NC-SA-4.0 | N/A               | N/A            | No data redistribution  |

---

## Phase 4 Pre-Flight Checklist

Before Phase 4 data loader development begins, the following must be resolved:

- [x] **LoCoMo NC clause** — RESOLVED 2026-05-05 via Path B (removed; Synthetic + MemoryAgentBench)
      alternative dataset (BLOCKER)
- [ ] **BEIR per-subset verification** — confirm only Apache-2.0 / CC-BY subsets are loaded
      (NQ and HotpotQA recommended); flag MSMARCO and TREC-COVID for commercial review
- [ ] **MemoryArena code repo** — confirm canonical GitHub URL and pin commit hash
- [ ] **MemoryAgentBench repo LICENSE file** — verify a LICENSE file exists in the GitHub repo
      (currently only confirmed via HuggingFace dataset card)

Items confirmed OK (no further action for Phase 4):
- [x] LIMIT data: CC-BY-4.0, redistribution OK
- [x] MTEB framework: Apache-2.0, redistribution OK
- [x] BEIR framework code: Apache-2.0, redistribution OK
- [x] MemoryAgentBench data: MIT (HF), redistribution OK
- [x] MemoryArena dataset: CC-BY-4.0 (HF), redistribution OK
- [x] WARP / XTR: MIT / Apache-2.0, code only, no data redistribution needed
