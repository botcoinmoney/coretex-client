# @botcoin/cortex

CoreTex memory-codec validator client, decoder, evaluator, and CLIs. This
package is installable standalone: one setup command derives everything a
validator needs, and one sync command audits the chain end-to-end —
epoch/context derived from chain, artifacts downloaded + hash-verified,
registry logs replayed, roots verified, and accepted receipts re-scored
post-reveal with the pinned production scorer.

## Install

```bash
npm install @botcoin/cortex
```

Host requirements for score replay: Node ≥ 20.10 and a CPU-only `python3`
with `torch` + `transformers` (see the bundle manifest `runtimePin`). The
canonical Python reranker runner ships inside this package at
`scripts/reranker_runner.py` and is resolved automatically in both repo and
installed layouts (`CORETEX_RERANKER_SCRIPT` overrides explicitly).

## Quick start (one command each)

```bash
export BASE_RPC_URL=https://mainnet.base.org
export CORETEX_REGISTRY_ADDRESS=0x…          # CoreTexRegistry
export BOTCOIN_MINING_CONTRACT_ADDRESS=0x…   # BotcoinMiningV4
export CORETEX_ARTIFACT_BASE_URL=https://…/coretex/launch/v16

# 1. Setup — fetches the launch manifest from
#    $CORETEX_ARTIFACT_BASE_URL/coretex-launch-v16-artifacts.json, downloads
#    corpus/embeddings/bundle/profile with SHA-256 + size verification into
#    .coretex-validator/, materializes the production corpus, and records the
#    bundle manifest path + previous corpus root + registry deploy block in
#    the validator state file.
npx coretex-validator-setup --registry-deploy-block <deployBlock>

# 2. Sync — epoch from V4 currentEpoch(), signed rotation/delta verification
#    under a TOFU-pinned key, registry log replay from the launch/blank
#    substrate (or the previous sync's snapshot), local live root == chain
#    liveStateRoot, and — once the epoch secret is revealed — automatic
#    fetch + verification (with score re-scoring) of every accepted advance's
#    post-reveal eval artifact.
npx coretex-validator-sync

# 3. Spot-audit one accepted receipt by its on-chain evalReportHash.
npx coretex-validator-sync verify-patch --hash 0x<evalReportHash> \
  --epoch-secret 0x<revealedSecret> --parent-state <parent-state.bin>
```

`coretex-validator-sync --help` / `coretex-validator-setup --help` list every
override flag (epoch, from-block, parent state, corpus, artifact URLs, …).

## Score honesty is fail-closed

The validator rescore path refuses anything but the bundle-pinned qwen3
production reranker (model id + revision from the bundle manifest), regardless
of environment. A misconfigured env (`CORETEX_RERANKER=deterministic`, a
conflicting `CORETEX_RERANKER_MODEL_ID`/`CORETEX_RERANKER_REVISION`, …) is a
hard error naming the required vars. `--skip-score-replay` is the ONLY way to
skip re-scoring; it warns loudly and exits with code 3 (distinct from success)
because a skipped run attests nothing about scores.

## Exit codes

| code | meaning |
|------|---------|
| 0    | fully verified sync / verify-patch |
| 1    | hard failure (any verification mismatch, missing input, outdated bundle) |
| 3    | `--skip-score-replay` was used — NOT a score attestation |

## Library entry points

```js
import { … } from '@botcoin/cortex';            // validator surface (default)
import { … } from '@botcoin/cortex/coordinator'; // coordinator surface
import { … } from '@botcoin/cortex/full';        // everything
```

## More

See `docs/CORETEX_VALIDATOR_STANDALONE_RUNBOOK.md` in the repository for the
full standalone validator runbook (state-dir layout, incremental replay
snapshots, epoch-secret reveal flow, troubleshooting).
