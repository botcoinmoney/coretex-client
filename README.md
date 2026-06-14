# @botcoin/coretex-client

CoreTex is a protocol for proposing, scoring, crediting, publishing, and
replaying changes to a deterministic memory retrieval substrate. This package
is the standalone validator client for that protocol: one setup command derives
everything a client needs, and one sync command audits the chain end-to-end —
epoch/context derived from chain, artifacts downloaded + hash-verified,
registry logs replayed, roots verified, and accepted receipts re-scored
post-reveal with the pinned production scorer.

## External context

- Full CoreTex docs: https://docs.agentmoney.net/coretex/
  Covers the protocol model, substrate layout, corpus generation, retrieval
  evaluation, mining flow, coordinator API, security model, and replay rules.
- BotcoinMiningV4 on Base:
  https://basescan.org/address/0xBc71E2428cc0955b3dF9f38F5cF5DE22a1fC1D9b#code
  The verified receipt, credit, funding, epoch, and claim contract used by the
  client for epoch context and post-reveal eval replay.
- CoreTexRegistry on Base:
  https://basescan.org/address/0x79A9e5a1Ab4D7834CB4f4fB952f1F583032021Bb#code
  The verified registry contract that publishes live roots, epoch context pins,
  transition events, and the replay surface this client validates.

## Install

```bash
npm install @botcoin/coretex-client
```

Host requirements for score replay: Node ≥ 20.10 and `python3`. By default,
`coretex-client-setup` bootstraps a pinned CPU-only scorer venv under the
client state dir, installs the bundle-compatible `torch` + `transformers`
runtime, verifies it with the in-package runner, and records that interpreter
for future syncs. Operators may provide their own interpreter with
`CORETEX_RERANKER_PYTHON` or opt out with `--no-venv-bootstrap`, but the default
path is one-command. The canonical Python reranker runner ships inside this
package at `scripts/reranker_runner.py` and is resolved automatically in both
repo and installed layouts (`CORETEX_RERANKER_SCRIPT` overrides explicitly).

## Quick start (one command each)

```bash
export BASE_RPC_URL=https://mainnet.base.org
export CORETEX_REGISTRY_ADDRESS=0x79A9e5a1Ab4D7834CB4f4fB952f1F583032021Bb
export BOTCOIN_MINING_CONTRACT_ADDRESS=0xBc71E2428cc0955b3dF9f38F5cF5DE22a1fC1D9b
export CORETEX_ARTIFACT_BASE_URL=https://…/coretex/launch/v16

# 1. Setup — fetches the launch manifest from
#    $CORETEX_ARTIFACT_BASE_URL/coretex-launch-v16-artifacts.json, downloads
#    bundle/profile plus the published materialized corpus triplet when present
#    (corpus.json, .events.ndjson, .root-leaves.ndjson), all with SHA-256 +
#    size verification into .coretex-client/. If no triplet is published, it
#    falls back to downloading source corpus/embeddings and materializing
#    locally. It also records the bundle manifest path + previous corpus root +
#    registry deploy block in the client state file, and bootstraps/verifies the
#    pinned CPU scorer venv unless explicitly disabled. Progress and ETA print
#    to stderr.
npx coretex-client-setup --registry-deploy-block <deployBlock>

# 2. Sync — epoch from V4 currentEpoch(), signed rotation/delta verification
#    under a TOFU-pinned key, registry log replay from the launch/blank
#    substrate (or the previous sync's snapshot), local live root == chain
#    liveStateRoot, and — once the epoch secret is revealed — automatic
#    fetch + verification (with score re-scoring) of every accepted advance's
#    post-reveal eval artifact. Sync uses the setup-recorded scorer venv,
#    selects a conservative CPU thread default, and prints progress/ETA to
#    stderr while keeping stdout machine-readable.
npx coretex-client-sync

# 3. Spot-audit one accepted receipt by its on-chain evalReportHash.
npx coretex-client-sync verify-patch --hash 0x<evalReportHash> \
  --epoch-secret 0x<revealedSecret> --parent-state <parent-state.bin>
```

`coretex-client-sync --help` / `coretex-client-setup --help` list every
override flag (epoch, from-block, parent state, corpus, artifact URLs, ...).

## Score honesty is fail-closed

The client rescore path refuses anything but the bundle-pinned qwen3
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
import { ... } from '@botcoin/coretex-client';           // client surface
import { ... } from '@botcoin/coretex-client/client';    // explicit client surface
import { ... } from '@botcoin/coretex-client/full';      // full client internals
```

## More

See `docs/CORETEX_CLIENT_STANDALONE_RUNBOOK.md` in the repository for the
full standalone client runbook (state-dir layout, incremental replay
snapshots, epoch-secret reveal flow, troubleshooting).
