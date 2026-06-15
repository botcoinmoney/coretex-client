# CoreTex Standalone Client Runbook

How to run a CoreTex client from a bare host with the `@botcoinmoney/coretex-client` npm
package, RPC access to Base, and the launch artifact base URL. The client
independently re-derives every on-chain claim: epoch context, corpus
continuity, registry state roots, and (post-reveal) the scores behind every
accepted state advance.

## 0. Prerequisites

- Node ≥ 20.10.
- `python3` with venv support. By default setup creates
  `.coretex-client/scorer-venv`, installs the pinned CPU-only scorer runtime
  (`torch==2.6.0+cpu`, `transformers==4.55.0`, plus pinned runtime peers),
  verifies it with the packaged reranker runner, and records it for sync. Use
  `CORETEX_RERANKER_PYTHON` for an operator-managed interpreter or
  `--no-venv-bootstrap` / `CORETEX_CLIENT_SKIP_VENV=1` to opt out.
- Disk: setup prefers the published materialized triplet when the launch
  manifest exposes one, so the normal footprint is the bundle/profile plus
  `corpus.json`, `corpus.json.events.ndjson`, and
  `corpus.json.root-leaves.ndjson`. If a manifest has no published triplet,
  setup falls back to the source corpus + embeddings path (~700 MB before the
  materialized cache). The scorer venv/model cache can add several more GB
  depending on the host cache layout.
- Env (the complete one-command set):

```bash
export BASE_RPC_URL=https://mainnet.base.org
export CORETEX_REGISTRY_ADDRESS=0x…          # CoreTexRegistry
export BOTCOIN_MINING_CONTRACT_ADDRESS=0x…   # BotcoinMiningV4
export CORETEX_ARTIFACT_BASE_URL=https://…/coretex/launch/v16
# optional but recommended (lets sync bootstrap full-history replay):
export CORETEX_REGISTRY_DEPLOY_BLOCK=<registry deploy block>
```

Contract addresses: `docs/contract-addresses-mainnet.md`.

```bash
npm install @botcoinmoney/coretex-client
```

## 1. Setup (`coretex-client-setup`)

```bash
npx coretex-client-setup --registry-deploy-block "$CORETEX_REGISTRY_DEPLOY_BLOCK"
```

What it does, in order:

1. Syntax-checks any chain-config env already set (`BASE_RPC_URL`,
   `CORETEX_REGISTRY_ADDRESS`, `BOTCOIN_MINING_CONTRACT_ADDRESS`) BEFORE any
   download/materialization. Setup itself stays offline artifact hydration —
   these envs are optional here — but a present-and-malformed value fails
   fast instead of surfacing on the first sync.
2. Fetches the launch artifact manifest from
   `$CORETEX_ARTIFACT_BASE_URL/coretex-launch-v16-artifacts.json`
   (`--manifest <path-or-url>` overrides; schema
   `coretex.launch-artifacts.v1`). When the manifest publishes a `chain`
   block (`chainId`, `registryAddress`, `miningContractAddress`,
   `registryDeployBlock`, `confirmationDepth`), setup cross-checks the env
   addresses against it and records it into the client state file;
   `--registry-deploy-block` falls back to the manifest value. With
   `--verify-chain-config` (opt-in; requires `BASE_RPC_URL` + addresses from
   env or manifest), setup also probes the RPC: chainId match, deployed code
   at both addresses, and `registry.botcoinMiningV4()` == the V4 address.
3. Downloads the bundle manifest and evaluator profile into the state dir with
   SHA-256 + byte-size verification. When the launch manifest publishes a
   complete `materialized` block, setup also downloads the prebuilt triplet
   (`manifest.json`, `corpus.json`, `corpus.json.events.ndjson`,
   `corpus.json.root-leaves.ndjson`) and skips the source corpus/embeddings
   materialization path. When no triplet is published, setup falls back to
   downloading corpus + embeddings and materializing locally. Already-verified
   files are never re-downloaded; `--verify-only` / `--no-download` make
   verification-only runs explicit.
4. Cross-checks `bundle.bundleHash` and `bundle.corpus.root` against the
   launch manifest.
5. Verifies the materialized corpus manifest against the launch manifest:
   `bundleHash`, `corpusRoot`, source input SHA-256 pins, bundle/profile
   SHA-256 pins, event count, and root-leaf cache root/count must all match.
   On the fallback path, this verification runs after the in-package canonical
   materializer (`scripts/materialize-production-corpus.mjs`) produces the
   same materialized layout.
6. Bootstraps or verifies the CPU scorer venv and records the resolved
   interpreter path.
7. Writes the client state file so sync needs no manual flags.

Setup prints download/materialization/scorer-bootstrap progress and ETA to
stderr when running in a TTY. Use `--no-progress` for quiet automation.

### State dir layout (default `.coretex-client`, env `CORETEX_CLIENT_STATE_DIR`)

```
.coretex-client/
  client-sync-state.json    # setup + sync state (see below)
  epoch-signing-key.pin.json   # TOFU pin, written after the first verified sync
  artifacts/                   # verified launch payloads (bundle/profile; source corpus+embeddings only on fallback)
  materialized/<bundleTag>/    # materialized production corpus cache
  scorer-venv/                 # managed CPU scorer runtime unless bootstrap is disabled
  substrate-state.bin          # replayed substrate snapshot (written by sync)
```

`client-sync-state.json` fields written by setup: `bundleHash`,
`corpusRoot` (previous corpus root for delta continuity),
`registryDeployBlock`, and `setup.{bundleManifestPath, profilePath,
corpusPath, materializedRoot, artifactBaseUrl}`. Sync merges its own fields
(`epoch`, `replay.{stateRoot, cursorBlock, epochTransitions}`, …) without
clobbering setup's.

## 2. Sync (`coretex-client-sync`)

```bash
npx coretex-client-sync
```

Pipeline (every step fail-closed):

1. **Epoch**: V4 `currentEpoch()` on chain. `--epoch` / `EPOCH_ID` /
   coordinator status override.
2. **Chain pins**: registry pins (parent root, live root, transition count,
   coreVersionHash, corpusRoot, frontier root, baseline hash, hidden-seed
   commit) cross-checked against V4 (`epochCommit`, `coreTexRegistry()`),
   plus the epoch-secret reveal status.
3. **Version self-check**: local bundleHash MUST equal the on-chain
   coreVersionHash (`--allow-version-mismatch` = read-only escape).
4. **Fail-closed scorer gate**: unless `--skip-score-replay`, sync resolves the
   setup-recorded scorer venv or the operator-provided
   `CORETEX_RERANKER_PYTHON`, then verifies the bundle-pinned qwen3 reranker
   before any expensive work.
5. **Signed epoch rotation + corpus delta**: signature verification under the
   TOFU-pinned epoch signing key; corpus-delta continuity against the LOCAL
   previous corpus root. Key resolution: `--public-key` → coordinator status
   `epochSigningPublicKeyUrl` → the canonical artifact-base default
   `<artifact-base>/epoch-rotations/epoch-signing-public.pem` (so the bare
   four-env-var sync works with no coordinator URL; TOFU pinning protects
   against substitution at any source).
6. **Registry log replay (default, no flags)**:
   - from-block: `--from-block` → `CORETEX_REPLAY_FROM_BLOCK` → previous
     sync's cursor + 1 → state-file `registryDeployBlock` →
     `CORETEX_REGISTRY_DEPLOY_BLOCK`;
   - parent substrate: `--parent-state` → previous sync's
     `substrate-state.bin` snapshot (root-verified) → the launch/blank
     substrate (all-zero packed state) when the chain parent root equals the
     launch parent root or when replaying from the deploy block;
   - replays every `CoreTexStateAdvanced` (patch-hash binding, parent
     continuity, reproduced roots), then
     verifies local live root == chain `liveStateRoot(epoch)` and cumulative
     per-epoch transitions == chain `transitionCount(epoch)`;
   - persists the replayed substrate + cursor block, so the next sync is
     incremental.
7. **Post-reveal eval verification (automatic)**: when the epoch secret is
   revealed on chain, every accepted advance in the synced window has its
   eval artifact fetched from
   `$CORETEX_ARTIFACT_BASE_URL/eval-reports/<evalReportHash>.json` and
   verified through `verifyPostRevealEvalReportArtifact`: artifact-hash
   binding, seed re-derivation from the revealed secret + blockhash, and
   FULL score re-scoring of both hidden packs against the advance's replayed
   parent substrate (within the pinned replay tolerance). Before reveal the
   sync prints `awaiting_epoch_secret_reveal` and exits 0.

Expect score re-scoring to be slow on CPU (it runs the pinned production
reranker); that cost is the point — it is the same work the coordinator
claims to have done.

Sync prints chain-replay and post-reveal scoring progress/ETA to stderr and a
clear final PASS/FAIL summary. `--no-progress` suppresses progress lines but
does not weaken verification.

## 3. Spot audits (`verify-patch`)

```bash
npx coretex-client-sync verify-patch \
  --hash 0x<evalReportHash> \
  --epoch-secret 0x<revealedSecret> \
  --parent-state <parent-state.bin>
```

Bundle manifest and corpus default from the setup state file. The parent
state must merkle to the artifact's `context.parentStateRoot` (sync's
`substrate-state.bin` is the live tip — for older advances, export the
parent from a sync run or replay up to the advance).

## 4. Fail-closed scorer

The rescore path constructs the reranker EXCLUSIVELY from the bundle
manifest pins (`model.reranker.modelId@revision`, currently
Qwen/Qwen3-Reranker-0.6B). It never falls back to the deterministic stub or
minilm, regardless of `CORETEX_RERANKER`:

- `CORETEX_RERANKER` unset or `qwen3` → OK (qwen3 forced);
- anything else → hard error naming the required vars;
- `CORETEX_RERANKER_MODEL_ID` / `CORETEX_RERANKER_REVISION` conflicting with
  the bundle pins → hard error;
- `--skip-score-replay` is the ONLY skip: loud warning + exit code **3**.
  Exit 3 means *the sync otherwise succeeded, but score replay was
  intentionally skipped* — it is a PASS-with-caveat, never a masked failure.
  Every mandatory config/chain read and check still runs and still exits **1**
  on failure (full success without the flag is 0). A skipped run does not
  attest scores.

Runtime hygiene is handled automatically: setup records the managed scorer venv,
and sync auto-selects a conservative `RERANKER_NUM_THREADS` based on estimated
physical cores capped at 16. These affect runtime speed only, never scoring.
Explicit operator overrides still win.

Useful scorer env: `CORETEX_RERANKER_PYTHON` (operator-managed interpreter),
`CORTEX_LOCAL_MODEL_CACHE` (HF cache dir), `CORTEX_LOCAL_MODEL_LOCAL_ONLY=1`
(air-gapped), `RERANKER_NUM_THREADS`, `CORETEX_RERANKER_BATCH_SIZE`,
`CORETEX_RERANKER_MODE=streaming|spawn` (default streaming),
`CORETEX_RERANKER_SCRIPT` (explicit runner path override; the default resolves
to the in-package `scripts/reranker_runner.py`).

## 5. Troubleshooting

| symptom | meaning / fix |
|---|---|
| `coretex client outdated` | on-chain coreVersionHash moved — re-run setup against the current launch artifacts. |
| `TOFU key pin mismatch` | the served epoch signing key changed — verify the rotation out-of-band before replacing `epoch-signing-key.pin.json`. |
| `corpus-delta continuity` error | your local previous corpus root diverged — audit before touching state; do not delete the state file casually. |
| `cannot bootstrap replay parent substrate` | no snapshot and the chain parent isn't the launch root — replay full history from the deploy block (`--registry-deploy-block` at setup) or pass `--parent-state`. |
| `registry replay root … != chain liveStateRoot` | either a head-of-chain advance inside the confirmation window (re-run) or a real divergence (escalate — this is the alarm the client exists for). |
| `client score replay is fail-closed: …` | env would not reproduce the pinned scorer — the error names the exact vars. |

## 6. Repo-checkout equivalents

Inside the canonical repo, run the compiled `coretex-client-setup` in
repo-hydration mode (payloads land at their committed repo paths and the
bundle source-tree pins are verified), then run `coretex-client-sync`.
