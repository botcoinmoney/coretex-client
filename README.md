# @botcoinmoney/coretex-client

This is the standalone validator for the rig-NFT-keyed, descriptor-v3 CoreTex production lane. It
authenticates the canonical deployment, reads chain state at a confirmed block, replays per-rig
receipt continuity, reconstructs transition descriptors and artifacts, reruns deterministic
admission, and exports reproduced state for portable activation.

## Production authority

The validator defaults to the operator-signed canonical Base production release at an immutable
git commit. It accepts production classification only after verifying that release's EIP-191
signature and exact production signer, mining, verifier, registry, genesis, cutover epoch,
descriptor-v3 receipt typehash, and EIP-712 domain. It then independently reads runtime bytecode,
immutable wiring, and the coordinator signer from Base.

The recorded genesis root is only the registry constructor's immutable deployment fact. It is not
the operational bootstrap authority. For every served epoch, the validator reads the verifier's
confirmed `CoreTexEpochContextSet.parentStateRoot` and reconstructs transition 0 from that root.
This allows the epoch-context production bootstrap to differ from the constructor diagnostic
without inventing a migration transition. Prospective activation requires that bootstrap and every
later resulting state to use the one schema-4 release shape.

Canonical Base contracts:

- mining: `0xB61BC7487424172CB9fa9dD381a9eC06C7067dCd`
- verifier: `0x82384E4DA334a4e3E1d8d2623359dC8c4d931Ed4`
- registry: `0xa4d8a7Bb3Ba2D023af29Bf77601A61673ED89ad3`

The production command follows only the deployed descriptor-v3 rig lane. It does not select a V4,
staking, word-patch, or descriptor-v2 replay path.

## Production quick start

```bash
export BASE_RPC_URL=https://mainnet.base.org
cd python
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps .

# Uses the immutable signed canonical production release by default.
coretex-validator verify-release --rpc "$BASE_RPC_URL"

# After a production transition and snapshot/artifacts are published:
coretex-validator reproduce --rpc "$BASE_RPC_URL" \
  --snapshot snapshot.json \
  --runtime-record runtime-integration.production.json \
  --artifact-dir artifacts \
  --export activation.json \
  --require-complete
```

Pass `--release` only to audit an explicit historical or alternate release. A file that merely
claims production is refused; production is not selectable with a CLI flag.

## Commands

| command | what it does |
|---------|--------------|
| `sync-law --mirror URL` | fetches the six published admission trees by publication root, re-derives every address from the bytes that arrived, materializes a verified law cache under `~/.local/share/coretex/law/<root>/`, and pins it for every later command |
| `reproduce --rpc URL` | the eight steps against a live endpoint; picks up the law cache automatically |
| `verify-release --release R --rpc URL` | steps 1–2: authenticate the release and read the deployment |
| `reproduce-snapshot --snapshot F --rpc URL --artifacts DIR` | rebuild a published resolver snapshot from chain truth, byte for byte |
| `replay-advance --logs F --artifacts DIR` | replay confirmed frontier advances; `PASS`/`FAIL`/`BACKLOG` per advance, verbatim |
| `verify-receipt RECEIPT.json` | replay a signed Benchmark-v2 receipt through the law cache, in a networkless child |
| `topics` | the dispatch table for both lanes |
| `selftest` | known-answer vectors for keccak256, ecrecover and canonical JSON |

### The law cache, in one command

Deterministic admission (step 5) needs six code trees. They are published as content-addressed
objects, addressed by the **same** tree-hash rule the signed receipt's `code_roots` binds, so
`sync-law` can fetch them from any mirror and check them against the chain-bound identity rather
than against the courier:

```bash
coretex-validator sync-law --mirror https://<coordinator-or-mirror>
coretex-validator reproduce --rpc "$BASE_RPC_URL"        # step 5 now runs the real admission
```

Every object is rehashed from the bytes that arrived; a mismatch, a truncation, an oversize
response, a tar carrying anything the hash rule does not cover, or a missing tree refuses outright
and installs nothing. `--print-export` emits `export VAR=...` lines instead, for a shell that
wants the three pins directly.

## Descriptor-v3 validator

```bash
cd python && ./reproduce.sh                                    # clean-machine proof, offline
cd python && ./reproduce.sh --rpc "$RPC" --release release.json --export export.json
```

`reproduce.sh` builds a wheel, installs it into a throwaway venv with
`pip install --no-deps`, and runs everything from **outside** the source tree.
The validator declares zero runtime dependencies: keccak256, secp256k1 recovery,
ABI encoding, canonical JSON and JSON-RPC are all implemented on the standard
library, because a validator whose verdict depends on a downloaded wheel has a
supply-chain root it did not choose.

Descriptor-v3 uses a distinct advance topic from V4/v2, while routing remains deployment-address
scoped so historical logs cannot enter the production stream. `coretex-validator topics` prints
the current and historical tables. Additional findings — including which parts of deterministic
admission a public machine structurally *cannot* run — are in
[docs/V5-RIG-VALIDATOR.md](docs/V5-RIG-VALIDATOR.md).

Production snapshots are classified `CANONICAL_PRODUCTION` only after the signed canonical release
is authenticated. Before the first accepted production transition exists, deployment and wiring
verification can pass, but transition replay and activation export correctly remain unavailable.

## Admission is fail-closed

Missing transition artifacts, an unavailable deterministic evaluator tree, or an unpublished
snapshot are reported as explicit unverified/backlog results. They never become a pass. Use
`--require-complete` when an incomplete verification must fail the command.

For prospective schema-v4 state, “available” means the complete graph: the composition manifest,
all three profile release manifests, and each release's direct ``module.py`` bytes. Every bundle is
exactly ``manifest.json`` + ``module.py``; ``base_modules`` is explicitly empty, miner bytes equal
module bytes, wrapper format is 3, and the admission report, analyzer ruleset, and inferred
``capabilities_used`` are bound. A missing object is BACKLOG (publication may be repaired); a
malformed, substituted, schema-3, wrapper-2, split miner/adapter, partially scoped, or wrongly
delegated graph is FAIL. Historical schema-3 inspection cannot authorize prospective activation.
Candidate-reported compute and wall-clock figures remain diagnostics and are not admission axes.

## Exit codes

| code | meaning |
|------|---------|
| 0    | no completed check contradicted the release; inspect `unverified` |
| 1    | a verification check ran and failed, or `--require-complete` found a gap |
| 2    | bad arguments, malformed release, or transport/startup failure |

## More

See [docs/V5-RIG-VALIDATOR.md](docs/V5-RIG-VALIDATOR.md) for descriptor-v3 wire details.
