# coretex-validator

Public validator for the live CoreTex descriptor-v3 rig on Base.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.3/coretex_validator-0.4.3-py3-none-any.whl
coretex-validator setup
```

`setup` verifies the signed production deployment, caches **and extracts** the
miner-kit from the coordinator kit (`GET /coretex/v5/kit/file/<sha256>`), reads
the confirmed chain head, and installs the published admission law. Defaults:
`--rpc https://mainnet.base.org` and
`--coordinator https://coordinator.agentmoney.net`.

**Start with `reproduce`.** It is the one command that verifies a live advance
end to end — release authentication, contract bytecode and wiring, per-rig
receipt continuity, the transition join, deterministic admission against the
installed law, the historical law at that transition, and the resolver snapshot:

```bash
coretex-validator reproduce --rpc https://mainnet.base.org
```

Everything else is a narrower slice of the same machinery, useful when you
already know which part you want.

## Production contracts (Base)

- mining: `0xB61BC7487424172CB9fa9dD381a9eC06C7067dCd`
- verifier: `0x82384E4DA334a4e3E1d8d2623359dC8c4d931Ed4`
- registry: `0xa4d8a7Bb3Ba2D023af29Bf77601A61673ED89ad3`

The default release is `builtin:base-mainnet`. Pass `--release` only to audit an
explicit historical artifact.

## Commands

| command | what it does |
|---------|--------------|
| `setup` | verify deployment, cache kit packages, read chain head, **install the admission law** |
| `verify-release --rpc URL` | authenticate the release and read bytecode/wiring |
| `sync-law --mirror URL --root ROOT` | fetch + verify a **named** publication (no default root) |
| **`reproduce --rpc URL`** | **the eight steps against a live endpoint — the full end-to-end verification** |
| `reproduce-snapshot --snapshot F --rpc URL --artifacts DIR` | rebuild a published resolver snapshot |
| `replay-latest --rpc URL --artifacts DIR` | discover and replay the **newest** confirmed advance |
| `replay-advance --logs F --artifacts DIR` | replay confirmed advances from a feed file |
| `preview-current-parent MODULE.py …` | score a candidate against the **live confirmed parent** |
| `verify-receipt RECEIPT.json --artifact A.json` | replay a signed Benchmark-v2 receipt |
| `topics` | the dispatch table |
| `selftest` | known-answer vectors |

Objects are fetched with the hash rule they were committed under (`get_for_rule`), and the root is
**recomputed here** from the bytes that arrived. A surface reporting `transportVerified` /
`canonicalVerification: "client_required"` is stating a transport-level fact only — the server can
check that `sha256(bytes)` equals the root, this client additionally requires the bytes to *be* the
canonical serialisation the root names. That matters for the float-bearing
`sha256-benchmark-canonical-json` rule, where raw-sha agreement is not canonical verification.

Zero runtime dependencies. See [docs/V5-RIG-VALIDATOR.md](docs/V5-RIG-VALIDATOR.md).

Version 0.4.3 verifies exact-parent replay: artifacts carry the incumbent's release root and module
SHA-256, and the validator independently fetches and re-hashes those bytes from the public CAS
before the pinned sandbox runs. It also removes what a clean machine still had to be handed first.
`setup` discovers the deployment's publication root and installs the admission law, so
deterministic admission runs instead of backlogging; `replay-latest` replays the newest confirmed
advance without being told which one; `preview-current-parent` scores a candidate against the live
parent; `verify-receipt` resolves the exact parent's execution itself rather than demanding it.
There is no longer a default publication root: a rehearsal root pinned by default is a validator
that reports a verified cache for the wrong law.

**Two publications, not one, and `setup` fetches both.** The law publication seals seven code
roots — five `benchmark-v2` subtrees, `coretex-memory`, and the candidate-isolation posture FILE.
`benchmark-v2/kit` and `benchmark-v2/integration` are *not* sealed roots and can never appear in
it. Both required support trees ship in the explicit hash-pinned `current_miner_kit` tar.

**One live decoder.** `replay-latest` / `replay-advance` / `reproduce` all decode the deployed
descriptor-v3 events (`rig_events`). The `CoreTexMemory*` tables in `dispatch`/`sync` are the
retired lane's and no live command consults them.

**Install closure.** `setup` activates only a production-release-bound current kit with exactly
one miner-kit tar and an explicit law-publication root. Missing components and a publication
without the posture file are refused rather than installed partially.

**One canonical validator release.** 0.4.3 is the validator this repository builds and the only
current production release; there is no supported prior/current version split. The deployment byte
authority is `GET /coretex/v5/status` → `productionRelease.validatorWheel`: that tuple names the
exact wheel, version and sha256 the coordinator will hand you, parsed from the bytes it serves. A
deployment is on the canonical release only when that tuple names the canonical 0.4.3 artifact;
documentation, tags and a local cache are not substitutes for those served bytes.
