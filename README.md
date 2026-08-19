# coretex-validator

Public validator for the live CoreTex descriptor-v3 rig on Base.

This repository's installable product is the Python package **`coretex-validator`**.
The older npm package `@botcoinmoney/coretex-client` (`coretex-client-setup`,
`coretex-client-sync`, GitHub release `v0.7.1`) is the **retired V4 client**. Do not
`npm install` it, and do not point it at `coretex/launch/v16`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.1/coretex_validator-0.4.1-py3-none-any.whl
```

Zero runtime dependencies. Alternative, from this repo:

```bash
pip install --no-deps "git+https://github.com/botcoinmoney/coretex-client.git@v0.4.1#subdirectory=python"
```

## Setup

```bash
coretex-validator setup
```

Defaults: `--rpc https://mainnet.base.org` and
`--coordinator https://coordinator.agentmoney.net`. That command:

1. Authenticates the signed canonical Base production release and reads bytecode/wiring.
2. Downloads the miner-kit tar (and frozen-runtime-packet identity) from the coordinator
   kit at `/coretex/v5/kit/file/<sha256>` — the public content-addressed store, S3-backed.
   Already-hashed files are skipped. This is **not** the retired V4 launch bucket.
3. Reads the confirmed chain head: current epoch, live state root, `transitionCount`.

Packages land in `~/.local/share/coretex/packages`. Setup does **not** silently fetch
the baked-in `sync-law` default root (that is a 2026-08-04 rehearsal, not this chain
head). After setup:

```bash
coretex-validator verify-release --rpc https://mainnet.base.org
```

## Production contracts (Base)

- mining: `0xB61BC7487424172CB9fa9dD381a9eC06C7067dCd`
- verifier: `0x82384E4DA334a4e3E1d8d2623359dC8c4d931Ed4`
- registry: `0xa4d8a7Bb3Ba2D023af29Bf77601A61673ED89ad3`

The default release is `builtin:base-mainnet`. Production classification is accepted
only after the operator-signed canonical release is authenticated. Pass `--release`
only to audit an explicit historical artifact.

## Other commands

| command | what it does |
|---------|--------------|
| `setup` | verify deployment, cache kit packages, read chain head |
| `verify-release --rpc URL` | steps 1–2 only |
| `sync-law --mirror URL --root ROOT` | fetch + verify admission trees (name a **live** root) |
| `reproduce --rpc URL` | the eight steps against a live endpoint |
| `reproduce-snapshot --snapshot F --rpc URL --artifacts DIR` | rebuild a published resolver snapshot |
| `replay-advance --logs F --artifacts DIR` | replay confirmed frontier advances |
| `verify-receipt RECEIPT.json` | replay a signed Benchmark-v2 receipt |
| `topics` | the dispatch table |
| `selftest` | known-answer vectors |

`reproduce` of a specific transition still needs a published snapshot and artifacts.
The live coordinator kit currently serves validator wheel `adb52e32…` (0.4.0 before
inherited-pin adoption). This 0.4.1 line includes that adoption; miners who only
`pip install` the kit wheel still cannot replay inherited first-edge pin re-anchors.

## Exit codes

| code | meaning |
|------|---------|
| 0    | no completed check contradicted the release; inspect `unverified` |
| 1    | a verification check ran and failed, or `--require-complete` found a gap |
| 2    | bad arguments, malformed release, or transport/startup failure |

See [docs/V5-RIG-VALIDATOR.md](docs/V5-RIG-VALIDATOR.md) for descriptor-v3 wire details.
The V4 npm runbook is archived at
[docs/CORETEX_CLIENT_STANDALONE_RUNBOOK.md](docs/CORETEX_CLIENT_STANDALONE_RUNBOOK.md).
