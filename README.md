# coretex-validator

Public validator for the live CoreTex descriptor-v3 rig on Base.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.3/coretex_validator-0.4.3-py3-none-any.whl
coretex-validator setup
```

`setup` verifies the signed production deployment, caches the miner-kit from the
coordinator kit (`GET /coretex/v5/kit/file/<sha256>`), and reads the confirmed
chain head. Defaults: `--rpc https://mainnet.base.org` and
`--coordinator https://coordinator.agentmoney.net`.

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
| `reproduce --rpc URL` | the eight steps against a live endpoint |
| `reproduce-snapshot --snapshot F --rpc URL --artifacts DIR` | rebuild a published resolver snapshot |
| `replay-latest --rpc URL --artifacts DIR` | discover and replay the **newest** confirmed advance |
| `replay-advance --logs F --artifacts DIR` | replay confirmed advances from a feed file |
| `verify-receipt RECEIPT.json` | replay a signed Benchmark-v2 receipt |
| `topics` | the dispatch table |
| `selftest` | known-answer vectors |

Zero runtime dependencies. See [docs/V5-RIG-VALIDATOR.md](docs/V5-RIG-VALIDATOR.md).

Version 0.4.3 keeps 0.4.2's exact-parent replay — new artifacts carry the incumbent's release root
and module SHA-256, and the validator independently fetches and re-hashes those bytes from the
public CAS before the pinned sandbox runs — and removes what a clean machine still had to be handed
first. `setup` discovers the deployment's publication root and installs the admission law, so
deterministic admission runs instead of backlogging; `replay-latest` replays the newest confirmed
advance without being told which one; `preview-current-parent` scores a candidate against the live
parent. There is no longer a default publication root: a rehearsal root pinned by default is a
validator that reports a verified cache for the wrong law.
