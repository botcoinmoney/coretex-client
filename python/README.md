# coretex-validator

Dependency-free public validator for BOTCOIN's canonical Base descriptor-v3 CoreTex rig.

```bash
pip install https://github.com/botcoinmoney/coretex-client/releases/download/v0.4.1/coretex_validator-0.4.1-py3-none-any.whl
coretex-validator setup
```

`setup` verifies the signed production deployment, caches the miner-kit from the
coordinator (`/coretex/v5/kit/file/<sha256>`), and reads the confirmed chain head.
The older npm `@botcoinmoney/coretex-client` is retired.

See the repository root README for commands and contracts.
