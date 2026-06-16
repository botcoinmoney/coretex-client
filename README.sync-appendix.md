## Release discipline

This repository is the standalone release source for
`@botcoinmoney/coretex-client`. Git tags, GitHub releases, the package version
in `package.json`, and the runtime constant in `src/version.ts` must match.

Shared protocol/client logic is synced from the canonical
`botcoinmoney/coretex` repository. To refresh this repo from a checked-out
CoreTex tree and record the upstream commit:

```bash
npm run sync:from-coretex -- --source /path/to/coretex
```

The sync script updates `SYNC_PROVENANCE.json` so releases can always be tied
back to a specific upstream CoreTex commit.
