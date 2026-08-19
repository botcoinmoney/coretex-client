# Evidence in this tree

`full-replay-e180-T0.json`, `full-replay-e180-T1.json`, `full-replay-e180-timings.txt`,
`reproduction-e180-client.json`, and `step5-admission-PASS-e180.json` are **legacy-era
mainnet-rehearsal records from 2026-08-04**. They replay the retired rehearsal deployment
(registry `0x9ec799e8743c9e5fa364c80576122d84b0e4149e`, observation block 49518473) under
the word-diff / descriptor-v1 rules. That rehearsal used epoch number 180; it is **not**
canonical production epoch 180.

Canonical production (checked 2026-08-19) is a different registry
(`0xa4d8a7Bb3Ba2D023af29Bf77601A61673ED89ad3`). Its epoch 180 is unsealed,
`transitionCount` 2, live root
`0x06bcdca6a8c02aafc13217baa6c40665264485d3a3bf8e780999acf0541366ad`. The 2026-08-18
rehearsal that first moved production genesis is epoch 179: `8f2455e5…` → `803c90ce…`.

Keep these files as era-bound history. Do not present them as a replay of live production
epoch 180. See `docs/V5-RIG-VALIDATOR.md` §4.
