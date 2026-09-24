# Bounded consumer installation check — release 1.1.2 with the optional Jev addon

Date: 2026-09-24. Harness: `tools/install-check-1.1.2.py`. Results:
`evidence/install-check-1.1.2/results.json` (111 checks, **111 pass, 0 fail**).

Everything below ran through the **public installer** (`tools/coretex-setup.py`) and the
**generated launcher** (`<install>/bin/coretex`) in throw-away installations on a data volume.
No source-tree import, no hand-bound adapter, no production endpoint, no paid call and no live
Jev traffic of any kind. Every arm that claims "no calls" ran with a network kill-switch armed
inside the installation's own interpreter, which refuses and **records** every `connect`,
`connect_ex` and `getaddrinfo`; the recorded count was zero in every arm.

## Two blocking release findings (these are why a candidate adapter was needed)

The shipped 1.1.2 adapter (`coretex_memory_agent-1.1.2`, sha
`91fc5750486b847e66b9b706864cd84af6dc5a9261899aa53f4b3b2bbda74bd9`) **cannot load the 1.1.2
release it ships with**, so no consumer installation of 1.1.1 or 1.1.2 is possible with release
bytes alone. Both failures are in `coretex_memory_agent/authority.py` and both are reproducible
from the wheel:

1. `_RELEASE_ANCESTRY = {"1.0.0": (1, None), "1.1.0": (2, …)}` — 1.1.1 and 1.1.2 are not in the
   table, so `_validate_release` refuses with *"release is not a supported CoreTex product
   version"*. Three further checks are gated on the literal `version == "1.1.0"`.
2. `_RELEASE_FIELDS` is a closed set that predates the release's own `judge` block, so 1.1.2's
   `RELEASE.json` is refused with *"release fields must be exactly […]; got […'judge'…]"*.

A third finding is release **content**, not adapter code: `GENESIS-COMPOSITION.json` records
`doc.tool.v1`'s baseline `miner_id` as `botcoin6-render-prefix`, while that bundle's
`manifest.json` carries `policy_id = botcoin6-render-prefix-e202`. `_load_module_composition`
requires equality, so composition loading fails for **all** profiles. This is present in 1.1.1
as well. It needs an operator decision: either the next cut makes the two equal, or the adapter
accepts an instance label (`<miner_id>-<tag>`) while continuing to require exact equality of
every binding that decides which bytes execute — `module_sha256`, the bundle manifest root and
the delegation candidate hash.

None of this is fixable in the installer: `release_root` is a hash over the whole release body,
so a filtered or edited view cannot verify. **A follow-up adapter wheel and release cut is
required before 1.1.2 can be installed by a consumer.** Nothing was re-cut here.

To run the check at all, a **candidate adapter** carrying exactly those changes was built from
the images-branch source and installed through the installer's new, recorded `--extra-wheel`
path: `coretex_memory_agent-1.1.2+consumerfix1`, sha
`39718563c1f9c85a6eb3d2eef61b563daafa9a8541ae6cdbe62beee2a3f144c6`. It differs from the release
adapter in `coretex_memory_agent/authority.py` and **nothing else** (verified member by member
against the release wheel). `CURRENT.json` records every extra wheel by digest and reports
`"pure_release": false`, so such an installation can never be mistaken for a release one.

## Beds

| bed | what it is |
|---|---|
| **fresh** | a 1.1.2 installation built by the installer, populated with 12 memories, then taken through the addon arms |
| **upgrade** | a **populated 1.1.1** installation (12 memories) upgraded to 1.1.2 tools through `bin/coretex upgrade`, taken through the same arms, then rolled back |
| **refusal** | the installer's inventory refusals |

Authority mode: `genesis` (the verified release directory, pinned, no chain read). The
chain-refreshing mode is unchanged by this work and was deliberately not exercised, because it
reaches the production coordinator's object endpoint.

## Results

| bed / arm | checks | result |
|---|---|---|
| fresh · install | 2 | PASS |
| fresh · addon absent | 5 | PASS |
| fresh · addon installed, disabled | 6 | PASS |
| fresh · enabled without a key | 5 | PASS |
| fresh · enabled with a FAKE provider (incl. live sidecar probe) | 11 | PASS |
| fresh · provider failure | 5 | PASS |
| fresh · provider deadline | 5 | PASS |
| fresh · provider declines (typed absence) | 4 | PASS |
| fresh · disabled after use | 1 | PASS |
| fresh · disabled and uninstalled after use | 5 | PASS |
| refusal · artifact digest mismatch | 1 | PASS |
| refusal · tampered inventory cache vs. the pin | 2 | PASS |
| upgrade · 1.1.1 install | 1 | PASS |
| upgrade · upgrade to 1.1.2 | 7 | PASS |
| upgrade · the ten addon arms | 47 | PASS |
| upgrade · rollback | 4 | PASS |

**Store preservation.** The upgraded store kept all 12 live records (`{"live": 12, "retracted":
0, "total": 12}` before and after), stayed at the same path and the same 77,824 bytes, opened
under 1.1.2 with no re-ingestion, and served the 1.1.2 generation's module. The rollback
returned the launcher to 1.1.1 against the same store, with the same record counts and rendered
bytes identical to the pre-upgrade baseline.

**Off is byte-identical.** In every arm the rendered context bytes and the receipt for three
fixed queries were compared against the pre-addon baseline taken before the addon existed on the
machine. They matched in all arms — addon absent, installed-but-disabled, enabled-without-key,
enabled-with-a-provider, provider failure, provider deadline, provider declining, and after the
addon was disabled and uninstalled following use.

**What "enabled" set, and how it was proved.** `coretex jev enable --key -` wrote the key to
`<install>/.jev/jev.key` at mode `0600` (the value never appeared in any output) and made the
launcher export `CORETEX_JUDGE_ENABLED=1`, `CORETEX_JEV_ENABLED=1` and `CORETEX_JEV_CONFIG` to
every serving invocation. `jev status` then reported `provider_attached: true` with
`provider_id: judge.provider.fake`, resolved through the real
`coretex_memory.judge_providers` entry point. The **running sidecar** was started and reported
the binding it captured itself (`probe: running-sidecar`, `available: true`), not a configuration
file. With `disable`, the launcher exports `…=0` and explicit off wins over an inherited
environment.

## Scope and honest limits

* **Judged selection inside M6 was not exercised.** The 1.1.2 genesis baseline modules declare
  `cap.text.v1` and `cap.lexicon.v1` only — not `cap.judge.v1` — so a bound provider is offered
  and never consulted. That is why enabling the addon leaves the rendered bytes identical here;
  it is an evaluation-side fact about the current modules, not an installer result. What this
  check proves is that the enable control reaches the serving store's provider binding, and that
  a failing, slow, declining or absent provider always leaves the complete local pack.
* The provider used was a deterministic local fake, by design: a live call would prove nothing
  about installer wiring and would cost money.
* **Quality was not re-measured.** The recorded 917-query, three-profile, zero-difference local
  identity gate for this runtime stands as the identity evidence; this check is about the public
  setup/launcher path that those source-tree and manually-bound adapter tests bypass.
* The 1.1.1 generation ran the same candidate adapter, because no shipped adapter can load a
  1.1.1 release either. The substantive difference between the two generations — runtime wheel,
  verified release, module bundles and retrieval binding — was real.
* `coretex_consumer` was rebuilt as **0.1.1** because 0.1.0 pins `coretex-memory-agent==1.1.0`
  and therefore fails `uv pip check` on any 1.1.x release after 1.1.0. The pin is now the range
  `>=1.1.0`: which adapter an installation runs is decided by the release inventory it installs
  from, not by a literal in the client's metadata.

## Reproducing

```sh
tools/install-check-1.1.2.py \
  --work <scratch on a data volume> \
  --installer tools/coretex-setup.py \
  --source-112 <dir: release/ + tools + uv wheel + release-inventory.json> \
  --inventory-112 <src112>/release-inventory.json \
  --source-111 <same for 1.1.1> --inventory-111 <src111>/release-inventory.json \
  --addon-wheel coretex_jev_addon-0.1.0-py3-none-any.whl \
  --fake-wheel coretex_fake_judge-0.1.0-py3-none-any.whl \
  --candidate-adapter coretex_memory_agent-1.1.2+consumerfix1-py3-none-any.whl \
  --out evidence/install-check-1.1.2/results.json
```
