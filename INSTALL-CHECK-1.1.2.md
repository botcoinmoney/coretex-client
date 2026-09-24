# Bounded consumer installation check — release 1.1.2 with the optional Jev addon

Date: 2026-09-24. Harness: `tools/install-check-1.1.2.py`. Results:
`evidence/install-check-1.1.2/results.json` (111 checks, **111 pass, 0 fail**).

Everything below ran through the **public installer** (`tools/coretex-setup.py`) and the
**generated launcher** (`<install>/bin/coretex`) in throw-away installations on a data volume.
No source-tree import, no hand-bound adapter, **no extra wheel of any kind**, no production
endpoint, no paid call and no live Jev traffic. Every arm that claims "no calls" ran with a
network kill-switch armed inside the installation's own interpreter, which refuses and
**records** every `connect`, `connect_ex` and `getaddrinfo`; the recorded count was zero in
every arm.

Release under test: **1.1.2**, release root `c1616ec3c6c02a6dda55da5ef4b40ce402a0fe4cc4a3965f9c3697108de18218`,
adapter wheel `coretex_memory_agent-1.1.2-py3-none-any.whl` sha
`067905430f7254d8f726d1fbed2915c98605e45919afc7707b879c9d4a9dc0db` (232413 bytes), installed from the generated
inventory `tools/release-inventory.json` (4258 bytes, sha `6dbe6ffdfbca1d2b81e8f599db174a534d9a7209e7f7aad64bc6220806b1755a`, source commit
`c7565fc005a9249a99bba8700b3e644210d9db27`).

## The blocking findings are CLOSED

The previous revision of this document recorded three findings that made release 1.1.2
uninstallable by a consumer, and a **candidate adapter** carrying the fixes had to be installed
through the installer's `--extra-wheel` path to run the check at all. All of them are now fixed
at the cause in the coordinator repository and 1.1.2 has been **re-minted**; a fourth, of the
same kind, was found by this pass and fixed before the mint that this run used:

1. **Ancestry table.** `coretex_memory_agent/authority.py` carried `_RELEASE_ANCESTRY`, a table
   of the product versions that existed when it was written, so every release refused every
   successor — including the one it shipped inside. The position and the parent edge are now
   DERIVED from the release itself and re-read from its own baseline bridge.
2. **Closed release-field tuple.** `_RELEASE_FIELDS` predated the release's `judge` block. The
   field set now comes from the schema the release declares; capability blocks are admitted when
   present and validated for shape, and the set stays closed in both shapes.
3. **Composition identity.** `GENESIS-COMPOSITION.json` named `doc.tool.v1`'s identity
   `botcoin6-render-prefix` while that bundle's manifest declares `policy_id
   botcoin6-render-prefix-e202`, so composition loading failed for all three profiles. The
   composition's dispatch identity is now taken from each bundle manifest's own `policy_id` —
   fixed in the generator, not by relaxing the equality.
4. **The sealed validator carried the same conflation.** Found by this pass: with (3) fixed, a
   release-bytes-only install still failed at installer step 2/4, inside
   `bootstrap.verify_sealed` → `coretex-validator verify-release`, with *"baseline execution for
   doc.tool.v1 is invalid: parent release miner provenance disagrees with the composition
   binding"*. `coretex_validator/parent_execution.py` required `source_provenance.miner` to equal
   the composition's `miner_id`; attribution is not the dispatch identity. The validator now
   requires `miner_id` to equal the manifest's own `policy_id` (strictly stronger) and requires
   miner attribution only to be PRESENT. The validator wheel was rebuilt and the release
   re-minted, which is the mint recorded above.

There is therefore **no candidate adapter and no `--extra-wheel` anywhere in this run**. Every
generation pointer written by this check reports `"pure_release": true` with an empty
`extra_wheels`; they are recorded per bed under `purity` in the results file:

| generation | version | release root | `pure_release` | `extra_wheels` |
|---|---|---|---|---|
| fresh | 1.1.2 | `c1616ec3…` | `true` | `[]` |
| upgrade, before | 1.1.0 | `fb1a0c66…` | `true` | `[]` |
| upgrade, after | 1.1.2 | `c1616ec3…` | `true` | `[]` |
| upgrade, rolled back | 1.1.0 | `fb1a0c66…` | `true` | `[]` |

## Beds

| bed | what it is |
|---|---|
| **fresh** | a 1.1.2 installation built by the installer, populated with 12 memories, then taken through the addon arms |
| **upgrade** | a **populated 1.1.0** installation (12 memories) upgraded to 1.1.2 tools through `bin/coretex upgrade`, taken through the same arms, then rolled back |
| **refusal** | the installer's inventory refusals |

Authority mode: `genesis` (the verified release directory, pinned, no chain read). The
chain-refreshing mode is unchanged by this work and was deliberately not exercised, because it
reaches the production coordinator's object endpoint.

### Why the upgrade bed starts from 1.1.0 and not 1.1.1

The previous pass upgraded from 1.1.1 and could only do it with the candidate adapter, because
no shipped adapter can load a 1.1.1 release either. **1.1.1 is not being re-cut**, and finding 3
above is a fix in release CONTENT rather than a tolerance in the adapter, so a corrected adapter
refuses 1.1.1's composition for good: 1.1.1's `GENESIS-COMPOSITION.json` names
`botcoin6-render-prefix` while its `doc.tool.v1` manifest declares
`botcoin6-render-prefix-e202`, and equality is still required exactly.

The upgrade bed therefore starts from **1.1.0**, which every consumer could actually install:
1.1.0 loads with its OWN shipped release adapter, its composition agrees with its manifests, and
the resulting installation is pure release bytes. That keeps the whole run free of extra wheels
while making the generation change larger, not smaller — runtime wheel, adapter wheel, verified
release, module bundles and retrieval binding all differ between the two generations. The
1.1.1 arm is **dropped**, and with it the only reason this check ever needed a wheel that was
not in a release.

One real client defect had to be fixed for that: the launcher tools are always the CURRENT
client's, but the generation they open may carry an OLDER release's adapter — an installation of
1.1.0, and the generation kept for rollback after any upgrade. `coretex-setup.py`'s health
probe, `coretex-run.py` and `coretex-sidecar.py` all called `AgentMemory.judge_status()`, which
only exists from the 1.1.2 adapter, so every one of those paths crashed with `AttributeError`.
They now go through `coretex-run.py::judge_status_of()`, which returns a typed absence
(`bound: null`, `available: false`, with a reason) when the bound adapter has no `cap.judge.v1`
binding. Without it the installer could not install, upgrade from, or roll back to any release
before 1.1.2.

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
| upgrade · 1.1.0 install | 1 | PASS |
| upgrade · upgrade to 1.1.2 | 7 | PASS |
| upgrade · the ten addon arms | 47 | PASS |
| upgrade · rollback | 4 | PASS |

**Store preservation.** The upgraded store kept all 12 live records (`{"live": 12, "retracted": 0,
"total": 12}` before and after), stayed at the same path and the same 77,824 bytes, opened under
1.1.2 with no re-ingestion (`store_retained: true`, `re_ingestion: false`), and served the 1.1.2
generation's module — `08c6908c…` under 1.1.0, `2efa129a…` under 1.1.2. The rollback returned
the launcher to 1.1.0 against the same store, with the same record counts and rendered bytes
identical to the pre-upgrade baseline; the store file is byte-identical before the upgrade and
after the rollback (`792fb7d9…`).

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

* **Judged selection inside M6 was not exercised, and the reason is narrower than this document
  previously stated.** The release's genesis baseline modules —
  `v5/release-1.1.2/releases/<profile>/manifest.json` — declare `capabilities` `[]` for
  **conv.pref.v1** and **doc.tool.v1**, and `["cap.text.v1", "cap.lexicon.v1"]` for
  **event.schema.v1**. *None of the three declares `cap.judge.v1`*, so a bound judge provider is
  offered to the serving store and never consulted through the genesis baseline. (The previous
  revision said the baseline modules declare `cap.text.v1` and `cap.lexicon.v1`; that is true of
  one of the three and of no other.) The release DOES bind `cap.judge.v1` at the release level —
  `RELEASE.json`'s `judge` block, model `jev-1.13.0`, with its sealed table and descriptor
  mapping — and the composed bundles under `benchmark-v2/composed/bundles/<profile>.jev.v3` DO
  declare `capabilities: ["cap.judge.v1"]`, but those are **mining candidates**, not the
  release's baseline. What this check proves is that the enable control reaches the serving
  store's provider binding, and that a failing, slow, declining or absent provider always leaves
  the complete local pack.
* The provider used was a deterministic local fake, by design: a live call would prove nothing
  about installer wiring and would cost money.
* **Quality was not re-measured.** The recorded 917-query, three-profile, zero-difference local
  identity gate for this runtime stands as the identity evidence; this check is about the public
  setup/launcher path that those source-tree and manually-bound adapter tests bypass.
* `coretex_consumer` is **0.1.1**, rebuilt from the coordinator tree at `f3d5f974`: 0.1.0 pins
  `coretex-memory-agent==1.1.0` and therefore fails `uv pip check` on any 1.1.x release after
  1.1.0. The pin is now the range `>=1.1.0` — which adapter an installation runs is decided by
  the release inventory it installs from, not by a literal in the client's metadata. The wheel
  already committed here is byte-identical to the one that source produces
  (`fab13adf1586aad8fdcd539248fc7a4778e750f29733dd3615c4483238aeddc2`, 19476 bytes), verified by
  rebuilding it; only `consumer-artifacts/SOURCE.json` moved, to name the commit that now carries
  the change.
* The installer's `--extra-wheel` path still exists — it is how a candidate fix is verified
  before it is cut into a release — but nothing in this run uses it, and `CURRENT.json` would
  report `pure_release: false` if anything did.
* **The optional addon is outside the release.** `coretex_jev_addon-0.1.0-py3-none-any.whl`
  (sha `1edb33e2ecdd635dbbea3c7f3a1f4b8907363f3243170c1a4673c81a06deef94`, 140763 bytes, the
  digest the release cut records) is carried in the inventory under `optional.jev_addon`, not in
  `RELEASE.json`'s artifacts, so its bytes are pinned by the inventory alone.

## The release adapter against the shipped suites

There is no candidate adapter to test any more, so what is recorded here is the RELEASE adapter,
in a 1.1.2 installation built by the installer from release bytes alone (`pure_release: true`),
with `pytest` and its dependencies added afterwards from local wheels and `TMPDIR` on the data
volume (the fixtures hard-link the model bundle). Suites taken from the coordinator tree at
`43a39883`:

* `coretex-memory-agent/tests` — **73 passed, 1 skipped, 0 failed** (74 collected, 29.1 s). The
  skip is `test_judge_cache_lifecycle_through_adapter`, which does `importorskip
  ("coretex_jev_addon")`: the addon is optional and is not installed in that bed.
* `coretex-consumer/tests` — **28 passed, 0 failed** (5.8 s). The previous revision recorded 12
  passed / 16 failed here; those fixtures pinned `release-1.1.0` and the literal epoch 200 and
  failed inside `verify_bundle` on `runtime_version_min`. They were carried forward in the
  coordinator commit that fixed the adapter, and now select the release graph the INSTALLED
  runtime can serve.

This run is an addition made after the recorded check; `results.json` covers the installation
check itself, which installs no test tooling at all.

## Reproducing

```sh
tools/make-release-inventory.py \
  --release-dir <coordinator>/v5/release-1.1.2 \
  --source-commit <this client commit> \
  --addon coretex_jev_addon-0.1.0-py3-none-any.whl \
  --out tools/release-inventory.json --pin tools/coretex-setup.py

tools/install-check-1.1.2.py \
  --work <scratch on a data volume> \
  --installer tools/coretex-setup.py \
  --source-112 <dir: release/ + tools + uv wheel + release-inventory.json> \
  --inventory-112 <src112>/release-inventory.json \
  --source-prev <same for the 1.1.0 release> \
  --inventory-prev <srcprev>/release-inventory.json --prev-version 1.1.0 \
  --addon-wheel coretex_jev_addon-0.1.0-py3-none-any.whl \
  --fake-wheel coretex_fake_judge-0.1.0-py3-none-any.whl \
  --out evidence/install-check-1.1.2/results.json
```

The inventory is generated from the release and never written by hand; `--pin` rewrites the one
literal left in `tools/coretex-setup.py` to the generated file's own size and digest, so the
installer and the inventory cannot drift apart silently. Because the inventory records the
digests of the launcher tools as they exist at `--source-commit`, the commit bound here is the
client commit that already carries them (`c7565fc005a9249a99bba8700b3e644210d9db27`), and the inventory and its pin
land in the commit after it.
