# The V5 rig lane, and what a public validator can actually check

This document records what the rig-lane validator in `python/coretex_validator` does, and — more
importantly — the things that were found to be **wrong or missing** while building it. The
findings are first because they change what anyone should believe about the staged design.

Status: the offline and local-chain legs are proven. **The mainnet-rehearsal leg is UNPROVEN**:
no rehearsal transition exists on Base yet (Phase 4/5 are blocked on operator keys), so nothing
here has been run against a real deployment. No mainnet snapshot and no signature has been
fabricated to stand in for one.

---

## 1. Findings

### F1 — The staged rig dispatch decodes events that no contract emits

`validator/dispatch.py` registers five rig events: `RigCoreTexStateAdvanced`,
`RigCoreTexScreenerPassRecorded`, `RigCoreTexEpochInherited`, `RigCoreTexEpochContextSet`,
`RigCoreTexEpochFinalized`. Grepping every `.sol` in the rig source tree and in
`RigCoreTexStateRegistry.sol` for those five names returns **nothing**. What the contracts
actually emit is:

| contract | events |
| --- | --- |
| registry | `CoreTexStateAdvanced`, `CoreTexEpochFinalized`, `CoreTexVerifierBound`, `EpochClockBound` |
| mining | `RigCoreTexCreditAccepted`, `RigCreditAccepted`, `EpochCommitSet`, `EpochSecretRevealed`, … |
| verifier | `CoreTexEpochContextSet`, `CoreTexPolicyScheduled`, … |

Consequences, each independently fatal to a validator built on the staged table:

* `dispatch.RIG_TOPICS` — the `eth_getLogs` topic0 set a rig validator would subscribe to —
  contains **none** of the topics a real deployment emits. The filter returns zero advances,
  which is indistinguishable from a deployment that never mined.
* `dispatch.route()` raises `WrongProtocolError` for a real rig advance, because its topic0 is
  registered under `PROTOCOL_V4` while the deployment says `PROTOCOL_RIG`.
* There is **no screener-pass event at all**. Priced work that did not move the root is visible
  only as a `RigCoreTexCreditAccepted` with no advance in the same transaction.
* The epoch's law pins are emitted by the **verifier**, not the registry (design §4, "Epoch
  context is DELEGATED, not owned"). A validator watching only the registry can never read the
  pins it is supposed to check an advance against.

`python/coretex_validator/rig_events.py` is derived from the exact sources and supersedes the
staged table for anything that touches a real chain. The staged table is **kept** in `dispatch.py`
— a decoder for a protocol that was never deployed — because deleting it would erase the evidence
of what changed.

### F2 — The rig advance topic0 is byte-identical to the V4 lane's

```
CoreTexStateAdvanced(uint64,uint64,address,bytes32,bytes32,bytes32,bytes32,bytes32,
                     bytes32,bytes32,uint256,uint16,bytes)
  → 2f0a89894d44aa2294de109d294ac072f0e206dc834a0c35c6fbf1623ec02dd0
```

That is the same digest as `dispatch.V4_STATE_ADVANCED_TOPIC0`, and `CoreTexEpochFinalized`
likewise matches `V4_EPOCH_FINALIZED_TOPIC0`. It is deliberate on the contract's side — design
§7.3 wants an indexer written for `RigCoreTexRegistry` to decode these logs unchanged — and it
**flatly contradicts** the staged dispatcher's stated requirement that "V5 must never emit an
event that collides with `CoreTexStateAdvanced`'s topic0". The dispatcher's import-time
non-collision assertion passes only because it is checking a signature the chain never emits.

The contract wins: it is the thing that emits logs. So:

* **topic0 is not an identity.** A log at `2f0a8989…` is a V4 advance or a rig advance depending
  only on which address emitted it. Routing is by address, in both languages.
* **The wire format is shared, so the DECODE is shared.** Identical topic0 means identical
  signature means identical field layout — the existing decoder reads a rig advance correctly.
  The lanes diverge at *interpretation* (which registry owns the epoch, which verifier holds its
  pins), never at decoding. This is why the TypeScript side adds no second advance decoder.
* Note there are **three** advance generations, not two: `v4.ts`'s original
  `CortexStateAdvanced` + `CoretexPatchBytes` pair is distinct from both and collides with
  neither.

### F3 — `chain_first.validate_rig_chain_first` uses the superseded patch-hash label

`chain_first.RIG_PATCH_HASH_LABEL` is `b"coretex-memory-transition-hash-v1"` — the V5 **memory**
lane's transition-hash domain. The rig verifier's rule (`RigCoreTexVerifier.sol:411-415`, and the
generated binding, which records the memory label explicitly as `COMPACT_PATCH_SUPERSEDED_LABEL`)
is:

```
patchHash = keccak256(utf8("coretex-patch-hash-v1") ‖ compactPatchBytes)
```

The two labels give different digests for **every** input, so the staged check does not merely
differ in style — it raises `RIG_PATCH_HASH_MISMATCH` on every real advance. Since step 5 of
`validate_rig_chain_first` is the check that makes fetching the candidate's edit by hash safe,
the whole rig chain-first envelope fails closed on correct data. Fixed in
`rig_events.PATCH_HASH_LABEL`; the superseded label is kept beside it so a mismatch can *report*
which rule produced the digest rather than leaving an operator to guess.

### F4 — Deterministic Benchmark-v2 admission depends on non-public trees

**This is the finding that decides whether a public validator can fully exist, and the answer
today is "not for step 5".**

`replay.py`'s consensus-grade admission needs two trees:

* `benchmark-v2/` — the frozen receipt replay (`validator/replay.py::replay_receipt`) and the
  G6b oracle screen;
* `coretex-memory/` — the pinned runtime.

Both live **inside the private `botcoin-coordinator` repository**. Verified anonymously:

```
$ env -i GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/botcoinmoney/botcoin-coordinator.git
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

A clean machine therefore **cannot** rerun deterministic admission. This is surfaced honestly
rather than papered over: with no trees configured the sandbox and screen report themselves
UNAVAILABLE, the replay records a **BACKLOG**, and the export carries the gap in its `unverified`
list. A BACKLOG is the correct outcome for "this host cannot check that" — a PASS would be a lie
and a FAIL would be a slander. Five of the ported tests skip for exactly this reason, and the
skip reasons name the missing trees.

An operator who holds the trees points at them with `CORETEX_BENCHMARK_V2_DIR` and
`CORETEX_MEMORY_RUNTIME_DIR`, and the same code path runs the real pinned admission.

### F5 — The rig contract source repository is also private

`github.com/botcoinmoney/botcoin-mining-rigs` (pinned at `cdb91d21`) is **not** anonymously
clonable. The validator does not need it at runtime — every event signature, tuple layout and
typehash it depends on is transcribed into the package and re-derived at import — but it means an
external reviewer cannot today check those transcriptions against their source. The
*deployment* is still verifiable without it, because bytecode is checked against the release
artifact's recorded runtime hashes.

### F6 — The coordinator's own rig E2E harness does not run as committed

`v5/e2e/deploy.py` on `v5-integration-20260730` deploys `TestRigAccessManager` and
`TestRigCoreTexVerifier` from `rig-test/doubles/`. Commit `b417c8a` ("Vendor the EXACT rig CoreTex
source; run the suite against the real verifier") removed both — the access manager became the
real `ProtocolAccessManager` and the verifier double was replaced by the real
`RigCoreTexVerifier`, whose constructor signature also changed to
`(accessManager, coreTexRegistry, CoreTexPolicyInput)`. `deploy.py` was not updated, so
`run_rig_e2e.py` aborts at the first `forge create`. The local-chain proof for this package
therefore drives its own deployment of the same exact contracts rather than reusing that harness.

### F7 — `null` is not a canonical value, and optional fields were emitting it

Found by the canonicaliser while wiring the export. Optional chain facts (an unrevealed epoch
secret, an unscheduled policy, an absent runtime-packet pin) were being serialised as `null`,
which `frontier.canonical_bytes` refuses by design: a field is either present with a well-typed
value or absent, and encoding "I do not have this" as a present `null` makes a **sealed** epoch
secret and a **missing** field the same bytes. Absence is now encoded by absence, with explicit
`revealed` / `available` booleans carrying the "known absent" meaning.

### F8 — RESOLVED: the resolver's per-epoch schema is the published one

This package first built a PER-TRANSITION snapshot. It lost the scope decision, and the reasoning
is worth keeping because it is not a matter of taste: the consumer is an isolated runtime agent
performing PORTABLE ACTIVATION. It needs the STATE at an epoch — live root, per-profile release
roots, composed manifest, law locks — not the story of one advance. A per-transition document
describes an **edge**; activation needs a **node**. Lineage still matters and belongs inside the
epoch snapshot as evidence, which is where the resolver puts it.

The published schema is therefore `coretex.rig-state.resolver-snapshot/v1`, 23 top-level keys.
`resolver_snapshot.py` reproduces it. The ordering discipline this package established — rebuild
the unsigned payload from chain truth, compare bytes, and only then look at a signature —
survives unchanged and was adopted on both sides.

**Two classes of key, and they are not evidence of the same thing.** `SCHEMA_CONSTANT_KEYS`
(`derivation`, `canonicalization`, `disclosure`, `prior`, `resolver`, …) are spec text, identical
in every snapshot of this schema; reproducing them proves a transcription is right and says
nothing about any chain. `CHAIN_DERIVED_KEYS` are read back from the chain, the logs, the calldata
and the store. The comparison report keeps them apart so "the constant blocks matched" can never
be presented as evidence about a deployment.

### F9 — Only `getHeader` returns a zero-filled struct; the other reads revert

Found by running against a real deployment, not by reading the source. Design §7.5's fall-through
rule is written about `getHeader(N)`, and it is correct: an unsealed epoch yields a zero-filled
struct rather than a revert. **The other registry reads do not share that behaviour.** The
registry delegates every epoch read to the bound verifier's context, and `liveStateRoot(N)` /
`epochParentStateRoot(N)` revert with `EpochContextNotSet()` (`0xae3a262a`) for an epoch that was
never given one.

A backwards lineage walk that only handled the `getHeader` case therefore dies on the first epoch
below the registry's first served one — which, for any young deployment, is immediately. The walk
now asks the verifier's `coreTexEpochContextSet(N)` **first**. That is deliberately a question
with an answer rather than an exception to catch: a `try/except` around the revert would have to
distinguish "this epoch has no context" from "the endpoint is broken", and a revert selector alone
does not reliably tell you which.

### F10 — `abi.pad_bytes` is misleadingly named

Ported verbatim from the staged lane. It returns the **entire** dynamic-`bytes` ABI tail (length
word + payload + padding), not just the padding its name implies. Prepending a length word to its
output — the natural reading — shifts every subsequent byte by 32, and on chain that surfaces as
`ECDSAInvalidSignatureS(...)` from OpenZeppelin rather than as a decode error. A misleading symptom
for an off-by-32 offset bug. Left as-is so the port stays verbatim; recorded here because the next
person will hit it.

---

## 2. What the client does

Eight steps, in order, stopping at the first outright failure and recording the rest as
`NOT_REACHED` — because "not reached" and "passed" must never render the same way.

| # | step | module | notes |
| --- | --- | --- | --- |
| 1 | discover the release | `release` | refuses `MAINNET_CANONICAL` by name |
| 2 | verify contract bytecode + wiring | `release` | against the RELEASE, not a rebuild |
| 3 | per-rig receipt continuity | `receipt_chain` | CoreTex **and** standard receipts share one chain |
| 4 | reconstruct the transition | `join` | design §7.2, keyed on `(epoch, parentStateRoot, patchHash)` |
| 5 | deterministic admission | `replay` | BACKLOGs on a clean machine — see F4 |
| 6 | artifacts + HISTORICAL law | `historical_law` | the law at that transition, never today's |
| 7 | reproduce the resolver snapshot | `snapshot` | unsigned payload FIRST, signature separately |
| 8 | export for portable activation | `export` | `MAINNET_REHEARSAL` only |

### The two authorities, never collapsed

The deployed rehearsal was built from an **earlier tree** than the pinned source HEAD, so the two
legitimately disagree about bytecode:

* the **release artifact** is the DEPLOYMENT authority — it records what was deployed and the
  `keccak256` of each contract's runtime bytecode;
* the **pinned source commit** is the SOURCE / INTERFACE authority — event signatures, the
  receipt tuple layout, the typehash, the join recipe.

`Release.source_divergence()` states this in every report. The client **does not compile
anything**: reproducing a build needs a pinned solc, settings and dependency tree, and getting any
of them wrong produces a mismatch indistinguishable from tampering. Bytecode reproduction is a
separate, opt-in claim. A release that fails to name its source commit is refused, because that
turns a *known* divergence into an unknown one.

### Why the join key must include `patchHash`

`(epoch, parentStateRoot)` is **not** unique. The only self-referential rule on the advance path
is `newStateRoot != parentStateRoot`, so the head may legally cycle — `P → A → P → C` is a valid
sequence within one epoch and `P` occurs as a parent twice. The intra-epoch transition graph is a
**walk, not a simple path**. Uniqueness comes entirely from the verifier's
`coreTexPatchCredited[epoch][parent][patchHash]` guard. A resolver keyed on two of the three
silently collapses two distinct real transitions into one: no exception, no decode error, just a
shorter history that looks fine. `index_advances` refuses to build a two-part key at all, and
`assert_key_is_patch_keyed` reports whether the dataset in front of you actually contains a cycle
— because a two-part key is wrong *always* but only *visibly* wrong when the head cycles.

### The screener-only fall-through (design §7.5, NORMATIVE)

`getHeader(N)` for an unsealed epoch returns a **zero-filled struct**, not a revert. "No header"
is read from `epochFinalized(N)` and never inferred from a zero root. Epochs that were never
served are **skipped** during the lineage walk — they genuinely did not move the root, so
skipping them is correct rather than a tolerance, and treating a header-less epoch as a fault
would make an ordinary screener-only epoch look like a break. A served-but-unsealed epoch is
compared against `liveStateRoot`, which is frozen once the epoch has ended, and is **flagged**
because the operator has not committed to that root on chain.

### Reproduction before signature, and no curve code on that path

A snapshot that reproduces byte-for-byte is true whether or not it was signed. A snapshot that is
signed but does not reproduce is a correctly-transmitted false statement, and the signature makes
it worse rather than better. So `build_unsigned` reconstructs from chain state, logs, calldata and
artifacts **without reading the published payload**; `reproduce` compares canonical bytes; and
only then does `verify_signature` run, labelled TRANSPORT AUTHENTICATION. `build_export` refuses
an unreproduced snapshot and there is no parameter that lets a caller override it.

`keccak256.py` exists so a validator needs no third-party crypto. `secp256k1.py` was added for one
purpose — recovering a signer — and is imported **lazily, inside the functions that recover a
key**. Reproduction runs with no key material and no curve arithmetic;
`test_reproduction_never_loads_curve_code` asserts it in a fresh interpreter, and
`test_the_curve_module_is_only_reachable_from_a_signature_check` walks every module's AST to keep
it that way. `join_advance(verify_signature=False)` exists for the same reason: for a *confirmed*
advance the chain already rejected anything the coordinator did not sign, so step 7 is defence in
depth rather than load-bearing. The load-bearing step is 4 — recomputing `receiptHash` — which
also proves `workPolicyHash` and, via the EIP-712 digest, the `artifactHash` that no event and no
registry parameter carries.

---

## 3. Running it

```bash
cd python && ./reproduce.sh                                   # offline clean-machine proof
cd python && ./reproduce.sh --rpc "$RPC" --release release.json --export export.json
```

`reproduce.sh` builds a wheel, installs it into a throwaway venv with `--no-deps` (the zero-
dependency claim, asserted rather than declared), and runs everything with the working directory
**outside** this source tree.

Exit codes: `0` nothing was contradicted, `1` a check ran and disagreed, `2` the run could not
start. A `0` with a non-empty `unverified` list is the normal clean-machine outcome — see F4.
`--require-complete` makes unverified steps fail, and is opt-in so that "I could not check X"
never silently becomes "X is broken".

---

## 4. REPRODUCED: the real MAINNET_REHEARSAL snapshot

A clean installation rebuilt the published epoch-180 snapshot **byte for byte from Base mainnet**,
before any signature was consulted.

```
client   sha256 7087b32d3199c352336c3d7faa2126b3a1ce139a0f16b2ecc62d292fc9c672c7  28964 bytes
target   sha256 7087b32d3199c352336c3d7faa2126b3a1ce139a0f16b2ecc62d292fc9c672c7  28964 bytes
signing digest  0x15636ac13d8ed786a0da76e26bdd0b17a6d0e9127f0d32df87679bd8f453c41e   (matches)
publication set a51544ecf69d59b29791bd7a83d82abd739c6a422d231a543ff0a13ea3718d51
```

All 23 keys: 13 chain-derived, 10 schema-constant. Run conditions: a wheel built from source,
`pip install --no-deps` into a fresh venv, working directory **outside** the source tree, Base
8453 at observation block 49518473 under the finalized-tag policy. The transport signature was
then verified separately over the CLIENT'S OWN reconstruction — not over the published file —
and recovers `0xd1446157…`, the `REHEARSAL_TEST_ONLY` resolver key.

```bash
coretex-validator reproduce-snapshot --snapshot snapshot.json \
  --rpc https://mainnet.base.org --artifacts ./artifacts \
  --runtime-record RUNTIME-INTEGRATION.pre-rig.json \
  --signature snapshot.sig.json --public-key resolver-public-key.json --out rebuilt.bin
```

Full record: `evidence/reproduction-e180-client.json`.

### Preserved, not tidied

Two things a "helpful" implementation would have smoothed away, and both would have been
reproduction failures:

* **Epoch 180 is UNSEALED.** It was still current, so `sealed: false` and its final root comes
  from `liveStateRoot`. No header block is emitted at all — `getHeader` returns a zero-filled
  struct rather than reverting, so emitting it unconditionally would put eight zero roots in the
  payload and make "never sealed" indistinguishable from "sealed at the zero root", a state D2
  forbids.
* **Four locks are `disputed`** — scorer, counter, counter-resource-law, renderer — because two
  committed artifacts disagree on `runtime_abi_root` (`d83638ae…` vs `8f17abc4…`). The
  chain-addressed manifest wins, both values are published, and every lock resting only on the
  loser is downgraded — not merely the differing one, because it is the record's credibility that
  was damaged. Silently resolving the dispute would have produced a snapshot that reproduced
  cleanly and asserted something no chain attests.

### F11 — the runtime-integration record is not in the publication set

`RUNTIME-INTEGRATION.pre-rig.json` is required to rebuild `locks`, and it lives in the **private**
`botcoin-coordinator` repository — it is not among the 14 content-addressed objects published
alongside the snapshot. A clean public install therefore cannot rebuild that one block. Everything
else reproduces from the publication set and the chain alone. Same class as F4/F5, reported rather
than worked around.

### What real data taught that a local harness could not

1. **A 429 is transport, not a revert.** The first mainnet attempt hit HTTP 429 and it surfaced as
   `TransportError` — "rate limited — back off; this is NOT a contract revert". The two demand
   opposite responses, and conflating them turns a rate limit into a fabricated claim about chain
   state. The over-correction is equally a bug, so a JSON-RPC `error` object stays a
   `ResponseError` and is never retried as a network blip. Requests are also now PACED: a
   validator's read pattern is a burst of small `eth_call`s, the worst possible shape for a token
   bucket.
2. **F9 is live.** Below epoch 180 — that registry's genesis — `liveStateRoot` and
   `epochParentStateRoot` really do revert while `epochFinalized` and `transitionCount` answer
   normally. The walk asks `coreTexEpochContextSet` first, and reverts are matched by RETURNDATA
   SELECTOR (`0xae3a262a`), never by message text.
3. **Candidate bundles use `sha256-signed-manifest-body`.** Rehashing them under the frontier-JSON
   rule reports a tamper that is not there — worse than not checking, because it burns an
   operator's trust in the check.
4. **The endpoint 403s urllib's default User-Agent** with a bare 403 that reads like an auth
   failure and sends you hunting for a key that was never required. Infura was unusable at the
   time (403 unauthenticated, 401 under Basic and Bearer); `https://mainnet.base.org` is
   archive-capable at these heights.

---

## 5. What has been proven, and how

### Local Anvil, all eight steps

A stand-in chain was deployed with the **exact** contracts — real `BotcoinMiningRigsV1`, real
`RigCoreTexVerifier`, our `RigCoreTexStateRegistry`, against exact-ABI peripheral doubles — and
mined:

* an **advance** (outcome 2): `CoreTexStateAdvanced` from the registry and `RigCoreTexCreditAccepted`
  from mining, in one transaction, broadcast by the OPERATOR key over a digest the COORDINATOR key
  signed;
* a **screener pass** (outcome 1): a credit with no advance — the case with no event of its own.

| step | result |
| --- | --- |
| 1 discover release | PASS |
| 2 bytecode + wiring | PASS — all three runtime hashes matched, wiring consistent both directions |
| 3 receipt continuity | PASS |
| 4 join (§7.2) | PASS — `receiptHash` recomputed from calldata equals the mining event's |
| 5 deterministic admission | **UNVERIFIED** — no artifact store, and `benchmark-v2` is unavailable (F4) |
| 6 historical law | PASS — law read from the verifier's context + scheduled policy |
| 7 resolver snapshot | PASS — **reproduced byte-for-byte**, 4877 bytes, `sha256 a383c77f…`, zero differences |
| 8 export | PASS — `MAINNET_REHEARSAL`, gaps carried in `unverified` |

Step 7's reproduction is between two **independent runs** against the same chain state, one of
them from a clean venv outside the source tree. It is a determinism-and-reproduction proof, not a
reproduction of a resolver's published payload — no resolver has published one. The signature over
it was made with a **local Anvil test key**, purely to exercise the transport-authentication path;
it is not a resolver signature and not a mainnet one.

Two guards fired for real during this work and are worth recording, because a guard that has never
refused anything is a guard nobody has tested:

* the finality guard refused an observation block only 39 blocks deep against a default
  confirmation depth of 15, and the remaining steps reported `NOT_REACHED` rather than passing;
* the transport-signature check caught a wrong expected signer and reported the recovered address,
  while the reproduction verdict beside it stayed `true` — which is the ordering working.

### Clean-machine install

`reproduce.sh` end to end: wheel built, installed into a fresh venv with `pip install --no-deps`,
then **534 passed / 6 skipped** plus the full eight-step chain replay, all with the working
directory outside the source tree. The 6 skips are F4's non-public trees.

---

## 6. What is still unproven

* **The mainnet-rehearsal leg.** No rehearsal transition exists on Base. Everything here has been
  exercised against a local Anvil deployment of the same exact contracts. Until Phase 4/5 land,
  the client has never seen a real rehearsal advance, a real resolver snapshot, or a real
  resolver signature.
* **Step 5 on a clean machine** (F4) — structurally blocked, not merely untested.
* **Bytecode reproduction from source** — deliberately out of scope; the release is the
  deployment authority.
* **The resolver's published payload shape.** Phase 6 is in flight; `snapshot.py` defines
  `coretex.rig-resolver-snapshot/v1` from the chain-derivable facts. If the resolver publishes a
  different field set, the format must be reconciled — the *ordering* property (reproduce, then
  authenticate) is what matters and does not change.
