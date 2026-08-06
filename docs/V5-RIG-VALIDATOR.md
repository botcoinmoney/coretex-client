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

**SUPERSEDED (2026-08-06, §7).** `coretex-patch-hash-v1` — the label this finding names as
*correct* — is itself now the RETIRED rule: transition-descriptor v2 replaces it with
`coretex-transition-descriptor-v2`. `chain_first.RIG_PATCH_HASH_LABEL` now carries the live v2
label (it previously carried the memory lane's, which this finding correctly identified as
wrong); the two-labels-give-different-digests property this finding relies on still holds, just
with a third label added to the refused set. See §7 for the full correction.

### F4 — CLOSED: the admission code trees are published

**This finding is resolved.** The six trees deterministic admission needs —
`benchmark-v2/{generators,scoring,miner_abi,validator,frontier}` and
`coretex-memory/coretex_memory` — are published as content-addressed objects under publication
root `d90f469cf8f737e100f8cd13f06c56559e315c04f974d4e3c987c40a7c4f7399`, addressed by the SAME
tree-hash rule the signed receipt's `code_roots` binds. So the address is the chain-bound identity,
not a new scheme, and a consumer verifies by extracting and recomputing rather than trusting the
container.

```bash
CORETEX_ADMISSION_REPO_ROOT=<dest>
CORETEX_BENCHMARK_V2_DIR=<dest>/benchmark-v2
CORETEX_MEMORY_RUNTIME_DIR=<dest>/coretex-memory
```

With those set, `BenchmarkV2Sandbox.available()` and `ChildInterpreterOracleScreen.available()`
both report `True` from a clean wheel install, and `sandbox_unavailable` /
`oracle_screen_unavailable` are no longer reachable. One public PyPI dependency (`wasmtime`) is
needed by the runtime tree; the validator itself still declares zero runtime dependencies.

Publishing the trees did not, on its own, make step 5 pass — two defects in THIS package sat in
front of them. See K1 and K2 below.

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

### Reconstruction equality IS the authority

**A downloaded snapshot is a CACHE.** What makes it true is that a clean installation
independently reconstructs identical canonical bytes from the pinned chain, contracts,
finalized block, events, calldata and content-addressed artifacts. Not that somebody
signed it.

So there is no off-chain signature ceremony in the verification path: no resolver
public-key pin, no signing-digest check, no `snapshot.sig.json` requirement, and no
`transport_signature` verdict in the export. That field was deleted rather than repaired,
because carrying it beside the reproduction invited exactly the wrong reading — that a
valid signature was a second, alternative reason to believe the payload. It was never
that, and a signature that could be *offered* as an alternative eventually gets accepted
as one.

The property that used to be a discipline is now structural: `build_export` has no
signature parameter, so nothing can be handed to it in place of a reproduction.

**One signature is still verified, because a deployed contract enforces it:** the
coordinator's EIP-712 mining receipt, checked against `mining.coordinatorSigner()` in the
§7.2 join (step 7). That is a fact about the chain rather than about a publisher, and it
is load-bearing — the `receiptHash` preimage that binds calldata to the confirmed credit
contains the digest.

`keccak256.py` exists so a validator needs no third-party crypto. `secp256k1.py` remains
for that one contract-enforced recovery, is imported lazily, and
`test_the_curve_module_is_only_reachable_from_a_signature_check` walks every module's AST
to keep it off the reconstruction path — which now needs no key material of any kind.

The signature functions in `snapshot.py` are kept but marked HISTORICAL and are
unreachable from the path. The epoch-180 rehearsal artifacts were published signed, those
runs are historical records, and somebody re-examining that evidence should be able to
re-check what they checked. Those artifacts are preserved unmodified. **Future artifacts
are unsigned and content-addressed.**

### Portable sync

Never activate a snapshot on the strength of HTTP delivery or its own self-declared chain
fields. A consumer either invokes `coretex-validator` reconstruction, or performs the
minimal finalized-chain and root verification itself, before activation. Delivery is not
provenance.

---

## 3. Running it, and what it costs

There are **two commands with very different cost classes**, and conflating them will mislead
anyone budgeting for a replay.

| command | what it proves | cost |
| --- | --- | --- |
| `reproduce-snapshot` | the published snapshot's unsigned payload rebuilds byte-for-byte from chain truth | **~153 s wall**, ~46 RPC calls, negligible CPU |
| `reproduce` (admission wired) | the above *plus* deterministic Benchmark-v2 admission re-executed | **754–1150 s wall**, three-deep process nesting with parallel scoring workers |

Quote the admission figure as a **range, not a number**. Three measured runs of the
same work on the same box came in at 754 s, 1093 s and 1150 s — a ~45 % spread driven
by nothing but contention. A single figure would imply a precision this workload does
not have.

`reproduce-snapshot` is **network-bound, not CPU-bound**: most of its wall time is deliberate
pacing (`--min-interval`, default 0.7 s) against a rate-limiting public endpoint, plus round-trip
latency. A private or higher-limit endpoint will be substantially faster; that is a property of
the endpoint, not of the work.

`reproduce` with `CORETEX_BENCHMARK_V2_DIR` / `CORETEX_MEMORY_RUNTIME_DIR` set is the expensive
one. It re-derives the selections, regenerates instances and re-runs scoring against the pinned
runtime — real computation, not verification of a hash. It spawns a sandbox child which spawns
three nested children which spawn three scoring workers, and on a small box those workers saturate
it.

**Measured on:** 4-core Intel Xeon Platinum 8259CL @ 2.50 GHz, 15 GiB RAM, Linux 6.8 (AWS),
CPython 3.10.12, `wasmtime` 46.0.1. That is a *modest* machine and the admission path is
CPU-bound, so a larger box should do materially better — an external agent budgeting from these
numbers needs to know which end of the range they came from. The three scoring workers alone
oversubscribe four cores.

**Pin `wasmtime>=46.0.1,<47`.** That is the single external dependency the six admission trees
need, and it is the range the publication lane's closure analysis recorded. The validator itself
still declares zero runtime dependencies; this one belongs to the runtime tree, not to the client.

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

### The full replay, every stage

Both epoch-180 receipts, clean wheel-only install, Base mainnet at block 49518473:

| stage | T0 | T1 |
| --- | --- | --- |
| `discover_release` | PASS | PASS |
| `verify_deployment` | PASS | PASS |
| `receipt_continuity` | PASS | PASS |
| `join_transition` | PASS | PASS |
| `deterministic_admission` | PASS | PASS |
| `historical_law` | PASS | PASS |
| `resolver_snapshot` | PASS | PASS |
| wall clock | 1150 s | 1093 s |

`export` reads UNVERIFIED when no snapshot is supplied to reproduce against — withheld
by design rather than failed, because an export attests to byte-for-byte reproduction
and there is nothing to attest to.

Admission's own summary, verbatim: *"advance replayed from confirmed chain truth: parent
manifest verified, transition applied, new root reproduced, artifact rehashed, every
binding checked, selection re-derived AND proven complete, candidate executed in the
pinned sandbox whose networkless execution was DEMONSTRATED (not asserted) by a real
socket probe, and the frozen law confirms it beat the exact parent incumbent."*

### Sandbox import isolation

The child's `sys.path` is **built, not filtered** — an allow-list, so the failure
direction is toward refusing an import:

* **allowed** — the pinned admission trees, plus the stdlib and site-packages of the
  verified interpreter (where `pip` put `wasmtime` and every other pinned wheel);
* **refused** — source tree, repository-relative entries, the working directory,
  `PYTHONPATH` injections, the user site directory. All ambient; all dependent on where
  the command was run from.

A blocklist can only remove what somebody remembered to name, and the previous one named
the wrong thing. Proven as a suite by `python/tools/sandbox_isolation_proofs.py` (7/7,
`evidence/sandbox-isolation-proofs.json`): wheel-only install, no source-tree imports,
site-packages admitted, networkless enforced, `socket(2)` → EPERM on both IP families,
`wasmtime` 46.0.1 matching the lock, and removal producing a named error.

**A missing dependency is a FAIL, never a BACKLOG.** `SandboxDependencyError` is
deliberately not a subclass of `SandboxUnavailable`: "this host is not configured" sends
a reader back to our documentation, while "your environment is wrong, here is which
dependency and the remedy" puts the fix where it belongs. Collapsing the second into the
first would have an external agent re-reading our instructions while the actual fix is
one `pip install` on their side.

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

### F11 — CLOSED: the runtime-integration record is published

**Resolved.** `RUNTIME-INTEGRATION.pre-rig.json` is required to rebuild `locks`, and it was not
among the objects published alongside the snapshot. It is now published as root `309cf988…` in the
companion set (commit `df3c2ae`), so a clean public install can rebuild that block too.

### K1 and K2 — two defects publication exposed in this package

Both were found by running the clean public client end to end against the published set. Neither
was a publication problem.

**K1 — the rig's `compactPatchBytes` was fed to a canonical-JSON parser.** `pipeline._admit`
handed the patch to `frontier.parse_transition_bytes`, which decodes UTF-8 and requires canonical
JSON. On real rig data that fails on the first byte (`0xff`), and it reported **FAIL** — a
determination, not a backlog, so it slandered a perfectly valid mine over a decoder mismatch.

This is structural. `compactPatchBytes` is a contract-mandated binary layout that
`RigCoreTexVerifier._validateCompactPatch` reverts on if it is anything else: `patchType`,
`wordCount`, a big-endian `uint64` score delta, `parentStateRoot`, then LEB128-indexed word pairs.
Canonical JSON in that field would have been rejected on chain, so the JSON reading could never
have been right — the memory lane's `transitionBytes` and the rig lane's `compactPatchBytes` are
two different formats and this package was treating one as the other.

`rig_events.decode_compact_patch` implements the verifier's own validation, refusal for refusal.
The LEB128 redundancy rule is the subtle one: `0x82 0x00` and `0x02` both decode to index 2, and
one index with two spellings is one patch with two hashes — which breaks the `patchHash` binding
outright. `_admit` now decodes under the contract's layout, cross-checks the patch against the
signed receipt (parent root, score delta, and that a word carries the `artifactHash`), and takes
the memory-lane JSON transition from the fetched artifact — safe precisely because the patch binds
it.

**K2 — the sandbox child deleted `site-packages` in a wheel install.** The child templates scrubbed
`_PKG_PARENT` from `sys.path` to keep this lane's `frontier` from shadowing `benchmark-v2`'s. In a
source checkout that removes the repo; in a **pip-installed** client `_PKG_PARENT` *is*
`site-packages`, so the child deleted the entire third-party import path and the runtime tree lost
`wasmtime` — meaning the pinned sandbox could never become available on exactly the installation
this package certifies. They now scrub only the package directory, which is the sole path that
could make this lane's modules resolve as top-level names. In a source checkout the parent holds a
package rather than a top-level `frontier`, so removing it was never useful there either.

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

§4 and §5 supersede the two bullets this section used to open with: two real rehearsal
transitions on Base mainnet (T0 and T1, epoch 180) have now been replayed end to end, all
eight steps, from a clean wheel-only install (F4 closed at `8ca6015`, both K1 and K2 fixed;
full stage table at `356f2ee`). What is listed below is what that work did **not** establish.

* **Production authority.** Nothing reproduced here has `production_authority: true`, and
  nothing ever will by accident: `release.py` refuses a release that declares
  `MAINNET_CANONICAL` by name, and `export.build_export` cannot emit that classification
  either. Every address, every deployment and the one signature that was ever checked
  (`0xd1446157…`, labelled `REHEARSAL_TEST_ONLY` in the release document) belong to the
  rehearsal deployment. A production genesis, production contract addresses and a production
  signing key do not exist yet, so there is nothing to run any of this against beyond what
  §4/§5 already cover.
* **Independent review of the rig contract source** (F5, unchanged by any of the above).
  `github.com/botcoinmoney/botcoin-mining-rigs` at `cdb91d21…` is still not publicly
  fetchable. The *deployment* is verifiable without it — bytecode is checked against the
  release artifact's recorded runtime hashes — but the event signatures, tuple layouts and
  typehashes this package transcribes from that source remain uncheckable by an outside
  reviewer against the original.
* **Bytecode reproduction from source** — deliberately out of scope; the release is the
  deployment authority, and reproducing a build would need a pinned solc, settings and
  dependency tree this package does not carry.
* **The /v2 resolver-snapshot `authority` block, independently.** `/v1` and `/v2` are both
  implemented and discriminated on the declared schema id, never guessed (`70a2055`); epoch
  180 is `/v1` and its reproduction (§4) is unaffected by any of this. But no real `/v2`
  artifact has ever been published, so `/v2`'s `authority` block is currently **adopted**
  from whatever payload is handed in — a schema constant that matches by construction,
  reported under `adopted_blocks` rather than counted as reproduced evidence — instead of
  independently re-derived the way every chain-derived key is. That stays open until a real
  `/v2` snapshot exists to test the block against.

One thing that is explicitly **no longer** on this list: a resolver signature over the
payload. That check was removed from the acceptance path by operator directive (`72c03b7`)
— reconstruction equality against chain truth is the whole of what a clean install now
verifies, so "no real resolver signature" describes a ceremony this package no longer
performs, not a gap in what it proves.

---

## 7. Protocol correction: `coretex.transition-descriptor/v2` (2026-08-06)

**The word-diff era is retired, pre-production.** Nothing in §§1-6 above describes a live
deployment — the rehearsal legs proven there were, and remain, run against the retired 4-word
compact patch (`patchType`/`wordCount`/LEB128 word indices, `coretex-patch-hash-v1`). That model
never reached a production deployment: it is superseded in full, before any production key or
production address existed, by `coretex.transition-descriptor/v2`
(`botcoin-mining-rigs docs/CORETEX-TRANSITION-DESCRIPTOR-V2.md` @
`ba4d5acfa7aa3042f39eb6e8e4d8e4007400090c`, mirrored from the migrated coordinator
`botcoin-coordinator-v5` @ `167444f`). This section is the operator-facing record of what changed
in this repo and why, alongside `specs/patch_format.md`'s technical rewrite.

**What moved.**

* `compactPatchBytes` is now a **fixed 105-byte commitment** — `version (1) ‖ patchArtifactHash
  (32) ‖ parentStateRoot (32) ‖ newStateRoot (32) ‖ scoreDeltaPpm (8)` — not a variable-length
  parsed word-diff struct. The edit itself is a separately fetched, sha256-addressed **canonical
  patch artifact**; the chain commits and orders, it never stores or interprets.
* **New typehash**: signed member 20 renames `uint16 stateWordCount` → `uint16
  transitionFormatVersion` (same slot, same width — the zero-extension of the descriptor's version
  byte, not a count of anything). `RigCoreTexReceipt`'s typehash moves from
  `0x1cb41d15e03f32744933332c24f5fe35eb76fdc99cbdc02c432aad682c67973b` to
  `0x70419dc57753cec023e5ca1563c9eb5858d96ddb82144f3c9e6d40e8f334b2cf`. Re-derived independently
  from the member list with this repo's own `keccak256` implementation and pinned in
  `python/tests/test_rig_lane.py::TestRigReceiptTypehashV2`, not merely transcribed.
* **New hash label**: `patchHash = keccak256("coretex-transition-descriptor-v2" ‖
  compactPatchBytes)`. Both prior labels — `coretex-patch-hash-v1` (this lane's own retired
  4-word rule) and `coretex-memory-transition-hash-v1` (the V5 memory lane's, and F3's finding
  above) — are REFUSED, never silently accepted; `rig_events.py` names which dead label a
  mismatched hash actually matches, the same "superseded label" idiom the retired decoder used.
* **New bundle hash**: `rig_receipt_binding.py`'s `BUNDLE_SHA256` moves to
  `307df364b165023b20ec1ea9ac699b8b39a5f340040be9a418b1a7d1d50b2c5a`. The real generation tool
  (`scripts/generate-rig-receipt-bindings.mjs`) and a v2 ABI bundle are not vendored in this repo,
  so this file's values were hand-transcribed from the migrated coordinator's mirrored binding and
  independently re-derivation-checked (see the file's own header note); it should be regenerated
  for real once a v2 bundle is available.
* The registry event/mutator field renames the same way: `wordCount` → `transitionFormatVersion`
  in `CoreTexStateAdvanced` and `submitStateAdvance`. Neither the event topic0
  (`2f0a8989…`) nor the mutator selector (`0xa2d87e1d`) changes — Solidity signatures are built
  from types, not names, so a positional/ABI-type decoder is unaffected; a name-keyed reader is
  the thing this rename is meant to break loudly.
* Off-chain, fail-closed availability is now load-bearing for the rig lane specifically:
  `pipeline.py`'s step-5 admission and `chain_first.py`'s rig join both fetch the canonical patch
  artifact by `patchArtifactHash`, re-hash it (`pub.fetch_json(..., hash_rule=
  pub.HASH_RULE_FRONTIER_JSON, ...)` — the same sha256-canonical-JSON rule every other
  content-addressed object in this repo uses), and only then feed its `transition` into the
  existing deterministic replay (`replay.replay_advance`, unchanged). An unpublished or
  substituted patch artifact is refused before replay is ever reached.

**Epoch-180 evidence remains valid, as legacy-era history, under the old rules only.** The two
real epoch-180 mainnet-rehearsal advances documented in §4 above are NOT re-read under v2 — their
first byte (`0xff`) is a permanently-burned version, and the whole point of keeping
`rig_events.py::decode_compact_patch` (renamed nowhere, deleted nowhere) is that this repo can
still decode them exactly as it always could. `resolver_schema_constants.py` keeps its
`payload_sha256`/`DISCLOSURE`/`PRIOR` transcription of that real epoch-180 snapshot byte-for-byte;
only the module's *schema description* (the typehash, the hash rule, the `stateWordCount` →
`transitionFormatVersion` join-recipe entry) moves to the v2 values a future real snapshot would
need to match, because there is no v2 mainnet snapshot to transcribe yet. Nothing described in
this section is armed for a live epoch — see the normative spec's own "OFFLINE, PRE-ARM" status
line.

**Test suite**: 600 passed / 8 skipped before this migration → 634 passed / 8 skipped after
(34 new: `TestTransitionDescriptorV2`, `TestTransitionArtifactV2`, `TestRigReceiptTypehashV2`, plus
adversarial additions to the existing rig-lane and chain-first suites). `decode_compact_patch`'s
own adversarial suite (`TestCompactPatchIsBinaryNotJson`) is unchanged in shape and still green —
it tests HISTORY, which does not move.

**Known gap, not silently narrowed.** The normative spec's §8 allows one transition to move an
unbounded number of profile releases and/or the composition root at once (T-3/T-4/T-5). This
repo's `frontier.py` still enforces one profile-release move per transition and is **out of
scope** for this migration (it is not one of the files this pass touches). The canonical-patch-
artifact envelope this repo implements is therefore scoped to the T-1/T-2 shape — depth within one
profile, not breadth across profiles — which is also the only shape any real mainnet rehearsal has
ever produced. Widening `frontier.py` to the full multi-profile artifact is a frontier-law change
for a future pass, tracked here rather than left to be discovered.

**Also out of scope for this pass, flagged rather than silently left stale**:
`src/coordinator/coretex-coordinator-core.ts`, `src/coordinator/retrieval-data-source.ts` and
`test/unit/chain-mirror-solidity-parity.test.mjs` still reference `stateWordCount` and the
word-diff `compactPatchBytes` model. They are TypeScript coordinator-side code, outside this
migration's given scope (the Python validator client), and were not touched.
