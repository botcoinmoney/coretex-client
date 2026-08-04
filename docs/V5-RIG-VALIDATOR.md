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

## 4. What is still unproven

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
