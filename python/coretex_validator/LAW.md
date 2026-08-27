# CoreTex benchmark law — fixed-suite, componentwise improvement

Status: GENESIS PUBLIC LAW. This document defines the admission semantics for the first public
CoreTex release and every state improvement admitted under it.

Law-Family-Id: `benchmark-v2-law/dominance-fixed-suite`

The active enforcement descriptor is
`benchmark-v2-law/dominance-fixed-suite.v1`. The family above names these stable normative
semantics; the descriptor and its content-addressed closure name the exact implementation. A normal
mined state improvement changes the canonical frontier, not the law id or `coreVersionHash`.

## 1. Purpose and publicity

CoreTex is a continuously improving, profile-scoped memory-IR adapter. A submission is admitted
only when it proves a strict composite improvement over the exact current parent while regressing
no protected quality objective and no protected resource axis. The same rule holds on both fixed
partitions of the public canonical suite. This creates the invariant that every admitted public
state is componentwise no worse than every ancestor and strictly better in composite score.

The law, canonical cases, generators, scorer, validator, reference implementation, runtime ABI,
resource counter, incumbent implementations, and all admission artifacts are public. Candidate id,
author, submission time, epoch entropy, retry count, and operator identity have no influence on the
exam or verdict.

Benchmark-aware optimization is intended. If a production-visible strategy improves the public
suite without violating an input, provenance, determinism, portability, or resource rule, that is a
valid improvement. Evaluator-only behavior is not:

- reading gold answers, dimension labels, scorer-private metadata, or unavailable filesystem data;
- branching on case ids, seeds, filenames, partitions, evaluation mode, or other evaluator-only
  signals;
- fixed answer tables or reconstruction of gold outputs;
- fabricated provenance, storage, compute, rendered-cost, or portability evidence;
- network access or undeclared dependencies.

If a valid production-visible strategy exposes a weakness in the benchmark, the submission is not
retroactively reclassified. The benchmark may be amended prospectively, with a new enforcement
descriptor and new content roots.

## 2. Profiles and claimed scope

The mineable profiles are:

| Profile | Surface |
|---|---|
| `conv.pref.v1` | Multi-session preferences, aliases, corrections, retractions, temporal state, and selective forgetting. |
| `doc.tool.v1` | Documents and tool results with conflicts, duplication, consolidation, workflow steps, and provenance. |
| `event.schema.v1` | Event histories, exact lookup, joins, temporal state, schema evolution, and heterogeneous records. |

Each profile has its own current release root and exact-parent vector. A submission targets one
profile. Acceptance advances only that profile's release root; every other profile remains exactly
unchanged.

The generators can produce several corpus scales, but revision v1 claims only the `small` stratum
present in `benchmark-v2/validator/CANONICAL-SUITE.v1.json`. No result under this law is evidence
for an unscored scale. Adding or changing a scored case, partition, profile, objective, or scale is
a normative law change and moves the suite and evaluation-law roots.

## 3. Candidate contract and hard gates

Before execution, the candidate commits to its exact module bytes and a closed manifest containing
the target profile, changed hooks, supported input schemas, resource limits, and targeted
objectives. The candidate hash is a content address of those bytes and declarations. Author-lane
metadata is bound into that manifest for attribution, but it is never a case-selection or scoring
input.

Every candidate measurement must pass the complete hard-gate vocabulary:

1. canonical-event integrity;
2. provenance integrity;
3. output validity;
4. zero stale or retracted disclosure;
5. deterministic replay on identical inputs;
6. declared resource limits;
7. the executed host-portability matrix; and
8. the target profile's composite floor.

A missing, malformed, renamed, reduced, non-boolean, or unevaluated gate is a failure. The report's
gate map is validator-owned evidence, never an assertion accepted from the candidate or evaluator.
Gates 2 and 4 are constructive postconditions: the trusted scorer rebuilds candidate references
against the clean canonical store, reapplies servability and validity, and binds the rendered
provenance to the resolved event. An attempted provenance or stale/retracted-disclosure violation
terminates evaluation before a report exists; a completed report therefore records zero for those
two gates. The remaining gates restate measurements recomputed by the validator.

Portability is a prerequisite, not a scoring reward. The exact runtime, ABI, dependency, and wheel
tuple is installed offline and exercised on every required support-matrix cell. That qualification
may be reused only for byte-identical artifacts. Every submission still passes the fast module
load, capability, dependency, network, determinism, and bounded-size checks.

## 3A. Fixed canonical suite and componentwise dominance

### 3A.1 One immutable exam

Each profile has one ordered canonical suite split into `gate` and `confirm`. Every case binds
`profile_id`, `seed`, `scale`, `instance_id`, and the canonical instance hash produced by the public
generator. Both partitions are fixed by the suite document and are identical for every submission.

The suite is never selected from epoch entropy and is never changed by candidate id. Cases are not
burned or redrawn. A receipt that omits, adds, reorders, substitutes, or re-hashes a case is invalid.
The fixed round id and the two fixed public entropy placeholders are inert wire-format constants;
they select nothing.

### 3A.2 Absolute vector

For law `L`, profile `p`, partition `q`, and release `x`, define:

```text
V[L,p,q](x) = (
  composite_ppm,
  quality_i for every objective i declared by p,
  rendered_cost_micro,
  work_fuel,
  logical_durable_storage_bytes
)
```

`composite_ppm = composite_micro // 100`. Composite and every quality objective are higher-is-
better. The three raw resource axes are lower-is-better. All components are exact integers. Wall
clock, host labels, and module-source length are telemetry only and never enter the vector.

The objective vocabulary is closed by the profile registry and mirrored in the suite. An omitted
objective is not an unchanged objective; it is an invalid vector.

### 3A.3 Admission rule

A candidate release `B` may replace exact parent `A` for profile `p` only if, independently on both
`gate` and `confirm`:

1. every hard gate and the profile floor pass;
2. `composite_ppm(B) >= composite_ppm(A) + 1`;
3. `quality_i(B) >= quality_i(A)` for every declared objective `i`;
4. each protected resource of `B` is less than or equal to the corresponding resource of `A`; and
5. `B` also dominates the law-bound genesis floor vector componentwise under the same directions.

There is no tolerance, slack, weighted trade, clause menu, or aggregate offset. Improvement in one
component cannot buy regression in another. The final decision is
`gate.admit AND confirm.admit`. The confirm partition's composite pair supplies the signed
`scoreBeforePpm` and `scoreAfterPpm`; the chain's strict `after > before` check is therefore a
projection of this rule, not a second rule.

The counter-resource aggregate is recomputed and bound for the receipt, but it cannot override the
raw-axis rule. Because every counter weight is non-negative and normalized, per-axis
non-regression implies aggregate non-regression.

### 3A.4 Exact-parent and determinism witness

The coordinator resolves the profile release held by the confirmed parent frontier. The evaluator
executes candidate and exact parent on the identical suite cases. It also receives the parent's
stored qualifying vector from a content-addressed public source:

- for the public genesis release, the content-addressed genesis baseline record; or
- after an accepted improvement, that release's accepting evaluation artifact.

The freshly re-executed parent vector must equal the stored vector byte-for-byte. A mismatch is an
environment or artifact drift refusal; it never adjusts a score and can never make a candidate
pass. The source object must be published and hash-verified before evaluation is enqueued.

### 3A.5 Genesis floor

The suite contains one resolved reference floor vector for each profile and partition. These are
the initial public baseline measurements and are part of the law. A missing or pending floor makes
admission impossible; it is never treated as zero or skipped.

The public genesis frontier maps each profile to the exact reference release measured by its floor.
The genesis baseline record binds that mapping, the suite root, and all floor vectors. Thus the
first candidate compares against exactly the release and numbers declared by this law.

### 3A.6 Transitive no-regression invariant

Let `G` be a profile's genesis vector and let `R0, R1, ... Rn` be its admitted releases. By rule,
`R0` dominates `G`; each `Rk+1` strictly improves composite and is componentwise no worse than
`Rk`; and every parent is reproduced by its determinism witness. Componentwise order is transitive,
so every `Rn` dominates `G` and every predecessor on both partitions.

Retrying identical bytes cannot change the suite, parent, vector, or verdict. Candidate ids and
epochs are metadata and therefore cannot create an evaluation lottery.

### 3A.7 Scope and limitations

This law proves monotonic componentwise improvement on the committed public suite and only on that
suite. It does not by itself prove performance on unscored scales or a different workload.

The candidate cannot read evaluator-only labels or metadata, and every behavior available to it in
evaluation must also be available through the production ABI. These constraints make improvements
meaningful adapter behavior rather than a privileged test path. Still, public cases can reveal gaps
in benchmark coverage. Such a gap is repaired prospectively by improving the benchmark, not by
randomizing retries or retroactively rejecting a valid result.

## 4. Measurement and resource authority

The deterministic scorer evaluates finalized consumer-visible renders. Raw measurements and their
meaning are bound into the report:

- utility objectives and composite use exact micro units;
- rendered cost is the finalized rendered-cost counter;
- work is trusted host `work_fuel`, not a candidate-reported duration;
- durable storage is the logical canonical-store byte count under
  `logical-durable-storage.cbor.v1`;
- operational latency is derived telemetry, never wall-clock consensus.

The candidate and parent run with the same case selection, runtime identity, scorer, renderer,
counter law, and resource policy. Every report restatement—declared limits, gate resource map,
storage meter, policy label, replay scope, compute figure, and latency figure—is recomputed from the
authoritative raw values before mint and again before signing.

## 5. Evaluation, minting, and public replay

The sole live evaluation job format is `eval.candidate.v2`:

1. validate the candidate content address and manifest;
2. resolve and hash-verify the exact current parent frontier and its stored vector;
3. load the fixed canonical suite for the target profile;
4. execute candidate and exact parent on both partitions in the sandbox;
5. recompute all hard gates, absolute vectors, both dominance decisions, and the final decision;
6. require the parent execution to reproduce its stored vector exactly;
7. mint a content-addressed evaluation artifact and publish every referenced object;
8. have the coordinator re-fetch and canonically verify the complete served artifact graph,
   independently re-execute the candidate and exact parent on the fixed suite, mirror the sealed
   decision, re-read chain policy and parent state, and sign only if every result agrees; and
9. allow any validator to reproduce the result from public bytes.

No evaluation secret or secret opening travels to the worker. The mining epoch secret may continue
to serve unrelated on-chain work and bonus mechanics; it has no role in suite selection or
admission.

A validator fails closed on unknown law, suite, scorer, renderer, counter, runtime, ABI, schema,
artifact format, missing object, mismatched content address, stale parent, non-reproducible vector,
or policy drift. Unavailable public evidence is backlog, never pass.

## 6. Frontier advancement

An accepted artifact authorizes one transition from the exact confirmed parent frontier. The
transition changes only the targeted profile's release root and the resulting composition root.
Every other profile, the law roots, runtime ABI root, compatibility-lock root, and `coreVersionHash`
remain unchanged during ordinary mining.

The coordinator signs only after a fresh chain read confirms the epoch context, current parent
root, work-policy version/hash, rig receipt cursor/head, and all other receipt inputs. Chain compare-
and-swap rejects a stale parent. A miner must use the rig's existing on-chain receipt cursor and
head; public CoreTex genesis does not reset the rig's economic or receipt history.

## 7. Public genesis and economic continuity

The first public release is release sequence `1`, predecessor `null`.

The existing mining, verifier, registry, rig NFT, token, access, reward, and settlement contracts
are reused so rigs, receipt cursors, credits, balances, NFT age/mass, policy schedules, claims, and
settlement state continue normally. At the declared public activation epoch, the authorized
context setter installs the release's genesis frontier root and `coreVersionHash` for that clean
epoch before the epoch commit. CoreTex roots, transitions, patch deduplication, difficulty, and
credits are epoch-keyed, so public evaluation begins from the genesis frontier without chaining
from private test roots.

Public resolvers and clients use that activation epoch and confirmed block as hard lower bounds.
The activation record therefore defines the complete public event namespace.

The on-chain CoreTex work-policy `rulesVersion` is an independent, dynamically read contract
identity. Product version `1.0.0` and law revision `.v1` never replace or renumber it.

## 8. Identity and change discipline

`benchmark_law_root` is the SHA-256 of these exact bytes. The canonical suite, evaluation
descriptor, scorer, renderer, counter law, runtime, ABI, schemas, and artifacts are independently
content-addressed and closed by `coretex.compatibility-lock/v1`. The compatibility-lock `v1` is a
format identifier, not a release sequence; `coreVersionHash` is its canonical lock root.

The release identity is the closed content graph rooted at `RELEASE.json`; public immutability
begins when that release is published.

After launch, a normal admitted memory improvement advances state under this same law. A change to
the exam, decision semantics, measured vector, hard gates, runtime ABI, scorer, renderer, counter,
or another admission-critical component requires a new content-addressed release and prospective
activation. No released receipt or state is reinterpreted retroactively.
