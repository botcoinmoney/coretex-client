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
only when it proves strict progress over the exact current parent inside a fixed law-owned product
cap: either a quality-composite gain with no quality-axis drop and resources inside the cap, or an
efficiency gain that holds every quality axis and strictly reduces at least one measured resource
without raising another. The same rule holds on both fixed partitions of the public canonical
suite. This creates the invariant that every admitted public state is quality-componentwise no
worse than every ancestor, never spends outside the product budget, and strictly advances on one
progress class.

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

### 3A.2 Absolute vector (Q / R / E)

For law `L`, profile `p`, partition `q`, and release `x`, the stored vector is:

```text
V[L,p,q](x) = (Q, R, E, suite_block_id)

Q = (
  composite_ppm,                          # higher-is-better; IR score
  quality_i for every objective i declared by p
)

R = (
  rendered_cost_micro,                    # lower-is-better
  work_fuel,                              # lower-is-better
  logical_durable_storage_bytes           # lower-is-better
)

E = (
  envelope_rendered_cost_micro,
  envelope_work_fuel,
  envelope_logical_durable_storage_bytes
)
```

`composite_ppm = composite_micro // 100`. Composite is the mean of quality objectives only; it is
never mixed with resource axes. All components are exact integers. Wall clock, host labels,
module-source length, candidate `hook_fuel`, and `hook_compute_fuel` are telemetry only and never
enter the vector or the admission rule.

`R` is measured. The existing serialized `E` fields carry `C`, the fixed law-owned product cap;
they are not a re-measurement and not the kit file `RESOURCE_ENVELOPE.json` (those are much larger
declared submission ceilings for hard gate 6). For a profile and partition, every valid parent and
candidate must carry the exact cap sealed by the canonical suite: `E(A) = E(B) = C`.

`suite_block_id` identifies which append-only suite block the vector was measured on. Genesis
public law ships block `0` only. See §3A.7.

The objective vocabulary is closed by the profile registry and mirrored in the suite. An omitted
objective is not an unchanged objective; it is an invalid vector.

#### Fixed product caps (law constants)

Genesis `Q` and `R` are the sealed floor measurements already in this suite. `C` is a separate,
explicit product SLO: it is not computed from a candidate and is not automatically equal to or a
fixed additive offset from genesis `R`. The values below are rounded operational ceilings that
leave approximately 24–29% reserve above each measured genesis axis while remaining far below the
kit's hard-gate-6 submission ceilings. Gate and confirm are independently budgeted because they
execute different case sets.

The exact 18 integers serialized in the suite's floor-vector `envelope_*` fields are:

| profile | partition | C rendered cost micro | C work fuel | C logical durable storage bytes |
|---|---|---:|---:|---:|
| `conv.pref.v1` | gate | 140000000 | 1800000 | 700000 |
| `conv.pref.v1` | confirm | 140000000 | 3600000 | 700000 |
| `doc.tool.v1` | gate | 280000000 | 2600000 | 3200000 |
| `doc.tool.v1` | confirm | 275000000 | 5000000 | 3200000 |
| `event.schema.v1` | gate | 180000000 | 2500000 | 2000000 |
| `event.schema.v1` | confirm | 180000000 | 5000000 | 2000000 |

These are permanence constants for suite block 0. Repeated efficiency wins do not change them; a
later quality win may use saved capacity up to them. Calibration inputs, measured margins, and
quality-spend evidence are recorded with the release evidence rather than inferred from these
rounded numbers.

### 3A.3 Admission rule

A candidate release `B` may replace exact parent `A` for profile `p` only if **both** `gate` and
`confirm` independently satisfy `gate_admit` / `confirm_admit` below. Final decision:
`admit = gate.admit AND confirm.admit`. Each partition must satisfy progress class (4a) or (4b);
the two partitions need not share a class. The signed receipt projection uses the **confirm**
partition's class and `admission_gain_ppm`.

On each partition:

1. every hard gate and the profile composite floor pass;
2. `quality_i(B) >= quality_i(A)` for every declared objective `i`, and `Q(B)` dominates the
   genesis **quality** floor (composite and every objective; resources are not compared to
   genesis `R`);
3. `R_j(B) <= C_j` for every protected resource axis `j`;
4. strict progress, exactly one winning class (if both (4a) and (4b) hold, the class is
   **quality**):
   - **(4a) Quality advance:** `composite_ppm(B) >= composite_ppm(A) + 1`. Resources may rise
     versus `R(A)` as long as they stay `<= C`.
   - **(4b) Efficiency advance:** `composite_ppm(B) >= composite_ppm(A)` (quality composite
     must not fall; it need not rise). Every `R_j(B) <= R_j(A)` and at least one
     `R_j(B) < R_j(A)`. Quality still (2). Independent rounding of composite vs the
     per-objective scores cannot buy an efficiency admit.
5. The serialized cap is exact and constant: parent `E(A)`, candidate `E(B)`, and the canonical
   suite's `C` must be byte-equal on all three axes. A forged tighter or looser envelope fails
   closed; no measurement or transition derives a new cap.

There is no tolerance, slack, weighted quality/resource mix, 0.1% efficiency noise floor, or
aggregate offset that can buy a quality drop. One-unit resource wins are valid; salami slicing is
a reward/pricing issue, not an admission floor. Improvement in one quality objective cannot buy
regression in another. Equal quality with equal resources is not progress.

Hook fuel remains diagnostic (`seam.py` `_candidate_resource_axes`). Wall-clock remains
telemetry.

#### Transition-local receipt projection (no Solidity change)

The deployed verifier requires `scoreAfterPpm > scoreBeforePpm` with both `<= 1_000_000`. Mapping
cumulative quality or a quality/efficiency mix onto that pair would hit the cap and would lie
about IR quality. Real `Q`/`R`/`E` live on the artifact. The signed pair is **transition-local**:

```text
scoreBeforePpm = 0
scoreAfterPpm  = admission_gain_ppm     # in [1, 1_000_000]
```

`admission_gain_ppm` is recomputed from the sealed confirm verdict, never caller-supplied:

- quality class: confirm `composite_gain_ppm` (already ≥ 1), capped at `1_000_000`;
- efficiency class: let `Δ_j = R_j(A) - R_j(B)` for each protected axis. For every `j` with
  `Δ_j > 0` and `R_j(A) > 0`, `axis_ppm_j = floor(Δ_j * 1_000_000 / R_j(A))`. Then
  `efficiency_gain_ppm = max(1, min(1_000_000, max_j axis_ppm_j))`. If `R_j(A) = 0` and `Δ_j > 0`
  the axis contributes `1_000_000`. There is no 0.1% floor: a one-unit win that floors to 0 ppm
  still admits at `1`.

Exact-parent sequencing remains `parentStateRoot` / `newStateRoot`. Visualizer and `/status`
display artifact `Q`/`R`/`E` and progress class; receipt scores are **admission gain
(compatibility)**, never utility.

The counter-resource aggregate is still recomputed and bound. On an efficiency admit it remains a
theorem that `resource_after_ppm <= resource_before_ppm = 1_000_000`. On a quality admit,
measured `R` may rise versus the parent inside `C`, so the aggregate may exceed `1_000_000`; that
does not override clause 3.

### 3A.4 Exact-parent and determinism witness

The coordinator resolves the profile release held by the confirmed parent frontier. The evaluator
executes candidate and exact parent on the identical suite cases. It also receives the parent's
stored qualifying vector from a content-addressed public source:

- for the public genesis release, the content-addressed genesis baseline record; or
- after an accepted improvement, that release's accepting evaluation artifact.

The freshly re-executed parent **measured** `Q` and `R` must equal the stored measured fields
byte-for-byte. Stored `E` is not re-measured: it must equal the canonical suite's fixed `C`, while
`suite_block_id` is carried unchanged. A measured mismatch is an environment or artifact drift
refusal; it never adjusts a score and can never make a candidate pass. The source object must be
published and hash-verified before evaluation is enqueued. Tampering with stored `E` changes
`witness_root` and also fails the exact-cap check.

### 3A.5 Genesis floor

The suite contains one resolved reference floor vector for each profile and partition, including
genesis `Q`, measured genesis `R`, law-owned fixed `C` serialized as `E`, and
`suite_block_id = 0`. These are part of the law. A missing or pending floor makes admission
impossible; it is never treated as zero or skipped. Quality floor checks compare `Q` only.
Resource checks compare `R(B)` to fixed `C`, not to genesis or parent `R` (except that the
efficiency class separately compares candidate `R` to exact-parent `R`).

The public genesis frontier maps each profile to the exact reference release measured by its floor.
The genesis baseline record binds that mapping, the suite root, and all floor vectors. Thus the
first candidate compares against exactly the release and numbers declared by this law. The first
parent stored vector is that floor, so `E(A) = C` at genesis; every later accepting artifact keeps
the same cap.

### 3A.6 Transitive no-regression invariant

Let `G` be a profile's genesis quality floor and `C` its fixed product cap. Let `R0, R1, ... Rn`
be admitted releases. By rule, every `Rk` dominates `G` on quality and every measured resource is
`<= C`; each step is a quality advance or an efficiency advance; and every parent is reproduced by
its determinism witness. Quality componentwise order is transitive. Resource order versus an
ancestor is not: a quality admit may use more capacity than its parent, up to `C`. A same-quality
successor cannot give back an efficiency win because it must compare componentwise against the
exact parent `R`; a later genuine quality win may reuse that saved capacity.

Retrying identical bytes cannot change the suite, parent, vector, or verdict. Candidate ids and
epochs are metadata and therefore cannot create an evaluation lottery.

### 3A.7 Suite blocks

The v1 case list is suite **block 0** and never edits. This document's `profiles.{id}.{gate,confirm}`
arrays ARE block 0. The top-level `suite_blocks` field records that fact so a later law revision
can append block `1+` without rewriting v1.

GA ships one block. Each block keeps its own `Q`/`R`/`C` (serialized in `E`). Gains on a new block cannot offset a
regression on an old block. A stored vector carries `suite_block_id = 0` until a later revision
exists. CoreTex 1.0.0 implements only block 0; the text above does not implement or bundle a future
block.

### 3A.8 Scope and limitations

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

The initial contract pays a flat outcome/difficulty reward; it does not price the artifact's gain
magnitude or `scoreAfterPpm`. Under a fixed cap, a quality release may spend capacity and a later
efficiency release may earn another flat payment by removing that cost, so repeated quality/spend
and efficiency/save transitions can create an efficiency-reward annuity. CoreTex 1.0.0 explicitly
accepts that economic limitation for the initial cut with the operational ability to suspend
intake. It is not repaired by shrinking `C`: admission remains safe because `Q` is componentwise
monotone and all `R` stays inside `C`. Magnitude pricing requires separate verifier/contract work
and gameability analysis.

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
