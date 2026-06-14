# Hidden Query Pack — Seeded Sampling, Stratification, Escrow

Status: launch-blocking spec. Pinned by bundle hash.

> **Per-patch on-chain randomness update** — production derives gate +
> confirm packs PER PATCH from the per-patch eval seeds. Same sampling +
> stratification rules apply; the seed input is broader (includes
> `blockhash(targetBlock)`, `patchHash`, `parentRoot`, `minerAddress`
> in addition to `epochSecret` + `epochId`). The previous per-epoch seed
> below remains the source for the baseline pack
> (`baselineEvalSeedHex` pinned in the bundle profile), so pre-patch
> baseline scoring stays reproducible from `(bundle, corpus)` alone.

## Scope

The hidden query pack is the set of queries against which the
coordinator scores patches. It is derived deterministically from
either:
  - `(evalSeedPatch, corpusRoot)` — per-patch live-eval packs (gate + confirm)
  - `(epoch, baselineEvalSeed, corpusRoot)` — per-epoch baseline pack at
    calibration / epoch rotation
The seed-reveal (`epochSecret` post-epoch + on-chain `blockhash`)
suffices for any third party to reproduce every pack + score.

## Commit-reveal (epoch secret)

At epoch initialization the coordinator commits

```
epochSecretCommit = keccak256(epochSecret)        # 32 bytes
```

on chain via `CortexState.initializeEpoch(... epochSecretCommit ...)`. The
32-byte `epochSecret` preimage is held by the coordinator (multisig
escrow) until epoch close.

At epoch close the coordinator calls
`CortexState.revealEvalSeed(epochId, epochSecret)`. The contract enforces

```
epochSecret != bytes32(0)
keccak256(epochSecret) == epoch.evalSeedCommit
```

(The contract field is named `evalSeedCommit` for historical reasons;
the preimage is the per-epoch `epochSecret` used to derive both the
per-patch eval seeds and the per-epoch baseline pack seed.)

Once revealed, every per-patch receipt and the per-epoch baseline pack
are independently recomputable from the bundle + epochSecret + corpus
delta history + Base RPC blockhash lookups.

## Sampling rule

Let `eval_hidden` be the lex-sorted-by-id list of corpus records whose
`splitForRecord(id, corpusEpoch) == 'eval_hidden'`. Let `K` be the pack
size (calibration output, pinned in bundle).

The sampling rule is the same for per-patch live eval and the per-epoch
baseline pack — only the seed input differs:

- **Per-patch live eval**: `seed = deriveGateEvalSeed(...)` or
  `deriveConfirmEvalSeed(...)`. The seed input already
  includes `epochId`, so the `epoch` term in the sampling rule below
  is fixed across an epoch's live evals (the seed entropy carries the
  per-patch uniqueness).
- **Per-epoch baseline**: `seed = baselineEvalSeedHex` pinned in the
  bundle profile. Used by `evaluateBaseline` at calibration / epoch
  rotation; the `epoch` term distinguishes baseline samples across
  epochs.

```
sortedEvalHidden = sorted(eval_hidden, key=id)
queryPack(epoch, seed, corpus) =
    [
        sortedEvalHidden[
            uint256(keccak256(seed || epoch || u64(i))) mod len(sortedEvalHidden)
        ]
        for i in [0, K)
    ]
```

After the initial sample, **hardness stratification** rebalances:

```
quotas = bundleProfile.packQuotas    // per family + per difficulty bucket
for stratum in quotas.keys():
    while count(stratum in pack) < quotas[stratum]:
        candidate = sortedEvalHidden[
            uint256(keccak256(evalSeed || epoch || stratum || u64(j))) mod len(sortedEvalHidden)
        ]
        if candidate not in pack and candidate.stratum == stratum:
            replace_lowest_priority_pack_member(candidate)
        j += 1
```

`stratum` keys are deterministic strings such as `family=temporal,bucket=hard`.
Quotas are calibration outputs.

The rule is public. Anyone with `evalSeed` and the bundle reproduces the
exact pack and verifies the per-stratum quota constraint is satisfied.

## Adversarial seed selection

The coordinator commits `evalSeedCommit = keccak256(evalSeed)` before
seeing any epoch traffic. Because the sampling rule is public and
deterministic, the coordinator gains no degree of freedom from the seed
beyond a uniform-random-with-quota-fill sample.

Watchers verify: given the revealed seed, the published pack equals the
deterministic recomputation, and the quota constraints hold.

## Seed escrow

The 32-byte `evalSeed` preimage is stored in a multisig-controlled secret
manager at commit time. The commit transaction is accompanied by an
off-chain signed escrow receipt naming the M-of-N multisig signers and
the storage location.

Loss of the preimage strands the epoch as un-replayable. To bound this
risk:

- `revealGracePeriod` is a calibration output (operational latency-bounded).
- If the epoch closes and `revealEvalSeed` has not been called within
  `revealGracePeriod`, multisig escrow holders are obligated to publish
  the seed. After this deadline, replay watchers alarm and the operator
  playbook is triggered.
- The escrow rule guarantees a worst-case disclosure deadline.

## Coordinator-trust window

Between commit and reveal, only the coordinator can compute scores. This
is a known commit-reveal property. Mitigations:

- Watchers monitor `WorkCreditAccepted` event volume per epoch and per
  miner. Anomalous concentrations trigger pre-reveal alarms.
- The escrow rule guarantees worst-case disclosure deadline.
- After reveal, every signed score is independently recomputable.

## Reference algorithm

```
function deriveQueryPack(epochId, evalSeed, corpusEpoch, corpus, profile):
    sorted = corpus.records
        .filter(r => splitForRecord(r.id, corpusEpoch) == 'eval_hidden')
        .sort_by(r => r.id)

    pack = []
    for i in 0..profile.packSize:
        idx = uint256(keccak256(evalSeed || u64(epochId) || u64(i))) % len(sorted)
        pack.append(sorted[idx])

    for stratum, quota in profile.packQuotas:
        present = count(r in pack if r.stratum == stratum)
        j = 0
        while present < quota:
            idx = uint256(
                keccak256(evalSeed || u64(epochId) || str(stratum) || u64(j))
            ) % len(sorted)
            cand = sorted[idx]
            if cand.stratum == stratum and cand not in pack:
                # replace lowest-priority member (lex-largest stratum hash)
                pack = replace_lowest_priority(pack, cand)
                present += 1
            j += 1

    assert all(quota_satisfied(pack, profile.packQuotas))
    return pack
```

`stratum_of(record)` is deterministic from the record's family and a hardness
bucket derived from the record's synthesizer-category qrels and calibrated
visible-split retrieval difficulty.
