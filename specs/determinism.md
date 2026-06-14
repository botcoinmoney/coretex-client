# Determinism — CPU-Only Inference Contract

Status: launch-blocking spec. Pinned by bundle hash.

## Goal

The reward signal must be reproducible by anyone running the pinned bundle.
fp16 inference and CUDA/MPS kernels are not bitwise reproducible across
hardware. CoreTex therefore commits to CPU-only inference on the canonical
scoring path.

A replay watcher with the bundle, the corpus + delta history, the
revealed `epochSecret`, and Base RPC access reproduces every signed
`scoreAfterPpm` within `replayTolerancePpm`. The canonical input chain
for per-patch eval seeds:

```
evalSeed_{gate|confirm} = keccak256(
  "coretex-eval-v1-{gate|confirm}",
  epochSecret,
  blockhash(receivedAtBlock + targetBlockOffset),
  uint64(epochId),
  patchHash, parentRoot, minerAddress,
  corpusRoot, bundleHash,
)
```

Replay watchers fetch `blockhash(targetBlock)` from a Base RPC archive
(lookback ≥ `replayBlockhashLookbackBlocks` pinned in the bundle's
`baseRpcConfig`). Anti-pre-testing invariant: `deriveGateEvalSeed`
refuses zero-blockhash input — a coordinator who signs a receipt
against an unobserved block fails verification.

## CPU-only contract + BLAS thread pinning

The canonical scoring path (coordinator and watchers) runs both the
bi-encoder and the cross-encoder on CPU only. GPU/accelerated inference
produces non-canonical scores that disagree with the chain.

The bundle profile carries `acceleratorPolicy: 'cpu_only'`. The coordinator
startup assertion refuses to run if any of the following is set:

- `CORETEX_USE_GPU`
- `CUDA_VISIBLE_DEVICES` (set to non-empty)
- `PYTORCH_USE_MPS=1`
- `ONNXRUNTIME_PROVIDERS` containing `CUDAExecutionProvider` or
  `MPSExecutionProvider`

## BLAS thread pinning

`torch.set_num_threads()` controls only torch's intra-op pool. The
underlying BLAS libraries (MKL, OpenBLAS) and numexpr read their
thread counts from environment variables at library-load time, and
a drifting BLAS pool size contributes to the replay-tolerance budget
even when all model bytes match.

The canonical scoring runners (`scripts/bi_encoder_runner.py`,
`scripts/reranker_runner.py`) therefore pin the full BLAS env BEFORE
importing torch:

```
OMP_NUM_THREADS          ← BIENCODER_NUM_THREADS or RERANKER_NUM_THREADS
MKL_NUM_THREADS          ← same
OPENBLAS_NUM_THREADS     ← same
NUMEXPR_NUM_THREADS      ← same
VECLIB_MAXIMUM_THREADS   ← same   (macOS Accelerate framework, harmless on Linux)
```

The propagation uses `os.environ.setdefault` so an explicit override
(e.g. a benchmark sweep) still wins.

## Pinned runtime

The runtime is one of two named pairs (chosen at calibration phase):

### Option A — torch + transformers (CPU build)

```
torch          == X.Y.* (CPU-only build)
transformers   == A.B.*
huggingface_hub== M.N.*
tokenizers     == P.Q.*
```

### Option B — onnxruntime (CPU)

```
onnxruntime    == C.D.* (CPU build, no CUDA EP)
```

The selected option and its versions bind into the bundle manifest as

```
runtimePin: {
  flavor:    'torch-transformers' | 'onnxruntime-cpu'
  versions:  Record<package, semverRange>
  buildFlags: string[]
}
```

The Python binary used by the orchestrator must run inside a venv that
matches `runtimePin.versions` exactly. The coordinator startup assertion
parses `pip freeze` output and refuses to run on mismatch.

## Pinned quantization

Two acceptable quantization schemes (chosen at calibration phase):

### int8 weight, fp32 accumulation

```
quantization: {
  weights:      'int8'
  activations: 'fp32'
  accumulation:'fp32'
  scheme:      'symmetric_per_channel' | 'asymmetric_per_tensor'
}
```

Deterministic across CPUs that follow IEEE 754 (essentially all modern x86/ARM).

### bfloat16 with explicit denormal flush

```
quantization: {
  weights:      'bf16'
  activations: 'bf16'
  accumulation:'fp32'
  flushDenormals: true
}
```

Requires CPU support for bf16. Calibration determines which flavor produces
the tightest cross-host agreement on the calibration sample.

## replayTolerancePpm

`replayTolerancePpm` is the only number that can absorb residual cross-host
score noise. It is computed during the calibration sweep:

```
replayTolerancePpm = ceil( P99(|coordinator_score - watcher_score|) * 1e6 )
```

over the calibration sample, across all configured CPU hardware
configurations (≥ 3). The value is bound into the bundle profile.

A replay watcher with score disagreement larger than `replayTolerancePpm`
alarms.

## Determinism harness

`scripts/determinism-check.mjs` runs both pinned models against a 1k
(query, document) pair sample and emits a CSV:

```
host_id, model, pair_index, score
```

The harness then computes pairwise diffs across runs and emits

```
{
  pairCount: int,
  hostConfigs: [string],
  p50PpmDiff:  int,
  p90PpmDiff:  int,
  p99PpmDiff:  int,
  maxPpmDiff:  int
}
```

The script exits non-zero if `p99PpmDiff > MAX_TOLERANCE_PPM` (5000 ppm
pre-calibration; replaced by the calibrated `replayTolerancePpm` once
pinned).

## Bundle manifest fields

```
manifest.evaluator.profile.acceleratorPolicy = 'cpu_only'
manifest.evaluator.profile.runtimePin        = { ... }
manifest.evaluator.profile.replayTolerancePpm = <calibrated>

manifest.model.biEncoder = {
  provider:    'huggingface',
  modelId:     'BAAI/bge-m3',
  revision:    <pinned commit>,
  mode:        'dense',
  outputDim:   <calibrated>,
  tokenizerRevision: <pinned commit>,
  quantization: { ... },
  files:       [{path, sha256, bytes}, ...]
}

manifest.model.reranker = {
  provider:    'huggingface',
  modelId:     'Qwen/Qwen3-Reranker-0.6B' | 'memreranker/0.6B' | ...,
  revision:    <pinned commit>,
  files:       [{path, sha256, bytes}, ...]
}

manifest.model.labelingReranker = {
  // separately pinned, MUST be different model from .reranker
  provider:    'huggingface',
  modelId:     <stronger reranker>,
  revision:    <pinned commit>,
  files:       [{path, sha256, bytes}, ...]
}
```

## Refusal

The coordinator refuses to start if:

1. `acceleratorPolicy != 'cpu_only'`
2. any GPU env var (above) is set
3. `runtimePin.versions` does not match the installed venv
4. `model.reranker.modelId == model.labelingReranker.modelId`
5. any model revision is `'main'`, `'master'`, `'latest'`, `'head'`,
   `'placeholder'`, `'todo'`, or fails the 40-hex commit-sha shape check
6. on-chain `coreVersionHash != bundleHash`
