#!/usr/bin/env python3
"""CPU-only reranker subprocess runner with one-shot and streaming modes.

Used for both:
    - production reranker (Qwen/Qwen3-Reranker-0.6B) on the inference path
    - labeling reranker (e.g. IAAR-Shanghai/MemReranker-4B) on the corpus
      generation / qrel path

Both share the same chat-template + logit(yes) - logit(no) sigmoid scoring;
the prompt template here is CANONICAL and is mirrored byte-for-byte by
eval/reranker.ts:renderQwenRerankerPrompt (golden parity test:
test/unit/qwen-prompt-template-golden.test.mjs).

Modes:

ONE-SHOT (default): reads one JSON request from stdin and emits scores on
stdout, then exits. Same wire format used by the existing per-batch spawn
caller in reranker.ts. Preserved for backward compatibility.

PRINT-PROMPT-TEMPLATE (--print-prompt-template): renders the canonical
template for a fixed probe (query, document) pair plus the resolved
CORETEX_RERANKER_INSTRUCTION and exits. No ML imports — usable as a golden
oracle so the TypeScript renderer can be asserted byte-identical.

HEALTH (--health): emits the runtime fingerprint as one JSON object on
stdout and exits — torch / transformers versions, python version, and
whether CUDA is active (CORETEX_RERANKER_ALLOW_CUDA=1 + torch.cuda
available) with the device name + fp32 / tf32=false math flags. The
keyless GPU scorer server calls this once at boot to populate scorerHealth.

STREAM (--stream): loads the pinned model once, then reads NDJSON requests
from stdin and writes NDJSON responses to stdout until EOF. Required for
launch-scale corpus generation: a 4B reranker takes 30-60s to load on CPU,
so per-batch spawn is unusable past a few hundred pairs. Pin is supplied
via env CORETEX_RERANKER_STREAM_MODEL_ID and CORETEX_RERANKER_STREAM_REVISION.

CPU-only enforcement (both modes):
    - CUDA / MPS / ONNXRUNTIME GPU providers refused before torch import
    - aborts if torch.cuda.is_available() or MPS detected
    - torch threads pinned to RERANKER_NUM_THREADS (default = available cores)
    - BLAS thread counts (OMP/MKL/OPENBLAS/NUMEXPR/VECLIB) propagated
      from RERANKER_NUM_THREADS BEFORE torch import so the BLAS pool
      doesn't drift across hosts (replay tolerance hardening)
    - tokenizer truncation to RERANKER_MAX_SEQ_LEN (default 2048)

Wire format:

ONE-SHOT request:
    { "model": "...", "revision": "...", "pairs": [
      { "query": "...", "document": "...", "prompt": "..." }, ... ] }
ONE-SHOT response:
    { "scores": [ <float in [0,1]>, ... ] }

STREAM ready signal (emitted once after model load):
    { "ready": true, "modelId": "...", "revision": "..." }
STREAM request line:
    { "id": <int>, "pairs": [ { "prompt": "..." }, ... ] }
STREAM response line:
    { "id": <int>, "scores": [ ... ] }   or   { "id": <int>, "error": "..." }
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from typing import Any, List

# CPU-only enforcement BEFORE any ML imports.
#
# A narrow calibration-only escape hatch exists: CORETEX_RERANKER_ALLOW_CUDA=1
# lets the runner load the model on CUDA for offline calibration sweeps where
# CPU throughput is infeasible (e.g. Qwen3-0.6B at ~1 pair/sec on 16-core CPU
# would take 40+ hours for a full Run 0..4 + variance pack). This is NOT a
# production path: the bundle profile pins acceleratorPolicy='cpu_only' and
# assertBundleBindingAtStartup still refuses to start any production binary
# with CUDA visible. Calibration outputs produced under this flag MUST be
# validated against the CPU path (smoke parity check) before any value is
# pinned into a signed bundle, and the calibration report SHOULD note that
# the values were GPU-accelerated.
_ALLOW_CUDA = os.environ.get("CORETEX_RERANKER_ALLOW_CUDA") == "1"
if not _ALLOW_CUDA:
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
os.environ.setdefault("ONNXRUNTIME_PROVIDERS", "CPUExecutionProvider")
if os.environ.get("CORETEX_USE_GPU") == "1":
    print(json.dumps({"error": "CORETEX_USE_GPU=1 not allowed"}), file=sys.stdout)
    sys.exit(2)
if os.environ.get("PYTORCH_USE_MPS") == "1":
    print(json.dumps({"error": "PYTORCH_USE_MPS=1 not allowed"}), file=sys.stdout)
    sys.exit(2)

# Pin BLAS thread counts BEFORE torch is imported. torch.set_num_threads()
# only controls torch's intra-op pool — the underlying BLAS libraries
# (MKL, OpenBLAS) and numexpr read their thread counts from env at
# library-load time, and a drifting BLAS pool contributes to replay
# tolerance budget. We propagate RERANKER_NUM_THREADS to all of them
# so determinism is reproducible across hosts. Match the canonical
# scoring-path env block in scripts/orchestrate-cpu-calibration.sh.
_blas_threads = os.environ.get("RERANKER_NUM_THREADS", str(os.cpu_count() or 1))
for _v in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS",
           "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    os.environ.setdefault(_v, _blas_threads)


def fail(msg: str, code: int = 1) -> None:
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(code)


# CANONICAL prompt-template constants. Mirrored byte-for-byte by
# eval/reranker.ts (QWEN_RERANKER_DEFAULT_INSTRUCTION /
# QWEN_RERANKER_PROMPT_PROBE / renderQwenRerankerPrompt) — do NOT change one
# side without the other; the golden parity test fails on any drift.
QWEN_RERANKER_DEFAULT_INSTRUCTION = (
    "Given a web search query, retrieve relevant passages that answer the query"
)
PROMPT_PROBE_QUERY = "coretex prompt-template probe query"
PROMPT_PROBE_DOCUMENT = "coretex prompt-template probe document"


def _resolve_instruction() -> str:
    return os.environ.get("CORETEX_RERANKER_INSTRUCTION", QWEN_RERANKER_DEFAULT_INSTRUCTION)


def _build_qwen3_prompt(query: str, document: str) -> str:
    # Match the Qwen3-Reranker model-card template so score calibration is
    # consistent with upstream yes/no relevance guidance.
    instruction = _resolve_instruction()
    return (
        "<|im_start|>system\n"
        "Judge whether the Document meets the requirements based on the Query and the Instruct provided. "
        "Note that the answer can only be \"yes\" or \"no\"."
        "<|im_end|>\n"
        "<|im_start|>user\n"
        f"<Instruct>: {instruction}\n<Query>: {query}\n<Document>: {document}"
        "<|im_end|>\n"
        "<|im_start|>assistant\n"
        "<think>\n\n</think>\n\n"
    )


def _load_model(model_id: str, revision: str):
    try:
        import torch  # type: ignore
        from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
    except Exception as exc:
        fail(
            "missing Python dependencies for reranker: install torch and transformers; "
            + str(exc)
        )
    use_cuda = _ALLOW_CUDA and torch.cuda.is_available()
    if torch.cuda.is_available() and not _ALLOW_CUDA:
        fail("torch detected CUDA; refuse to run on canonical scoring path "
             "(set CORETEX_RERANKER_ALLOW_CUDA=1 to enable for calibration only)")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        fail("torch detected MPS; refuse to run on canonical scoring path")

    num_threads = int(os.environ.get("RERANKER_NUM_THREADS", str(os.cpu_count() or 1)))
    torch.set_num_threads(num_threads)
    torch.set_num_interop_threads(1)

    if use_cuda:
        # Deterministic GPU math for calibration: matmul kept in fp32 so
        # composite scores stay within replay tolerance vs the CPU fp32
        # canonical path. cuDNN benchmark off for repeatability.
        torch.backends.cudnn.benchmark = False
        torch.backends.cudnn.deterministic = True
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
        print(json.dumps({
            "warning": "CUDA mode (CORETEX_RERANKER_ALLOW_CUDA=1)",
            "device": torch.cuda.get_device_name(0),
            "dtype": "fp32",
            "tf32": False,
        }), file=sys.stderr)

    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        revision=revision,
        trust_remote_code=True,
        torch_dtype=torch.float32,
    )
    # Memory-IR shadow-epoch: optionally load a LoRA adapter (E1) ON TOP of the frozen base (E0).
    # Default unset → base model unchanged. Used by the full-benchmark E0-vs-E1 comparison (step 5).
    _adapter_dir = os.environ.get("CORETEX_RERANKER_ADAPTER_DIR")
    if _adapter_dir:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, _adapter_dir)
        print(json.dumps({"adapter": _adapter_dir}), file=sys.stderr)
    model.to("cuda" if use_cuda else "cpu")
    model.eval()

    yes_id = tokenizer.convert_tokens_to_ids("yes")
    no_id = tokenizer.convert_tokens_to_ids("no")
    if yes_id is None or no_id is None or yes_id < 0 or no_id < 0:
        fail("could not resolve yes/no token ids")
    return torch, tokenizer, model, yes_id, no_id


def _split_base_and_head(model):
    """Return (transformer_body, lm_head) so we can read the last-real-token
    hidden state and project ONLY that position through the head, instead of
    materializing [batch, seq, vocab] logits and discarding all but two
    numbers at one position. Qwen3's vocab is ~152k against a 1024 hidden, so
    the full-position vocab projection is a large fraction of each forward and
    scales linearly with sequence length (HF exposes `logits_to_keep` for the
    same reason). Unwraps a PEFT adapter wrapper if present. Returns
    (None, None) when the layout isn't the expected ForCausalLM(body, lm_head)
    so the caller falls back to the full-logits path (bit-for-bit unchanged)."""
    inner = model.get_base_model() if hasattr(model, "get_base_model") else model
    body = getattr(inner, "model", None)
    head = getattr(inner, "lm_head", None)
    if body is not None and head is not None and callable(head):
        return body, head
    return None, None


def _score_pairs(torch, tokenizer, model, yes_id: int, no_id: int, prompts: "List[str]") -> "List[float]":
    """Batched padded forward pass for chat-template rerankers.

    For each prompt we read logits at the actual last non-pad position of
    that sequence (computed via attention_mask.sum() - 1). This makes the
    batched score per pair invariant to batch composition: padding tokens
    on the right don't contribute logits at the position we read, and the
    attention mask prevents non-padded tokens from attending to pads.

    Fast path (default): run the transformer body once, gather the
    last-real-token hidden state per sequence, and project ONLY those
    positions through lm_head. This reads the exact same hidden vector at
    the exact same position that the full-logits path reads, so the yes/no
    logits — and therefore every score — are numerically identical, with
    none of the wasted [seq-1] * vocab output projection. Set
    CORETEX_RERANKER_FULL_LOGITS=1 to force the legacy full-logits path
    (used by the parity harness to prove equivalence).
    """
    max_seq = int(os.environ.get("RERANKER_MAX_SEQ_LEN", "2048"))
    inner_batch = int(os.environ.get("RERANKER_INNER_BATCH", "8"))
    emit_telemetry = os.environ.get("CORETEX_RERANKER_TELEMETRY") == "1"
    force_full_logits = os.environ.get("CORETEX_RERANKER_FULL_LOGITS") == "1"
    scores: List[float] = []
    if not prompts:
        return scores
    # Need a pad token; chat-template reranker tokenizers may not define one
    # by default. Use the EOS token for padding, which is a documented Qwen3
    # convention and does not change the right-padded last-real-token logic.
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    body, head = (None, None) if force_full_logits else _split_base_and_head(model)
    target_device = "cuda" if (_ALLOW_CUDA and torch.cuda.is_available()) else "cpu"
    tok_ms = fwd_ms = proj_ms = 0.0
    seq_lens: List[int] = []

    with torch.no_grad():
        for start in range(0, len(prompts), inner_batch):
            chunk = prompts[start : start + inner_batch]
            t0 = time.perf_counter()
            encoded = tokenizer(
                chunk,
                return_tensors="pt",
                truncation=True,
                max_length=max_seq,
                padding=True,
            )
            encoded = {k: v.to(target_device) for k, v in encoded.items()}
            tok_ms += (time.perf_counter() - t0) * 1000.0
            attn = encoded["attention_mask"]
            # Last real token index per sequence: sum of mask - 1.
            last_idx = attn.sum(dim=1) - 1
            if emit_telemetry:
                seq_lens.extend(int(x) for x in attn.sum(dim=1).tolist())
            batch_n = attn.shape[0]
            rows_idx = torch.arange(batch_n)
            clamped = last_idx.clamp(min=0)

            if body is not None:
                t1 = time.perf_counter()
                hidden = body(**encoded).last_hidden_state  # [batch, seq, hidden]
                fwd_ms += (time.perf_counter() - t1) * 1000.0
                t2 = time.perf_counter()
                gathered = hidden[rows_idx, clamped]  # [batch, hidden]
                rows = head(gathered)  # [batch, vocab] — vocab projection at ONE position/seq
                proj_ms += (time.perf_counter() - t2) * 1000.0
            else:
                t1 = time.perf_counter()
                logits = model(**encoded).logits  # [batch, seq, vocab]
                fwd_ms += (time.perf_counter() - t1) * 1000.0
                rows = logits[rows_idx, clamped]  # [batch, vocab]

            for i in range(batch_n):
                row = rows[i]
                diff = float((row[yes_id] - row[no_id]).detach().cpu())
                score = 1.0 / (1.0 + math.exp(-diff))
                if score < 0.0:
                    score = 0.0
                elif score > 1.0:
                    score = 1.0
                scores.append(score)

    if emit_telemetry and seq_lens:
        srt = sorted(seq_lens)
        n = len(srt)
        total_ms = tok_ms + fwd_ms + proj_ms
        print(json.dumps({
            "telemetry": {
                "pairs": n,
                "path": "last_token" if body is not None else "full_logits",
                "seqLen": {"p50": srt[n // 2], "p95": srt[min(n - 1, (n * 95) // 100)], "max": srt[-1]},
                "tokenizeMs": round(tok_ms, 1),
                "forwardMs": round(fwd_ms, 1),
                "projectionMs": round(proj_ms, 1),
                "pairsPerSec": round(n / (total_ms / 1000.0), 2) if total_ms > 0 else None,
            }
        }), file=sys.stderr, flush=True)
    return scores


def _resolve_prompts(pairs: "List[dict]") -> "List[str]":
    prompts: List[str] = []
    for pair in pairs:
        if "prompt" in pair and pair["prompt"]:
            prompts.append(str(pair["prompt"]))
        else:
            prompts.append(_build_qwen3_prompt(str(pair.get("query", "")), str(pair.get("document", ""))))
    return prompts


def _run_one_shot() -> None:
    raw = sys.stdin.read()
    if not raw:
        fail("empty stdin")
    try:
        payload = json.loads(raw)
    except Exception as e:
        fail(f"invalid stdin JSON: {e}")

    model_id = payload["model"]
    revision = payload["revision"]
    pairs = payload.get("pairs", [])
    torch, tokenizer, model, yes_id, no_id = _load_model(model_id, revision)
    prompts = _resolve_prompts(pairs)
    scores = _score_pairs(torch, tokenizer, model, yes_id, no_id, prompts)
    print(json.dumps({"scores": scores}))


def _run_stream() -> None:
    model_id = os.environ.get("CORETEX_RERANKER_STREAM_MODEL_ID")
    revision = os.environ.get("CORETEX_RERANKER_STREAM_REVISION")
    if not model_id or not revision:
        fail(
            "stream mode requires CORETEX_RERANKER_STREAM_MODEL_ID and "
            "CORETEX_RERANKER_STREAM_REVISION",
            code=2,
        )
    torch, tokenizer, model, yes_id, no_id = _load_model(model_id, revision)
    print(json.dumps({"ready": True, "modelId": model_id, "revision": revision}), flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            print(json.dumps({"error": f"invalid request JSON: {e}"}), flush=True)
            continue
        corr_id = req.get("id")
        try:
            pairs = req.get("pairs", [])
            prompts = _resolve_prompts(pairs)
            scores = _score_pairs(torch, tokenizer, model, yes_id, no_id, prompts)
            resp = {"scores": scores}
            if corr_id is not None:
                resp["id"] = corr_id
            print(json.dumps(resp), flush=True)
        except Exception as e:
            resp = {"error": str(e)}
            if corr_id is not None:
                resp["id"] = corr_id
            print(json.dumps(resp), flush=True)


def _run_print_prompt_template() -> None:
    """Golden-oracle mode: emit the canonical template rendering for the fixed
    probe pair (JSON, so byte-exactness survives stdout newline handling)."""
    print(json.dumps({
        "probeQuery": PROMPT_PROBE_QUERY,
        "probeDocument": PROMPT_PROBE_DOCUMENT,
        "instruction": _resolve_instruction(),
        "prompt": _build_qwen3_prompt(PROMPT_PROBE_QUERY, PROMPT_PROBE_DOCUMENT),
    }))


def _run_health() -> None:
    """Runtime fingerprint for the keyless GPU scorer's scorerHealth (no model load)."""
    import platform

    health: dict[str, Any] = {
        "python": platform.python_version(),
        "dtype": "fp32",
        "tf32": False,
        "cuda": False,
        "device": "cpu",
    }
    try:
        import torch  # type: ignore

        health["torch"] = getattr(torch, "__version__", "unknown")
        use_cuda = _ALLOW_CUDA and torch.cuda.is_available()
        health["cuda"] = bool(use_cuda)
        if use_cuda:
            health["device"] = torch.cuda.get_device_name(0)
    except Exception as exc:  # torch not importable yet — report it, don't crash
        health["torch"] = None
        health["torchError"] = str(exc)
    try:
        import transformers  # type: ignore

        health["transformers"] = getattr(transformers, "__version__", "unknown")
    except Exception as exc:
        health["transformers"] = None
        health["transformersError"] = str(exc)
    print(json.dumps(health), flush=True)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--print-prompt-template":
        _run_print_prompt_template()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "--health":
        _run_health()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "--stream":
        _run_stream()
        return
    _run_one_shot()


if __name__ == "__main__":
    main()
