#!/usr/bin/env python3
"""CPU-only bi-encoder subprocess runner.

Two modes, selected by --stream flag:

ONE-SHOT (single-request default): reads a single JSON request from stdin and emits
{ "embeddings": [...] } on stdout, then exits. Used by the original
spawnSync call site. Preserved for backward compatibility.

STREAM (--stream): loads the pinned model once, then enters a request loop.
Each line on stdin is a JSON request:
    { "id": "<corr-id>", "inputs": [ { "text": "...", "id": "..." }, ... ] }
Each response is a single JSON line on stdout:
    { "id": "<corr-id>", "embeddings": [ "<hex>", ... ] }
or
    { "id": "<corr-id>", "error": "<message>" }
EOF on stdin terminates the process cleanly. The model/tokenizer/layout pin
is supplied via env (CORETEX_BIENCODER_STREAM_MODEL_ID,
CORETEX_BIENCODER_STREAM_REVISION, CORETEX_BIENCODER_STREAM_LAYOUT_JSON).
This avoids paying the model-load cost on every request, which is required
for launch-scale corpus generation (>3M encode calls).

Both modes share the same CPU-only enforcement, quantization, and
determinism settings:
    - CUDA / MPS / ONNXRUNTIME GPU providers all refused before torch import
    - aborts if torch.cuda.is_available() or MPS detected
    - torch threads pinned to BIENCODER_NUM_THREADS (default 1)
    - BLAS thread counts (OMP/MKL/OPENBLAS/NUMEXPR/VECLIB) propagated
      from BIENCODER_NUM_THREADS BEFORE torch import so the BLAS pool
      doesn't drift across hosts (replay tolerance hardening)
    - tokenizer truncation to MAX_SEQ_LEN (default 512)
    - L2 normalize before quantization
    - int8: 4-byte float32 BE per-vector scale, then dim int8 codes
    - bf16: 2 bytes per scalar (BE)
"""

from __future__ import annotations

import json
import os
import struct
import sys
from typing import Any, Iterable, List

# CPU-only enforcement BEFORE any ML imports.
os.environ.setdefault("CUDA_VISIBLE_DEVICES", "")
os.environ.setdefault("ONNXRUNTIME_PROVIDERS", "CPUExecutionProvider")
if os.environ.get("CORETEX_USE_GPU") == "1":
    print('{"error": "CORETEX_USE_GPU=1 not allowed"}', file=sys.stdout)
    sys.exit(2)
if os.environ.get("PYTORCH_USE_MPS") == "1":
    print('{"error": "PYTORCH_USE_MPS=1 not allowed"}', file=sys.stdout)
    sys.exit(2)

# Pin BLAS thread counts BEFORE torch is imported. torch.set_num_threads()
# only controls torch's intra-op pool — the underlying BLAS libraries
# (MKL, OpenBLAS) and numexpr read their thread counts from env at
# library-load time, and a drifting BLAS pool contributes to replay
# tolerance budget. We propagate BIENCODER_NUM_THREADS to all of them
# so determinism is reproducible across hosts. Match the canonical
# scoring-path env block in scripts/orchestrate-cpu-calibration.sh.
_blas_threads = os.environ.get("BIENCODER_NUM_THREADS", "1")
for _v in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS",
           "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    os.environ.setdefault(_v, _blas_threads)


def fail(msg: str, code: int = 1) -> None:
    print(json.dumps({"error": msg}), file=sys.stdout)
    sys.exit(code)


def quantize_int8(vec: "List[float]", dim: int) -> bytes:
    if not vec:
        fail("quantize_int8: empty vector")
    abs_max = 0.0
    for v in vec:
        a = abs(v)
        if a > abs_max:
            abs_max = a
    if abs_max == 0.0:
        scale = 1.0
    else:
        scale = abs_max / 127.0
    out = bytearray()
    out += struct.pack(">f", scale)
    for i in range(dim):
        v = vec[i] if i < len(vec) else 0.0
        if scale == 0.0:
            q = 0
        else:
            q = int(round(v / scale))
        if q < -128:
            q = -128
        if q > 127:
            q = 127
        out += (q & 0xff).to_bytes(1, "big", signed=False)
    return bytes(out)


def quantize_bf16(vec: "List[float]", dim: int) -> bytes:
    out = bytearray()
    for i in range(dim):
        v = vec[i] if i < len(vec) else 0.0
        # Pack fp32 BE then take top 2 bytes (bf16 is upper half of fp32)
        packed = struct.pack(">f", v)
        out += packed[:2]
    return bytes(out)


def _load_torch_and_pin_threads():
    try:
        import torch  # type: ignore
        from transformers import AutoModel, AutoTokenizer  # type: ignore
    except Exception as e:
        fail(f"missing transformers/torch: {e}")
    if torch.cuda.is_available():
        fail("torch detected CUDA; refuse to run on canonical scoring path")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        fail("torch detected MPS; refuse to run on canonical scoring path")
    num_threads = int(os.environ.get("BIENCODER_NUM_THREADS", "1"))
    torch.set_num_threads(num_threads)
    torch.set_num_interop_threads(1)
    return torch, AutoModel, AutoTokenizer


def _load_model(model_id: str, revision: str):
    torch, AutoModel, AutoTokenizer = _load_torch_and_pin_threads()
    tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision, use_fast=True)
    model = AutoModel.from_pretrained(model_id, revision=revision, torch_dtype=torch.float32)
    model.eval()
    return torch, tokenizer, model


def _encode_texts(torch, tokenizer, model, texts: "List[str]", dim: int, quantization: str, max_seq: int) -> "List[str]":
    """Batched padded forward pass for BGE-M3 dense.

    Per-text results are invariant to batch composition because the attention
    mask zeros out padding contributions and the [CLS] token at position 0
    only attends to non-padded positions of its own sequence. Batching cuts
    CPU forward-pass cost by close to the batch factor at small sequence
    lengths and remains substantially faster than 1-by-1 even at 512 tokens.
    """
    embeddings: List[str] = []
    if not texts:
        return embeddings
    inner_batch = int(os.environ.get("BIENCODER_INNER_BATCH", "16"))
    with torch.no_grad():
        for start in range(0, len(texts), inner_batch):
            chunk = texts[start : start + inner_batch]
            enc = tokenizer(
                chunk,
                truncation=True,
                max_length=max_seq,
                padding=True,
                return_tensors="pt",
            )
            out = model(**enc)
            # Dense pooling: BGE-M3 uses [CLS] (position 0) of last_hidden_state.
            # Shape: [batch, dim]. Position 0 is CLS for every sequence.
            cls = out.last_hidden_state[:, 0, :]
            # L2 normalize per-row.
            norms = torch.norm(cls, p=2, dim=1, keepdim=True)
            norms = torch.where(norms > 0, norms, torch.ones_like(norms))
            cls = cls / norms
            for vec in cls.tolist():
                if quantization == "int8":
                    qbytes = quantize_int8(vec, dim)
                elif quantization == "bf16":
                    qbytes = quantize_bf16(vec, dim)
                else:
                    fail(f"unknown quantization {quantization}")
                embeddings.append(qbytes.hex())
    return embeddings


def _run_one_shot() -> None:
    raw = sys.stdin.read()
    if not raw:
        fail("empty stdin")
    try:
        payload = json.loads(raw)
    except Exception as e:
        fail(f"invalid stdin JSON: {e}")

    model_id = payload["modelId"]
    revision = payload["revision"]
    layout = payload["layout"]
    dim = int(layout["dim"])
    quantization = layout["quantization"]
    inputs = payload["inputs"]

    torch, tokenizer, model = _load_model(model_id, revision)
    max_seq = int(os.environ.get("BIENCODER_MAX_SEQ_LEN", "512"))
    texts = [str(x.get("text", "")) for x in inputs]
    embeddings = _encode_texts(torch, tokenizer, model, texts, dim, quantization, max_seq)
    print(json.dumps({"embeddings": embeddings}))


def _run_stream() -> None:
    model_id = os.environ.get("CORETEX_BIENCODER_STREAM_MODEL_ID")
    revision = os.environ.get("CORETEX_BIENCODER_STREAM_REVISION")
    layout_json = os.environ.get("CORETEX_BIENCODER_STREAM_LAYOUT_JSON")
    if not model_id or not revision or not layout_json:
        fail(
            "stream mode requires CORETEX_BIENCODER_STREAM_MODEL_ID, "
            "CORETEX_BIENCODER_STREAM_REVISION, CORETEX_BIENCODER_STREAM_LAYOUT_JSON",
            code=2,
        )
    try:
        layout = json.loads(layout_json)
    except Exception as e:
        fail(f"invalid CORETEX_BIENCODER_STREAM_LAYOUT_JSON: {e}", code=2)
    dim = int(layout["dim"])
    quantization = layout["quantization"]
    max_seq = int(os.environ.get("BIENCODER_MAX_SEQ_LEN", "512"))

    torch, tokenizer, model = _load_model(model_id, revision)

    # Signal readiness on its own line so the parent can wait without races.
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
            inputs = req["inputs"]
            texts = [str(x.get("text", "")) for x in inputs]
            embeddings = _encode_texts(torch, tokenizer, model, texts, dim, quantization, max_seq)
            resp = {"embeddings": embeddings}
            if corr_id is not None:
                resp["id"] = corr_id
            print(json.dumps(resp), flush=True)
        except Exception as e:
            resp = {"error": str(e)}
            if corr_id is not None:
                resp["id"] = corr_id
            print(json.dumps(resp), flush=True)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--stream":
        _run_stream()
        return
    _run_one_shot()


if __name__ == "__main__":
    main()
