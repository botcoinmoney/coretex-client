/**
 * CPU-only bi-encoder runtime wrapper for the production scorer.
 *
 * Spec: specs/determinism.md.
 *
 * Backends:
 *   - 'pinned' (production): subprocess to a pinned Python venv that loads
 *     the bundle-pinned bi-encoder and emits quantized embedding bytes.
 *     Refuses to run if any GPU env var is set or the runtime versions do
 *     not match the bundle's runtimePin.
 *   - 'deterministic' (CI/offline only): hash-derived embeddings; refuses
 *     to be selected when CORETEX_RERANKER_PRODUCTION=1 or
 *     CORTEX_REAL_EVAL=1.
 */

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';

import type { RetrievalKeyLayout } from './retrieval-corpus.js';

export interface BiEncoderInput {
  readonly text: string;
  readonly id?: string;
}

export interface BiEncoder {
  readonly modelId: string;
  readonly revision: string;
  readonly mode: 'dense';
  readonly layout: RetrievalKeyLayout;
  encode(inputs: readonly BiEncoderInput[]): Promise<Uint8Array[]>;
}

export interface PinnedBiEncoderOptions {
  readonly modelId: string;
  readonly revision: string;
  readonly layout: RetrievalKeyLayout;
  readonly pythonBin?: string;          // CORETEX_BIENCODER_PYTHON or 'python3'
  readonly scriptPath?: string;         // path to scripts/bi_encoder_runner.py
  readonly batchSize?: number;
  /** Run mode: 'cpu' is the only allowed canonical scoring path. */
  readonly mode?: 'cpu';
}

const GPU_ENV_VARS = ['CORETEX_USE_GPU', 'PYTORCH_USE_MPS'] as const;

function refuseGpu(): void {
  for (const envVar of GPU_ENV_VARS) {
    const v = process.env[envVar];
    if (v && v !== '0') throw new Error(`bi-encoder refuses to run with ${envVar}=${v} set (CPU-only contract)`);
  }
  if (process.env.CUDA_VISIBLE_DEVICES && process.env.CUDA_VISIBLE_DEVICES !== '') {
    throw new Error('bi-encoder refuses to run with CUDA_VISIBLE_DEVICES set (CPU-only contract)');
  }
  const ortProviders = process.env.ONNXRUNTIME_PROVIDERS ?? '';
  if (ortProviders.includes('CUDA') || ortProviders.includes('MPS')) {
    throw new Error(`bi-encoder refuses to run with ONNXRUNTIME_PROVIDERS=${ortProviders} (CPU-only contract)`);
  }
}

/**
 * Subprocess to a pinned Python venv that loads the bi-encoder and emits
 * quantized embedding bytes per input. The venv is verified by the
 * coordinator's startup assertion against the bundle's runtimePin.
 */
export function createPinnedBiEncoder(opts: PinnedBiEncoderOptions): BiEncoder {
  refuseGpu();
  const pythonBin = opts.pythonBin ?? process.env['CORETEX_BIENCODER_PYTHON'] ?? 'python3';
  const scriptPath =
    opts.scriptPath ??
    process.env['CORETEX_BIENCODER_SCRIPT'] ??
    new URL('../../scripts/bi_encoder_runner.py', import.meta.url).pathname;
  const batchSize = opts.batchSize ?? 32;

  return {
    modelId: opts.modelId,
    revision: opts.revision,
    mode: 'dense',
    layout: opts.layout,
    async encode(inputs: readonly BiEncoderInput[]): Promise<Uint8Array[]> {
      const out: Uint8Array[] = [];
      for (let i = 0; i < inputs.length; i += batchSize) {
        const batch = inputs.slice(i, i + batchSize);
        const stdinPayload = JSON.stringify({
          modelId: opts.modelId,
          revision: opts.revision,
          mode: 'dense',
          layout: opts.layout,
          inputs: batch.map((b) => ({ text: b.text, id: b.id ?? '' })),
        });
        const result = spawnSync(pythonBin, [scriptPath], {
          input: stdinPayload,
          encoding: 'utf8',
          env: { ...process.env },
          maxBuffer: 64 * 1024 * 1024,
        });
        if (result.status !== 0) {
          throw new Error(`bi-encoder subprocess failed (${result.status}): ${result.stderr}`);
        }
        const parsed = JSON.parse(result.stdout) as { embeddings: string[] };
        for (const hex of parsed.embeddings) {
          out.push(hexToUint8(hex));
        }
      }
      return out;
    },
  };
}

export interface DeterministicBiEncoderOptions {
  readonly modelId: string;
  readonly revision: string;
  readonly layout: RetrievalKeyLayout;
}

/**
 * Hash-derived deterministic stub bi-encoder. CI/offline only.
 *
 * Refuses to be used in production mode (CORETEX_RERANKER_PRODUCTION=1 or
 * CORTEX_REAL_EVAL=1). This keeps unit tests deterministic without running
 * a Python subprocess.
 */
export function createDeterministicBiEncoder(opts: DeterministicBiEncoderOptions): BiEncoder {
  if (process.env['CORETEX_RERANKER_PRODUCTION'] === '1' || process.env['CORTEX_REAL_EVAL'] === '1') {
    throw new Error('createDeterministicBiEncoder refused in production mode');
  }
  return {
    modelId: opts.modelId,
    revision: opts.revision,
    mode: 'dense',
    layout: opts.layout,
    async encode(inputs: readonly BiEncoderInput[]): Promise<Uint8Array[]> {
      return inputs.map((input) => deterministicEmbedding(input.text, opts.layout));
    },
  };
}

function deterministicEmbedding(text: string, layout: RetrievalKeyLayout): Uint8Array {
  const bytesPerScalar = layout.quantization === 'bf16' ? 2 : 1;
  const prefixBytes = layout.quantization === 'int8' ? 4 : 0;
  const out = new Uint8Array(prefixBytes + layout.dim * bytesPerScalar);
  if (layout.quantization === 'int8') {
    new DataView(out.buffer, out.byteOffset, out.byteLength).setFloat32(0, 1.0, false);
  }
  let counter = 0;
  let chunk = createHash('sha256').update(`${counter}|${text}`).digest();
  let chunkIdx = 0;
  for (let i = prefixBytes; i < out.length; i++) {
    if (chunkIdx >= chunk.length) {
      counter++;
      chunk = createHash('sha256').update(`${counter}|${text}`).digest();
      chunkIdx = 0;
    }
    out[i] = chunk[chunkIdx++]!;
  }
  return out;
}

function hexToUint8(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error('hexToUint8: odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function biEncoderFromEnv(layout: RetrievalKeyLayout, opts?: Partial<PinnedBiEncoderOptions>): BiEncoder {
  const mode = process.env['CORETEX_BIENCODER'] ?? 'pinned';
  const modelId = opts?.modelId ?? 'BAAI/bge-m3';
  const revision = opts?.revision ?? process.env['CORETEX_BIENCODER_REVISION'] ?? '';
  if (!revision) throw new Error('biEncoderFromEnv: revision is required');
  if (mode === 'deterministic') {
    return createDeterministicBiEncoder({ modelId, revision, layout });
  }
  if (process.env['CORETEX_BIENCODER_MODE'] === 'streaming') {
    return createStreamingBiEncoder({ modelId, revision, layout, ...opts });
  }
  return createPinnedBiEncoder({ modelId, revision, layout, ...opts });
}

/**
 * Persistent-subprocess bi-encoder. Spawns one Python child that loads the
 * pinned model exactly once and then services request/response NDJSON over
 * stdin/stdout. This is the only bi-encoder implementation that can sustain
 * launch-scale corpus generation; the per-call spawnSync variant pays the
 * model-load cost on every encode() and is unusable past a few hundred
 * texts on a CPU host. Returns a BiEncoder with the same external API as
 * createPinnedBiEncoder; clean shutdown is via close().
 */
export function createStreamingBiEncoder(
  opts: PinnedBiEncoderOptions,
): BiEncoder & { close: () => Promise<void> } {
  refuseGpu();
  const pythonBin = opts.pythonBin ?? process.env['CORETEX_BIENCODER_PYTHON'] ?? 'python3';
  const scriptPath =
    opts.scriptPath ??
    process.env['CORETEX_BIENCODER_SCRIPT'] ??
    new URL('../../scripts/bi_encoder_runner.py', import.meta.url).pathname;
  const child: ChildProcessWithoutNullStreams = spawn(pythonBin, [scriptPath, '--stream'], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CORETEX_BIENCODER_STREAM_MODEL_ID: opts.modelId,
      CORETEX_BIENCODER_STREAM_REVISION: opts.revision,
      CORETEX_BIENCODER_STREAM_LAYOUT_JSON: JSON.stringify(opts.layout),
    },
  });

  const stderrChunks: string[] = [];
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => stderrChunks.push(chunk));

  const responses = new Map<number, { resolve: (hexes: string[]) => void; reject: (err: Error) => void }>();
  let nextId = 1;
  let readyResolve: () => void = () => {};
  let readyReject: (err: Error) => void = () => {};
  const ready = new Promise<void>((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  let exited = false;

  const rl = createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return;
    }
    if (parsed && typeof parsed === 'object' && 'ready' in parsed) {
      readyResolve();
      return;
    }
    if (parsed && typeof parsed === 'object' && 'id' in parsed) {
      const id = (parsed as { id: number }).id;
      const pending = responses.get(id);
      if (!pending) return;
      responses.delete(id);
      if ('error' in parsed) {
        pending.reject(new Error(`bi-encoder stream error: ${(parsed as { error: string }).error}`));
        return;
      }
      const embeddings = (parsed as { embeddings?: string[] }).embeddings ?? [];
      pending.resolve(embeddings);
    }
  });

  child.on('exit', (code, signal) => {
    exited = true;
    const stderr = stderrChunks.join('');
    const err = new Error(`bi-encoder stream child exited (code=${code}, signal=${signal}): ${stderr.slice(-500)}`);
    readyReject(err);
    for (const pending of responses.values()) pending.reject(err);
    responses.clear();
  });

  child.on('error', (e) => {
    exited = true;
    readyReject(e);
    for (const pending of responses.values()) pending.reject(e);
    responses.clear();
  });

  async function encode(inputs: readonly BiEncoderInput[]): Promise<Uint8Array[]> {
    if (exited) throw new Error('bi-encoder stream child is no longer running');
    await ready;
    if (inputs.length === 0) return [];
    const id = nextId++;
    const payload = JSON.stringify({ id, inputs: inputs.map((b) => ({ text: b.text, id: b.id ?? '' })) }) + '\n';
    return new Promise<Uint8Array[]>((resolve, reject) => {
      responses.set(id, {
        resolve: (hexes) => resolve(hexes.map(hexToUint8)),
        reject,
      });
      child.stdin.write(payload, (writeErr) => {
        if (writeErr) {
          responses.delete(id);
          reject(writeErr);
        }
      });
    });
  }

  async function close(): Promise<void> {
    if (exited) return;
    try {
      child.stdin.end();
    } catch {
      /* noop */
    }
    await new Promise<void>((resolve) => {
      if (exited) return resolve();
      child.once('exit', () => resolve());
    });
  }

  return { modelId: opts.modelId, revision: opts.revision, mode: 'dense', layout: opts.layout, encode, close };
}

/**
 * Cosine similarity between two pre-quantized embedding byte arrays. Uses
 * the layout to dequantize. For int8 quant: assumes a per-vector scale stored
 * in a leading 4 bytes (float32 BE) and the remainder are int8 codes.
 *
 * For bf16 quant: each scalar is 2 bytes (bf16 BE).
 */
export function dequantize(bytes: Uint8Array, layout: RetrievalKeyLayout): Float32Array {
  const dim = layout.dim;
  const out = new Float32Array(dim);
  if (layout.quantization === 'int8') {
    if (bytes.length < 4 + dim) throw new Error(`dequantize int8: bytes too short (${bytes.length})`);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const scale = dv.getFloat32(0, false);
    for (let i = 0; i < dim; i++) {
      const raw = bytes[4 + i]!;
      const signed = raw < 128 ? raw : raw - 256;
      out[i] = signed * scale;
    }
    return out;
  }
  if (layout.quantization === 'bf16') {
    if (bytes.length < dim * 2) throw new Error(`dequantize bf16: bytes too short (${bytes.length})`);
    for (let i = 0; i < dim; i++) {
      const hi = bytes[i * 2]!;
      const lo = bytes[i * 2 + 1]!;
      // bf16 = upper 16 bits of fp32; reconstruct
      const u32 = (hi << 24) | (lo << 16);
      const buf = new ArrayBuffer(4);
      new DataView(buf).setUint32(0, u32, false);
      out[i] = new DataView(buf).getFloat32(0, false);
    }
    return out;
  }
  throw new Error(`dequantize: unknown quantization ${layout.quantization}`);
}

export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) throw new Error('cosineSimilarity: dim mismatch');
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}
