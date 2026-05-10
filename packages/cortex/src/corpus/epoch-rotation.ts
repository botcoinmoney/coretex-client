import { createHash, createSign, createVerify } from 'node:crypto';

import type { CorpusDelta } from './delta.js';
import { corpusDeltaSha256 } from './delta.js';

export interface EpochRotationManifestSigner {
  readonly keyId: string;
  readonly algorithm: 'RSA-SHA256' | 'ECDSA-SHA256';
  readonly signature: string;
}

export interface EpochRotationManifest {
  readonly schemaVersion: 'coretex.epoch-rotation.v1';
  readonly epoch: number;
  readonly generatedAt: string;
  readonly previousCorpusRoot: string;
  readonly nextCorpusRoot: string;
  readonly corpusDeltaHash: string;
  readonly challengeBookHash: string;
  readonly bundleHash: string;
  readonly minImprovementPpm: number;
  readonly advancesObserved: number;
  readonly qualityAttemptsObserved: number;
  readonly signer?: EpochRotationManifestSigner;
}

export interface BuildEpochRotationManifestOptions {
  readonly epoch: number;
  readonly delta: CorpusDelta;
  readonly challengeBook: unknown;
  readonly bundleHash: string;
  readonly minImprovementPpm: number;
  readonly advancesObserved: number;
  readonly qualityAttemptsObserved: number;
  readonly generatedAt?: string;
}

export function buildEpochRotationManifest(opts: BuildEpochRotationManifestOptions): EpochRotationManifest {
  return {
    schemaVersion: 'coretex.epoch-rotation.v1',
    epoch: opts.epoch,
    generatedAt: opts.generatedAt ?? new Date().toISOString(),
    previousCorpusRoot: opts.delta.previousRoot,
    nextCorpusRoot: opts.delta.nextRoot,
    corpusDeltaHash: hashCorpusDelta(opts.delta),
    challengeBookHash: hashJson(opts.challengeBook),
    bundleHash: opts.bundleHash.toLowerCase(),
    minImprovementPpm: opts.minImprovementPpm,
    advancesObserved: opts.advancesObserved,
    qualityAttemptsObserved: opts.qualityAttemptsObserved,
  };
}

export function signEpochRotationManifest(
  manifest: EpochRotationManifest,
  privateKeyPem: string,
  keyId: string,
  algorithm: EpochRotationManifestSigner['algorithm'] = 'RSA-SHA256',
): EpochRotationManifest {
  const unsigned = withoutSigner(manifest);
  const signer = createSign(algorithm === 'RSA-SHA256' ? 'RSA-SHA256' : 'SHA256');
  signer.update(canonicalJson(unsigned));
  signer.end();
  return {
    ...unsigned,
    signer: {
      keyId,
      algorithm,
      signature: `0x${signer.sign(privateKeyPem).toString('hex')}`,
    },
  };
}

export function verifyEpochRotationManifestSignature(
  manifest: EpochRotationManifest,
  publicKeyPem: string,
): boolean {
  if (!manifest.signer) return false;
  const verifier = createVerify(manifest.signer.algorithm === 'RSA-SHA256' ? 'RSA-SHA256' : 'SHA256');
  verifier.update(canonicalJson(withoutSigner(manifest)));
  verifier.end();
  return verifier.verify(publicKeyPem, Buffer.from(manifest.signer.signature.replace(/^0x/i, ''), 'hex'));
}

export function hashCorpusDelta(delta: CorpusDelta): string {
  // Delta can carry binary embedding bytes; defer to delta.ts canonical-JSON
  // which knows how to hex-encode Uint8Array fields.
  return `0x${corpusDeltaSha256(delta)}`;
}

export function hashJson(value: unknown): string {
  return `0x${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function withoutSigner(manifest: EpochRotationManifest): Omit<EpochRotationManifest, 'signer'> {
  const { signer: _signer, ...unsigned } = manifest;
  return unsigned;
}

function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`).join(',')}}`;
  }
  throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
}
