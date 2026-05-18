/**
 * @botcoin/cortex — state module
 * Phase 1 deliverable: encode/decode, merkleization, patch wire format, apply.
 */

export type {
  CortexState,
  MutableCortexState,
  Patch,
  PatchError,
  PatchResult,
  PatchSuccess,
  PatchErrorCode,
  PatchTypeCode,
} from './types.js';

export {
  RANGES,
  PATCH_TYPE,
  ERROR_NAMES,
  MAGIC,
  SCHEMA_VERSION_CoreTex,
  WORD_COUNT_VALUE,
} from './types.js';

export {
  pack,
  unpack,
  getField,
  setField,
  writeBigEndian32,
  readBigEndian32,
  PACKED_SIZE,
} from './codec.js';

export {
  merkleizeState,
  buildMerkleCache,
  updateMerkleCache,
  bytesToHex,
  hexToBytes,
} from './merkle.js';

export type {
  MerkleTreeCache,
  MerkleWordUpdate,
} from './merkle.js';

export {
  hasNonZeroReservedBits,
  validateReservedBits,
  RESERVED_MASKS,
} from './validate.js';

export {
  encodeLEB128,
  decodeLEB128,
  encodePatch,
  decodePatch,
  validatePatchType,
  applyPatch,
  applyPatchOntoCurrent,
  patchMatchesEpochParent,
} from './patch.js';

export { keccak256 } from './keccak256.js';
