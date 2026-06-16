# Cortex Receipt Field Mapping (CoreTex)

> Phase 5 deliverable. The §6 published mapping that lets Cortex receipts ride the existing `BotcoinMining` EIP-712 domain in CoreTex without a new contract domain.

| `BotcoinMining` field   | Cortex meaning                                                                |
|-------------------------|-------------------------------------------------------------------------------|
| `worldSeed` (uint128)   | u128 derived from `keccak(H_e ‖ miner ‖ solveIndex ‖ parentStateRoot)`         |
| `docHash`               | `parentStateRoot`                                                              |
| `questionsHash`         | `experienceCorpusRoot`                                                         |
| `constraintsHash`       | `shardCommitment`                                                              |
| `answersHash`           | `patchHash`                                                                    |
| `rulesVersion`          | reserved Cortex value (`0xC0`)                                                 |

Auditors and explorers disambiguate via `rulesVersion`. The contract does not introspect semantics — only the signature.

**V1 path** (tracked, non-blocking): `BotcoinMining.submitCortexReceipt(...)` sister function with explicit Cortex field names. Removes the receipt-field overloading without changing the `BotcoinMining` storage layout.

## Trust assumption

The on-chain schema labels say "doc/questions/constraints/answers" and explorers will see them as such. This is documented in miner-facing docs as a soft-coupling that V1 removes. Acceptable for CoreTex because credit issuance is identical to SWCP, and the `rulesVersion = 0xC0` byte makes Cortex receipts machine-distinguishable from SWCP receipts.
