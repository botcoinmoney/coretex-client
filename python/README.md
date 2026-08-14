# coretex-validator

Dependency-free public validator for BOTCOIN's canonical Base descriptor-v3 CoreTex rig lane.

The default release is the immutable, operator-signed production deployment. Production
classification is accepted only after its signature and exact contract/genesis identities are
verified, followed by independent Base bytecode and wiring reads.

The constructor genesis is verified as an immutable deployment fact only. Operational state begins
at the parent root in the confirmed epoch context. Schema-v3 validation then requires the complete
content-addressed composition, all three profile releases, and every bound module file.

Deterministic admission needs six code trees. They are published as content-addressed objects,
addressed by the same tree-hash rule the signed receipt's `code_roots` binds, so a clean machine
gets them from a mirror and checks them against the chain-bound identity rather than the courier:

```bash
coretex-validator sync-law --mirror https://<coordinator-or-mirror>
```

Every object is rehashed from the bytes that arrived, and a mismatch, a truncation, an oversize
response, a tar carrying anything the hash rule does not cover, or a missing tree installs nothing
at all. The verified cache is applied automatically by `reproduce`, `replay-advance` and
`verify-receipt`.

See the repository root README for installation and production replay commands.
