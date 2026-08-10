# coretex-validator

Dependency-free public validator for BOTCOIN's canonical Base descriptor-v3 CoreTex rig lane.

The default release is the immutable, operator-signed production deployment. Production
classification is accepted only after its signature and exact contract/genesis identities are
verified, followed by independent Base bytecode and wiring reads.

The constructor genesis is verified as an immutable deployment fact only. Operational state begins
at the parent root in the confirmed epoch context. Schema-v3 validation then requires the complete
content-addressed composition, all three profile releases, and every bound module file.

See the repository root README for installation and production replay commands.
