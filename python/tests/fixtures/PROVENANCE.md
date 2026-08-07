# Cross-lane fixtures

Files here are immutable known-answer vectors. Their provenance and `sha256` are recorded so drift
is detectable rather than silent — which is the entire reason a shared vector is worth having.

| file | origin | sha256 at copy time |
| --- | --- | --- |
| `signing-vector.json` | resolver lane, `v5/resolver/tests/fixtures/signing-vector.json` | `e19b0f513b4ebeb66bdd698ed95a6cd72eb38cac8bd990d11b071d76d332ba1c` |
| `rig-descriptor-v3-vector.json` | independently derived from `botcoin-mining-rigs@a473f3fd1038a81f8ef456cd4c7ce1f7b9fbef6e` | `c9c6e86b23f34ba4c871d70f0c581b5019778f9fd8b187add0033e056339b1fb` |

## Why this is a fixture and not a recomputation

`test_signing_vector.py` asserts this package's signing digest against the **file**, not against
a value this package computes. The difference matters: a test that recomputed the digest with the
same code that produces it would pass no matter what the domain tag said, and a tag change would
silently re-key every signature both lanes can verify. Reading a committed vector makes such a
change fail loudly, on both sides, at the same moment.

The vector deliberately carries `superseded_signing_digest` — the digest under the retired tag
`\x19coretex.rig-resolver-snapshot/v1\n`. **Do not prune it.** It is what makes the tag flip
auditable: it lets a stale signature be *diagnosed* ("signed under the superseded domain") rather
than merely rejected, and it is the evidence that no published snapshot was ever signed under the
old tag.
