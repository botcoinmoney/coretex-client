# Cross-lane fixtures

Files here are **copies**, not originals. Their provenance and `sha256` are recorded so drift
between the two copies is detectable rather than silent — which is the entire reason a shared
known-answer vector is worth having.

| file | origin | sha256 at copy time |
| --- | --- | --- |
| `signing-vector.json` | resolver lane, `v5/resolver/tests/fixtures/signing-vector.json` | `e19b0f513b4ebeb66bdd698ed95a6cd72eb38cac8bd990d11b071d76d332ba1c` |

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
