# Independently rebuildable Lean evidence

Bridge Contract 2.1 returns the complete fixed checker input for verified
bounds. A `Verified` result can export that retained certificate as a pinned
Lean project:

```python
import leancert as lc
from leancert import ast

x = ast.var("x")
result = lc.prove(ast.sin(x) <= 1, where={x: (0, 1)})

if isinstance(result, lc.Verified):
    export = result.export_lean_project("verified-sine")
    assert isinstance(export, lc.ExportVerified)
```

The exported project reconstructs the exact lowered LeanCert expression, box,
bound, and global-optimization configuration retained by the bridge. It closes
the Boolean checker with `decide +kernel`, applies the recorded Golden Theorem,
and checks the resulting declaration with `#assert_trust kernel`.

For an expression comparison such as `sin(x) <= x`, the checker certifies the
normalized bound `sin(x) - x <= 0`. The project additionally reconstructs both
semantic operands and proves the original `sin(x) <= x` theorem in Lean; the
lowered checker statement is never substituted for the user-facing claim.

`VerifiedConjunction` exports each compatible bound child as a separate fixed
certificate and then composes their semantic theorems into a checked
`semantic_conjunction`. Exact-normalization-only children are labeled in the
Python result and do not acquire fabricated Bridge evidence; mixed
exact/Bridge conjunction export currently returns `ExportUnsupported` until a
dedicated exact-logical Lean renderer is available.

This is a second verification event. It does not change the original bridge
result from `compiled_checker` into a kernel result.

Project creation is atomic. LeanCert writes and, when requested, builds a
temporary sibling directory before publishing the final path. Build rejection,
missing tooling, and the typed `ExportResourceLimit` timeout outcome leave no
partial project at the requested destination.

Contract 2.0 `bound-check/1` descriptors remain valid checked outcomes, but are
not exportable because they do not retain fixed checker inputs.

Contract 2.3 `VerifiedSystemRoot` outcomes retain a complete
`checked-unique-system-root/1` payload. Their exported project reconstructs the
exact `KrawczykCert`, kernel-reduces `krawczykCheck`, applies
`verify_unique_system_root`, and pins the resulting theorem with
`#assert_trust kernel`. If the requested claim asks only for system-root
existence, export derives that weaker theorem from the retained uniqueness
certificate.

Contract 2.4 `VerifiedEventualBound` outcomes export the retained fixed cutoff,
not the discovery procedure. The project kernel-reduces
`checkReciprocalPowerUpper`, applies `verify_reciprocal_power_upper`, and uses
`#assert_trust kernel` on the theorem for the complete natural-number tail.

Contract 2.5 scalar-root outcomes export the exact expression, rational
interval, and Taylor depth accepted by `checkSignChange`,
`checkNewtonContractsCore`, or `checkNoRoot`. The project reconstructs the
required support, single-variable, and continuity witnesses, applies the
matching Golden Theorem, and ends with `#assert_trust kernel exported_claim`.

Contract 2.6 integral outcomes export the exact integrand, rational endpoints,
relation and bound, plus the accepted partition count for numerical bounds.
Exact polynomial equalities retain no search data; partition-search telemetry
is intentionally excluded from proof authority.

## Verify exported projects

Every new export contains an `artifact.json` manifest using schema
`leancert-export/1`. The manifest binds the claim identifier, certificate
payload digests, expected trust class, Lean target, and SHA-256 identities of
the proof, claim, certificate, provenance, toolchain, and Lake configuration.

Verify one project or recursively discover projects beneath a directory:

```bash
leancert verify verified-sine
leancert verify exported_proofs/ --require-trust kernel
leancert verify exported_proofs/ --format json
```

Verification first validates the artifact envelope and its semantic claim
digest. It then runs the pinned project's explicit `LeanCertExport` target.
The numerical search and Python proving operation are not rerun.

The command uses stable exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Every discovered artifact independently rebuilt |
| `1` | Lean rejected at least one exported theorem |
| `2` | An artifact or command argument was malformed |
| `3` | Required verification infrastructure was unavailable |
| `4` | A rebuild exceeded its resource limit |

Use `--timeout SECONDS` to set the per-project build limit, `--lake PATH` to
select a Lake executable, and `--fail-fast` to stop after the first failure.
JSON reports use schema `leancert-verification-report/1` and include each
artifact's claim identifier, certificate digests, trust class, result, timing,
and captured build output.
