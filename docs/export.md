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
`#assert_trust kernel`.

Contract 2.4 `VerifiedEventualBound` outcomes export the retained fixed cutoff,
not the discovery procedure. The project kernel-reduces
`checkReciprocalPowerUpper`, applies `verify_reciprocal_power_upper`, and uses
`#assert_trust kernel` on the theorem for the complete natural-number tail.
