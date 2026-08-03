# Registered downstream enclosures

Bridge Contract 2.8 lets a Python proof use unary enclosure rules registered by
a downstream Lean project. The project is loaded once at Bridge startup from
an immutable `leancert-enclosure-profile/1`; requests cannot import modules,
submit Lean syntax, or change the registry.

## Profiled solver

```python
import leancert as lc
from leancert import ast

with lc.Solver(
    enclosure_profile="./leancert-enclosures.json",
    project_dir="./my-lean-project",
) as solver:
    li = solver.enclosures.function("MyProject.Enclosures.li")
    x = ast.var("x")

    result = solver.prove(li(x) < 2, where={x: (1, 2)})
    assert isinstance(result, lc.VerifiedRegisteredEnclosure)

    # Candidate discovery is disabled during this second pass.
    replayed = solver.replay(result)
    assert replayed[0]["replayed"] is True
```

`project_dir` starts the Bridge through `lake env`, so the modules named by the
profile can be resolved from that downstream Lake environment. An explicit
`binary_path` may be supplied when testing a locally built Bridge.

The profile has this closed form:

```json
{
  "schema_version": "leancert-enclosure-profile/1",
  "name": "my-project-enclosures",
  "modules": ["MyProject.Enclosures"],
  "allowed_functions": ["MyProject.Enclosures.li"],
  "leancert_revision": "<exact resolved revision>",
  "environment_digest": "sha256:<downstream environment identity>"
}
```

The SDK compares every field with the Bridge handshake. Function handles are
issued only for declarations that the loaded registry resolves at least once;
the complete deterministic priority-ordered rule inventory is bound into the
handle identity.
Their semantic AST identities retain the profile name, exact LeanCert
revision, environment digest, checker, theorem, and priority. A handle from a
different solver or profile is rejected before a proof request is sent.

## Evidence and trust

Python composes an exact structured expression from rational arithmetic,
supported core unary functions, and registered handles. The Bridge constructs
the closed Lean proposition and returns `VerifiedRegisteredEnclosure` only
after a fresh kernel proof succeeds. Candidate functions remain untrusted.

Each successful check retains a `ReplayableRegisteredEnclosureCertificate`
containing the exact claim, profile identity, subdivision tree, leaf domains,
fixed rule inputs and outputs, and composition counts. `solver.replay(result)`
uses `replay_registered_enclosure`, which disables candidate execution and
reruns only retained Boolean checker inputs in the same frozen environment.

This is fixed Bridge replay, not automatically a standalone Lean project.
`export_lean_project()` returns `ExportUnsupported` until the downstream
modules and their dependency provenance can be packaged into the exported
artifact. The distinction prevents a profile-dependent proof from being
presented as portable evidence when its Lean dependencies are absent.

## Current expression fragment

The first route is univariate over one closed exact rational interval. It
supports exact constants, negation, addition, multiplication, division,
non-negative integer powers, registered unary calls, and the Contract 2.8 core
unary functions. Non-success remains typed as `Unsupported`, `Inconclusive`,
or `DomainObstruction`; it is never promoted by Python-side sampling.
