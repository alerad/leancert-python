# Unified checked proving

`leancert.prove` is the public front door for semantic AST claims. It closes
free variables using exact domains, normalizes the resulting claim, computes a
stable semantic digest, selects an advertised checked capability, and returns a
typed outcome.

```python
import leancert as lc
from leancert import ast

x = ast.var("x")
claim = ast.sin(x) <= 1
result = lc.prove(claim, where={x: (0, 1)})

if isinstance(result, lc.Verified):
    print(result.claim_id)
    print(result.provenance)
elif isinstance(result, lc.Inconclusive):
    print(result.reason)
```

## Initial checked surface

The first route supports exact, universally quantified real bounds over closed
rational intervals:

```python
upper = lc.prove(x**2 <= 1, where={x: (-1, 1)})
two_sided = lc.prove(
    ast.all_of(x >= -1, x <= 1),
    where={x: (-1, 1)},
)
```

Each requested lower or upper bound is checked exactly once. A successful
result retains the normalized closed claim, its `ClaimDigest`, the enclosure,
checker and verifier identities, verification route, numerical backend, and
the complete build provenance. Contract 2.1 additionally retains the exact
fixed checker input and resolved Lean dependencies needed for
[independently rebuildable export](export.md).

Strict inequalities, scalar roots, integrals, and external functions currently
return `Unsupported`. They are not routed through a
discovery API or silently weakened to non-strict bounds. A bridge that does not
advertise an expression node receives no request for that node.

## Unique nonlinear-system roots

Contract 2.3 adds unique roots of square nonlinear systems:

```python
from fractions import Fraction
import leancert as lc
from leancert import ast

x, y = ast.var("x"), ast.var("y")
claim = ast.unique_system_root(
    (x**2 + y - 2, x + y**2 - 2),
    variables=(x, y),
    within=ast.box({
        x: (Fraction(9, 10), Fraction(11, 10)),
        y: (Fraction(9, 10), Fraction(11, 10)),
    }),
)
result = lc.prove(claim)
```

`VerifiedSystemRoot` retains the exact rational center, preconditioner, root
box, contraction evidence, fixed checker payload, and bridge provenance.
Automatic search is untrusted: only `LeanCert.Engine.krawczykCheck` and
`LeanCert.Validity.verify_unique_system_root` authorize success.

External numerical solvers may supply an untrusted candidate:

```python
candidate = lc.KrawczykCandidate.from_arrays(
    scipy_guess,
    approximate_inverse_jacobian,
)
result = lc.prove(
    claim,
    config=lc.ProveConfig(
        system_root=lc.SystemRootConfig(candidate=candidate),
    ),
)
```

Float rationalization is deterministic but does not participate in soundness.
A bad candidate returns `CandidateRejected`; it cannot mint a verified result.

## Eventual reciprocal-power bounds

Contract 2.4 checks a deliberately narrow quantitative-asymptotic family:

```python
from fractions import Fraction

n = ast.var("n", sort=ast.NATURAL)
claim = ast.eventually(
    3 / n**2 <= Fraction(1, 1000),
    variable=n,
)
result = lc.prove(claim)
```

The bridge performs bounded exponential search and binary refinement as
untrusted candidate generation. `VerifiedEventualBound` is returned only when
`LeanCert.Validity.checkReciprocalPowerUpper` accepts the retained cutoff; the
result records the search bracket, counts, completion state, checker, Golden
Theorem, and exact fixed payload. A caller can bypass discovery with
`cutoff=100` or control its budget with
`EventualConfig(max_checks=...)`.

## Exact inputs

New semantic claims reject Python floats. Use integers, `Fraction`, `Decimal`,
or decimal strings:

```python
from fractions import Fraction

claim = x <= Fraction(1, 10)
```

Malformed claims and incomplete `where` mappings raise AST validation errors.
Ordinary mathematical non-success remains a typed result:

- `Verified`: every requested checker accepted;
- `Inconclusive`: the checked enclosure was insufficient;
- `Unsupported`: no negotiated checked route covers the claim;
- `DomainObstruction`: a mathematical domain precondition failed;
- `Rejected`: reserved for a checked counterexample route.
- `CandidateRejected`: a system-root candidate failed its fixed checker.
- `EventualCandidateRejected`: a supplied or discovered cutoff was rejected.
- `InconclusiveEventualBound`: cutoff discovery exhausted its budget.

`verify_bound` remains available for the pre-1.0 expression API but is
deprecated. It delegates to its existing conservative checked implementation;
new code should construct `leancert.ast` claims and call `prove`.
