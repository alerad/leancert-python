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

Strict inequalities, roots, integrals, eventual claims, and external functions
currently return `Unsupported`. They are not routed through a discovery API or
silently weakened to non-strict bounds. A bridge that does not advertise an
expression node receives no request for that node.

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

`verify_bound` remains available for the pre-1.0 expression API but is
deprecated. It delegates to its existing conservative checked implementation;
new code should construct `leancert.ast` claims and call `prove`.
