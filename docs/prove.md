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

Module-level `lc.prove(...)` lazily retains one managed Lean client for reuse
within the Python process. For an explicit lifetime—especially in notebooks,
services, and proof batches—use a context-managed solver:

```python
with lc.Solver() as solver:
    first = solver.prove(x**2 <= 1, where={x: (-1, 1)})
    second = solver.prove(x < 2, where={x: (0, 1)})
```

The first checked proof may download and prepare the managed Bridge. Later
proofs reuse the same process. Call `lc.close_default_prove_client()` if an
application needs to release the module-level convenience client early.

## Checked bound surface

The first route supports exact, universally quantified real bounds over closed
rational intervals:

```python
upper = lc.prove(x**2 <= 1, where={x: (-1, 1)})
two_sided = lc.prove(
    ast.all_of(x >= -1, x <= 1),
    where={x: (-1, 1)},
)

# Either side may be an expression. LeanCert retains and exports the original
# semantic comparison rather than only its normalized checker expression.
comparison = lc.prove(x <= x + 1, where={x: (0, 1)})

# Contract 2.7 proves a strict target from a checked interior bound.
strict = lc.prove(x < 2, where={x: (0, 1)})
```

Non-trivial expression equality is routed as two inequalities and returns an
aggregate result. Exact identities that normalize immediately instead return
the explicitly labeled `NormalizedTrue` result described below.

Each requested lower or upper bound is checked exactly once. A successful
result retains the normalized closed claim, its `ClaimDigest`, the enclosure,
checker and verifier identities, verification route, numerical backend, and
the exact `lean-runtime` environment and execution identities. Contract 2.1
additionally retains the exact fixed checker input and runtime-resolved Lean
dependency identities needed for
[independently rebuildable export](export.md). Expression-to-expression
comparisons retain an explicit proof-relevant lowering record, so export states
and proves the original inequality rather than only its normalized checker
input.

Conjunctions that are not a single two-sided enclosure are routed recursively:

```python
result = lc.prove(
    ast.all_of(x**2 <= 1, ast.sin(x) <= 1),
    where={x: (-1, 1)},
)

if isinstance(result, lc.VerifiedConjunction):
    for child in result.children:
        print(type(child).__name__, child.claim_id)
```

`VerifiedConjunction` preserves every child result and can export compatible
replayable bound children as separate checked theorems plus a kernel-checked
conjunction theorem. If any child is unsupported or inconclusive, the result is
`IncompleteConjunction`; successful siblings are not discarded.

Contract 2.7 routes `<` and `>` only when the Bridge advertises
`check_strict_bound`. The optimizer proposes an exact rational interior bound;
Lean checks that fixed non-strict bound, and exact rational comparison supplies
the strict margin. A domain touching the target is `Inconclusive`, not silently
weakened to a non-strict claim. Older Bridges return `Unsupported` without
receiving a strict request.

External functions remain capability-gated. A bridge that does not
advertise an expression node receives no request for that node. Contract 2.8
provides the deliberately narrower
[registered downstream enclosure route](registered-enclosures.md): callable
handles come only from a frozen, handshake-validated profile and retain fixed
replay evidence. Arbitrary external function references remain unsupported.
The semantic
AST constants `ast.e` and `ast.log_two` currently have no Lean Core wire
identity and therefore remain precisely unsupported. `ast.pi` and
`ast.euler_mascheroni` use the canonical negotiated wire identities when the
Bridge advertises named constants.

### Tight margins near transcendental roots

The default Taylor effort (`ProveConfig(taylor_depth=10)`) can be too shallow
when the claim's margin is comparable to the enclosure's remainder — the
canonical case being `sin` evaluated near pi, where a `1e-4`-scale sign claim
meets a `~2e-3` remainder and returns `Inconclusive`. Two remedies, in order
of preference:

1. Reformulate at a smaller argument, where the same series converges much
   faster: `cos` at `pi/2` resolves what `sin` near `pi` cannot
   (`ast.cos(ast.const(Fraction(15722, 10**4))) < 0` certifies
   `pi < 3.1444` at default depth).
2. Raise the effort: `lc.ProveConfig(taylor_depth=20)` resolves
   `sin(3.1415) > 0`. Depth is a checker-effort knob and increases enclosure
   cost; prefer remedy 1 when a reformulation exists.

## Exact normalized claims

Some claims reduce exactly before a Bridge is needed:

```python
result = lc.prove(x <= x, where={x: (0, 1)})
assert isinstance(result, lc.NormalizedTrue)
assert result.authority == "python_exact_normalizer"
```

`NormalizedTrue` and `NormalizedFalse` deliberately do **not** pretend to be
Bridge-checked outcomes. Their separate authority label makes the boundary
explicit. Exact-false reduction is used only when the quantified domain is
provably inhabited.

## Nonlinear-system roots

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

`ast.system_root_exists(...)` uses the same route. The Krawczyk checker proves
the stronger uniqueness theorem, and the exported artifact derives the weaker
requested existence theorem from it. `VerifiedSystemRoot` records both
`requested_uniqueness` and `established_uniqueness` so this strengthening is
never implicit.

## Scalar roots

Contract 2.5 checks a supplied exact interval without treating numerical
search as proof authority:

```python
x = ast.var("x")

exists = lc.prove(ast.root_exists(x, variable=x, within=(-1, 1)))
unique = lc.prove(ast.unique_root(x, variable=x, within=(-1, 1)))
excluded = lc.prove(ast.root_excluded(x + 2, variable=x, within=(-1, 1)))
```

The successful outcomes are `VerifiedRootExistence`, `VerifiedUniqueRoot`,
and `VerifiedRootExclusion`. They retain respectively the fixed
`checkSignChange`, `checkNewtonContractsCore`, or `checkNoRoot` input and the
corresponding Golden Theorem. `ScalarRootCandidateRejected` means only that
the supplied interval did not satisfy the requested checker; it is not a
proof that the mathematical claim is false. All three verified outcomes
support standalone kernel replay with `export_lean_project()`.

## Definite integrals

Contract 2.6 distinguishes exact integration from enclosure-based bounds:

```python
from fractions import Fraction

x = ast.var("x")
area = ast.integral(x**2, x, 0, 1)

exact = lc.prove(ast.eq(area, Fraction(1, 3)))
upper = lc.prove(area <= Fraction(1, 2))
lower = lc.prove(Fraction(1, 4) <= area)
```

`VerifiedIntegralEquality` is available only when the rational-polynomial
checker computes the exact claimed value. `VerifiedIntegralBound` retains the
fixed uniform partition count accepted by the lower- or upper-bound checker.
Partition discovery is untrusted and its limits are configurable:

```python
config = lc.ProveConfig(
    integral=lc.IntegralConfig(start_partitions=16, max_partitions=4096),
)
```

A numerical enclosure never establishes equality. Verified equality and bound
results both support standalone kernel replay with `export_lean_project()`.

## Opt-in checked refutation

By default, an enclosure that does not establish a bound is
`Inconclusive`. Callers may enable a small deterministic search over exact
rational point boxes:

```python
result = lc.prove(
    x <= 0,
    where={x: (0, 2)},
    config=lc.ProveConfig(
        refutation=lc.RefutationConfig(enabled=True, max_candidates=9),
    ),
)
```

Search never authorizes rejection. LeanCert returns `Rejected` only after a
point enclosure lies wholly on the violating side **and** a second checked
opposite-direction bound certifies the strict separation. The result retains
that `refutation_check` and exact `CheckedCounterexample`. The feature is
disabled by default so existing proof effort remains unchanged.

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
- `NormalizedTrue` / `NormalizedFalse`: decided by exact Python AST normalization;
- `VerifiedConjunction` / `IncompleteConjunction`: child-preserving recursive results;
- `CandidateRejected`: a system-root candidate failed its fixed checker.
- `EventualCandidateRejected`: a supplied or discovered cutoff was rejected.
- `ScalarRootCandidateRejected`: the supplied interval failed its fixed root checker.
- `InconclusiveEventualBound`: cutoff discovery exhausted its budget.

`verify_bound` remains available for the pre-1.0 expression API but is
deprecated. It delegates to its existing conservative checked implementation;
new code should construct `leancert.ast` claims and call `prove`.
