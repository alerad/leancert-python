# LeanCert

> **v1 overhaul licensing:** Post-baseline Python SDK work is source-available
> under a provisional evaluation license. Personal evaluation,
> non-commercial research, education, and bounded commercial, governmental,
> or other organizational proofs of concept are permitted; production and
> commercial use require written terms.
> Python SDK versions through `v0.3.2-apache-final`, LeanCert Core, and LeanCert
> Bridge remain separately available under Apache-2.0. See [LICENSE](LICENSE).

Formal verification for numerical Python code, powered by Lean4.

Write Python, get mathematical proofs. LeanCert proves properties about your code for *all* inputs, not just test samples.

## Installation

```bash
pip install leancert
```

The wheel is pure Python. On the first checked operation, `lean-runtime`
downloads the compatible Bridge ready-to-run program from the
`ghcr.io/alerad/leancert-bridge-programs` program library. The program contains
the precompiled Bridge and its runtime libraries, not a Mathlib source/build
tree. Later calls reuse it; no Bridge path or system-wide Lean installation is
needed.

Profile-enabled SDK releases pin that multi-platform program by immutable OCI
digest. Its content-addressed provenance records the exact Core and Bridge
revisions, Lean toolchain, protocol, and capability identity. Before accepting
checked results, the SDK verifies that this profile agrees with both the
program description and the running Bridge handshake.

Full LeanCert and Mathlib environments are hydrated lazily only for independent
kernel replay, source rebuild audits, or custom registered-enclosure profiles.
Those environments remain distinct from ready programs in result provenance: a
program establishes `compiled_checker`, while successful exported proof replay
establishes `kernel_replay`.

Set `LEAN_RUNTIME_AVAILABILITY=required` when CI must use a downloadable
environment, or `LEAN_RUNTIME_AVAILABILITY=local` to audit the source-build
path. An explicit `LEAN_RUNTIME_LIBRARIES` value replaces the SDK defaults,
including an empty value to disable environment-library lookup.

The v1 overhaul also includes a bridge-independent, exact semantic model under
`leancert.ast`. Its versioned encoding, binder rules, claim closure, and legacy
conversion boundary are documented in [Semantic AST v1](docs/semantic-ast.md).
The typed line-protocol negotiation and checked-response invariants are
documented in [Python protocol model v2](docs/protocol-v2.md).
The semantic claim front door is documented in
[Unified checked proving](docs/prove.md).
Verified bounds from Bridge Contract 2.1+ can also be exported as
[independently rebuildable Lean evidence](docs/export.md).
Bridge Contract 2.3 extends the same workflow to unique nonlinear-system roots
certified by exact rational Krawczyk certificates; NumPy and SciPy candidates
remain untrusted inputs.
Bridge Contract 2.4 adds exact reciprocal-power eventual bounds with supplied
or automatically discovered natural-number cutoffs.
Bridge Contract 2.5 adds fixed, replayable scalar-root checks for existence,
uniqueness, and exclusion on exact rational intervals.
Bridge Contract 2.6 adds exact polynomial integral equalities and replayable
one-sided integral bounds with fixed checked partitions.
Bridge Contract 2.7 adds replayable strict global bounds backed by an exact
interior margin and the existing checked non-strict Golden Theorems.
Bridge Contract 2.8 adds [profile-bound downstream enclosure rules](docs/registered-enclosures.md)
with immutable registry negotiation and candidate-free fixed replay.

Exported projects can be audited without rerunning Python or numerical search:

```bash
leancert verify exported_proofs/ --require-trust kernel
```

After installation, `leancert doctor` checks the managed environment,
negotiated contract, replay support, adaptive checked route, and runtime-owned
execution provenance.

## Quick Start

```python
import leancert as lc
from leancert import ast

# Define an exact semantic claim
x = ast.var("x")
claim = ast.sin(x) <= 1

# A Solver keeps one managed Lean process alive for the whole batch. The first
# proof prepares it; subsequent proofs normally reuse it in milliseconds.
with lc.Solver() as solver:
    result = solver.prove(claim, where={x: (0, 1)})
    if isinstance(result, lc.Verified):
        print(f"Verified claim {result.claim_id}")
        print(result.provenance)
    else:
        print(type(result).__name__, result.reason)

    # Two-sided claims use an explicit conjunction.
    two_sided = solver.prove(
        ast.all_of(x >= 0, x <= 1),
        where={x: (0, 1)},
    )

    # Compare two expressions directly; export retains this original theorem.
    comparison = solver.prove(x <= x + 1, where={x: (0, 1)})

    # Strict targets retain an exact interior checked bound for replay.
    strict = solver.prove(x < 2, where={x: (0, 1)})

    # Independent conjunction children are routed and retained separately.
    combined = solver.prove(
        ast.all_of(x**2 <= 1, ast.sin(x) <= 1),
        where={x: (-1, 1)},
    )

    # Discover and certify a cutoff for every n at or beyond it.
    from fractions import Fraction
    n = ast.var("n", sort=ast.NATURAL)
    eventual = solver.prove(
        ast.eventually(3 / n**2 <= Fraction(1, 1000), variable=n)
    )

    # Prove that one—and only one—root lies in the supplied interval.
    unique = solver.prove(ast.unique_root(x, variable=x, within=(-1, 1)))
    if isinstance(unique, lc.VerifiedUniqueRoot):
        # Preparing files is cheap. Pass verify=True, or run `leancert verify`
        # later, to hydrate dependencies and independently rebuild the proof.
        unique.export_lean_project("verified-unique-root", verify=False)

    # Exact polynomial integration and checked one-sided bounds.
    area = ast.integral(x**2, x, 0, 1)
    exact_area = solver.prove(ast.eq(area, Fraction(1, 3)))
    bounded_area = solver.prove(area <= Fraction(1, 2))
```

## Neural Network Verification

Verify properties of neural networks across entire input domains:

```python
import leancert as lc
from leancert.nn import TwoLayerReLUNetwork, Layer
import numpy as np

# Create/load a neural network
layer1 = Layer.from_numpy(
    weights=np.array([[2.0, -2.0], [-2.0, 2.0]]),
    bias=np.array([0.0, 0.0]),
    activation='relu'
)
layer2 = Layer.from_numpy(
    weights=np.array([[1.0, 1.0]]),
    bias=np.array([0.0]),
    activation='none'
)
network = TwoLayerReLUNetwork(layer1=layer1, layer2=layer2)

# Prove output bounds for ALL inputs in domain
verified = lc.verify_nn_bounds(
    network,
    {'x0': (-1, 1), 'x1': (-1, 1)},
    output_lower=-5,
    output_upper=5,
)
print(verified)  # True - proven for every possible input!
```

## Key Features

- **Checked Bounds**: Typed LeanCert checker outcomes with exact provenance
- **Neural Networks**: Verify ReLU networks, transformers
- **Root Finding**: Locate and isolate roots with guaranteed correctness
- **Integration**: Compute integral bounds
- **Independent Audit**: Rebuild exported fixed certificates with `leancert verify`
- **PyTorch Import**: Load weights directly from PyTorch models

## Supported Functions

The checked `ast` + `prove` route currently supports arithmetic plus `sin`,
`cos`, and `exp`. Other constructors exposed by the legacy expression API are
capability-gated and may return `Unsupported`; their presence in Python does
not imply that the negotiated Bridge can certify them. See the
[current capability notes](https://docs.leancert.io/python/proving/)
for the exact distinction.

## Why LeanCert?

Traditional testing samples inputs: `f(0.5)`, `f(1.0)`, etc. You can never test `f(0.7)` and the infinitely many values in between.

LeanCert uses interval arithmetic to check properties for all inputs
simultaneously. Every `Verified` result identifies the checker, Golden Theorem,
verification route, numerical backend, and exact bridge build that accepted the
certificate. Independently rebuildable Lean projects are a separate export
milestone rather than an implicit claim of this runtime API.

`Verified`, `Rejected`, `Unsupported`, `DomainObstruction`, and `Inconclusive`
are distinct outcomes. An enclosure that is too wide produces `Inconclusive`;
failure to find a counterexample is never reported as proof. Bridge Contract
2.2 provides a separate typed adaptive certificate route backed by LeanCert's
checked rational optimizer. It can close subdivision leaves that the fixed
replayable checker cannot, but is not mislabeled as a replayable `bound-check/2`
certificate.

## Links

- [Documentation](https://docs.leancert.io/python/)
- [Python SDK Repo](https://github.com/alerad/leancert-python)
- [Lean Core Repo](https://github.com/alerad/leancert)
- [Bridge Binaries Repo](https://github.com/alerad/leancert-bridge)
- [Examples](https://github.com/alerad/leancert-python/tree/main/examples)

## Development tests

`pytest` runs the Bridge-independent suite by default. Tests that launch a real
managed Lean process are explicit because a cold run may download and build
large dependencies:

```bash
pip install -e ".[test]"
pytest                         # fast/default suite
pytest -m integration          # managed-Bridge integration suite
```

LeanCert supports CPython 3.10 through 3.14. The complete default suite runs
on every supported Python version in CI. Runtime requirements stay minimal;
linting, type checking, PyTorch support, and release tooling are isolated in
the `lint`, `typecheck`, `pytorch`, and `release` extras respectively. The
`dev` extra remains a convenient test/lint/type-check bundle.

## License

Post-baseline v1 Python SDK material is source-available under the provisional
[LeanCert Evaluation License 1.0](LICENSES/LeanCert-Evaluation-1.0.txt).
Personal evaluation, education, non-commercial research, and a bounded
90-day commercial, governmental, or other organizational proof of concept are
permitted. Qualifying nonprofit education and non-commercial research are not
subject to that 90-day limit. Production deployment, commercial product
development, customer services, and SaaS/API deployment require a separate
written commercial license. Generated reports,
certificates, and proof artifacts lawfully created during permitted use remain
free to retain, publish, and use, including commercially; this does not grant
continued rights to execute the SDK. See [COMMERCIAL.md](COMMERCIAL.md) for the
commercial boundary and [LICENSE_SCOPE.toml](LICENSE_SCOPE.toml) for the
authoritative source classification.

Python SDK material through commit `716cb2d`, preserved by the tag
`v0.3.2-apache-final`, remains available under Apache-2.0. LeanCert Core,
LeanCert Bridge, and third-party components retain their separate licenses.
See [LICENSE](LICENSE),
[LICENSES/LeanCert-Evaluation-1.0.txt](LICENSES/LeanCert-Evaluation-1.0.txt),
and [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
