# LeanCert

> **v1 overhaul licensing:** Work on the `v1-overhaul` development line is
> provisionally all-rights-reserved while final community and commercial terms
> are prepared. Python SDK versions through the baseline tagged
> `v0.3.2-apache-final` remain Apache-2.0. LeanCert Core and LeanCert Bridge
> remain separately available under Apache-2.0. See [LICENSE](LICENSE).

Formal verification for numerical Python code, powered by Lean4.

Write Python, get mathematical proofs. LeanCert proves properties about your code for *all* inputs, not just test samples.

## Installation

```bash
pip install leancert
```

That's it! The package includes pre-built binaries - no Lean installation required.

Bridge binaries are sourced from the decoupled `leancert-bridge` release tag
pinned in `bridge-version.txt`.

The v1 overhaul also includes a bridge-independent, exact semantic model under
`leancert.ast`. Its versioned encoding, binder rules, claim closure, and legacy
conversion boundary are documented in [Semantic AST v1](docs/semantic-ast.md).
The typed line-protocol negotiation and checked-response invariants are
documented in [Python protocol model v2](docs/protocol-v2.md).
The semantic claim front door is documented in
[Unified checked proving](docs/prove.md).
Verified bounds from Bridge Contract 2.1+ can also be exported as
[independently rebuildable Lean evidence](docs/export.md).

After installation, `leancert doctor` checks the bundled binary, negotiated
contract, replay support, adaptive checked route, and release provenance.

## Quick Start

```python
import leancert as lc
from leancert import ast

# Define an exact semantic claim
x = ast.var("x")
claim = ast.sin(x) <= 1

# Check it for every x in the closed interval [0, 1]
result = lc.prove(claim, where={x: (0, 1)})
if isinstance(result, lc.Verified):
    print(f"Verified claim {result.claim_id}")
    print(result.provenance)
else:
    print(type(result).__name__, result.reason)

# Two-sided claims use an explicit conjunction.
two_sided = lc.prove(
    ast.all_of(x >= 0, x <= 1),
    where={x: (0, 1)},
)
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
- **PyTorch Import**: Load weights directly from PyTorch models

## Supported Functions

`sin`, `cos`, `tan`, `exp`, `log`, `sqrt`, `abs`, `sinh`, `cosh`, `tanh`, `atan`, `erf`, `sinc`, and more.

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

- [Documentation](https://leancert.readthedocs.io)
- [Python SDK Repo](https://github.com/alerad/leancert-python)
- [Lean Core Repo](https://github.com/alerad/leancert)
- [Bridge Binaries Repo](https://github.com/alerad/leancert-bridge)
- [Examples](https://github.com/alerad/leancert-python/tree/main/examples)

## License

The v1 Python SDK overhaul is currently covered by a provisional
all-rights-reserved notice. No license is presently granted for post-baseline
v1 code. Do not use or redistribute that development code without written
permission.

Python SDK material through commit `716cb2d`, preserved by the tag
`v0.3.2-apache-final`, remains available under Apache-2.0. LeanCert Core,
LeanCert Bridge, and third-party components retain their separate licenses.
See [LICENSE](LICENSE) and [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
