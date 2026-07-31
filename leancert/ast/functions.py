from __future__ import annotations

from dataclasses import dataclass

from ._base import Node
from .errors import AstValidationError
from .sorts import REAL, Sort


@dataclass(frozen=True, slots=True)
class FunctionSignature(Node):
    arguments: tuple[Sort, ...]
    result: Sort

    def __post_init__(self):
        object.__setattr__(self, "arguments", tuple(self.arguments))


@dataclass(frozen=True, slots=True)
class BuiltinFunctionRef(Node):
    name: str
    signature: FunctionSignature
    semantic_id: str


@dataclass(frozen=True, slots=True)
class PackageIdentity(Node):
    name: str
    source: str
    revision: str
    environment_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ExternalFunctionRef(Node):
    lean_name: str
    signature: FunctionSignature
    package: PackageIdentity
    semantic_id: str
    declaration_digest: str | None = None

    def __post_init__(self):
        if not all(
            (
                self.lean_name,
                self.semantic_id,
                self.package.name,
                self.package.source,
                self.package.revision,
            )
        ):
            raise AstValidationError("external function identity fields must be non-empty")


def _builtin(name: str, arity: int = 1):
    return BuiltinFunctionRef(
        name, FunctionSignature((REAL,) * arity, REAL), f"leancert.builtin.{name}.v1"
    )


SIN = _builtin("sin")
COS = _builtin("cos")
TAN = _builtin("tan")
EXP = _builtin("exp")
LOG = _builtin("log")
SQRT = _builtin("sqrt")
ABS = _builtin("abs")
MIN = _builtin("min", 2)
MAX = _builtin("max", 2)
ARCSIN = _builtin("arcsin")
ARCCOS = _builtin("arccos")
ATAN = _builtin("atan")
ARSINH = _builtin("arsinh")
ATANH = _builtin("atanh")
SINH = _builtin("sinh")
COSH = _builtin("cosh")
TANH = _builtin("tanh")
SINC = _builtin("sinc")
ERF = _builtin("erf")
