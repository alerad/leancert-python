"""Explicit adapters from the pre-1.0 Python expression and domain classes."""

from __future__ import annotations

from .builders import (
    abs as ast_abs,
)
from .builders import (
    arsinh,
    atan,
    atanh,
    cos,
    cosh,
    erf,
    exp,
    inv,
    log,
    sin,
    sinc,
    sinh,
    sqrt,
    tan,
    tanh,
)
from .builders import (
    max as ast_max,
)
from .builders import (
    min as ast_min,
)
from .claims import ComparisonClaim
from .domains import Box, Interval, box
from .expressions import Add, Div, Mul, Neg, Pow, Variable, as_expr
from .relations import Relation
from .sorts import REAL
from .symbols import Symbol, SymbolId


class _Symbols:
    def __init__(self, namespace: str):
        self.namespace = namespace
        self.values: dict[str, Variable] = {}

    def get(self, name: str) -> Variable:
        return self.values.setdefault(
            name, Variable(Symbol(SymbolId(self.namespace, name), name, REAL))
        )


def _expression(value, symbols: _Symbols):
    from leancert import expr as old

    if isinstance(value, old.Variable):
        return symbols.get(value.name)
    if isinstance(value, old.Const):
        return as_expr(value.value)
    if isinstance(value, old.Add):
        return Add((_expression(value.e1, symbols), _expression(value.e2, symbols)))
    if isinstance(value, old.Sub):
        return Add((_expression(value.e1, symbols), Neg(_expression(value.e2, symbols))))
    if isinstance(value, old.Mul):
        return Mul((_expression(value.e1, symbols), _expression(value.e2, symbols)))
    if isinstance(value, old.Div):
        return Div.coerce(_expression(value.e1, symbols), _expression(value.e2, symbols))
    if isinstance(value, old.Pow):
        return Pow(_expression(value.base, symbols), as_expr(value.n))
    if isinstance(value, old.Neg):
        return Neg(_expression(value.e, symbols))
    unary = {
        old.Sin: sin,
        old.Cos: cos,
        old.Exp: exp,
        old.Log: log,
        old.Sqrt: sqrt,
        old.Tan: tan,
        old.Atan: atan,
        old.Inv: inv,
        old.Arsinh: arsinh,
        old.Atanh: atanh,
        old.Sinc: sinc,
        old.Erf: erf,
        old.Sinh: sinh,
        old.Cosh: cosh,
        old.Tanh: tanh,
        old.Abs: ast_abs,
    }
    for kind, function in unary.items():
        if isinstance(value, kind):
            return function(_expression(value.e, symbols))
    if isinstance(value, old.MinExpr):
        return ast_min(_expression(value.e1, symbols), _expression(value.e2, symbols))
    if isinstance(value, old.MaxExpr):
        return ast_max(_expression(value.e1, symbols), _expression(value.e2, symbols))
    raise TypeError(f"unsupported legacy expression: {type(value).__name__}")


def legacy_expression(value, *, namespace: str = "legacy"):
    """Convert one legacy ``leancert.expr.Expr`` without changing its value."""
    return _expression(value, _Symbols(namespace))


def legacy_interval(value) -> Interval:
    from leancert.domain import Interval as OldInterval

    if not isinstance(value, OldInterval):
        raise TypeError("legacy_interval expects leancert.domain.Interval")
    return Interval.closed(value.lo, value.hi)


def legacy_box(value, *, namespace: str = "legacy") -> Box:
    from leancert.domain import Box as OldBox

    if not isinstance(value, OldBox):
        raise TypeError("legacy_box expects leancert.domain.Box")
    symbols = _Symbols(namespace)
    return box({symbols.get(name): legacy_interval(interval) for name, interval in value.items()})


def legacy_bound_claim(expression, domain, *, upper=None, lower=None, namespace: str = "legacy"):
    """Convert a legacy expression/domain pair into one or two open comparisons.

    This adapter deliberately does not claim verification.  It only preserves
    the exact rational values already stored by the legacy objects.
    """
    if (upper is None) == (lower is None):
        raise TypeError("specify exactly one of upper or lower")
    from leancert.domain import Box as OldBox

    if not isinstance(domain, OldBox):
        raise TypeError("legacy_bound_claim expects leancert.domain.Box")
    symbols = _Symbols(namespace)
    converted = _expression(expression, symbols)
    converted_domain = box({symbols.get(name): legacy_interval(i) for name, i in domain.items()})
    relation = Relation.LE
    claim = (
        ComparisonClaim(converted, relation, as_expr(upper))
        if upper is not None
        else ComparisonClaim(as_expr(lower), relation, converted)
    )
    return claim, converted_domain, dict(symbols.values)
