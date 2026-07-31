from __future__ import annotations

from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from ._base import Node, reject_bool
from .constants import NamedConstantKind
from .errors import ArityError, AstValidationError, DimensionMismatchError, SortMismatchError
from .functions import BuiltinFunctionRef, ExternalFunctionRef
from .sorts import (
    INTEGER,
    NATURAL,
    RATIONAL,
    REAL,
    Sort,
    VectorSort,
    can_cast,
    common_sort,
)
from .symbols import Symbol


class Expr(Node):
    sort: Sort

    def __bool__(self):
        reject_bool("expression")

    def __add__(self, o):
        return _binary(Add, self, o)

    def __radd__(self, o):
        return _binary(Add, o, self)

    def __sub__(self, o):
        return _binary(Add, self, Neg(as_expr(o)))

    def __rsub__(self, o):
        return _binary(Add, o, Neg(self))

    def __mul__(self, o):
        return _binary(Mul, self, o)

    def __rmul__(self, o):
        return _binary(Mul, o, self)

    def __truediv__(self, o):
        return Div.coerce(self, o)

    def __rtruediv__(self, o):
        return Div.coerce(o, self)

    def __pow__(self, o):
        return Pow(self, as_expr(o))

    def __neg__(self):
        return Neg(self)

    def __lt__(self, o):
        return _compare(self, "lt", o)

    def __le__(self, o):
        return _compare(self, "le", o)

    def __gt__(self, o):
        return _compare(self, "gt", o)

    def __ge__(self, o):
        return _compare(self, "ge", o)

    def free_variables(self):
        from .traversal import free_variables

        return free_variables(self)

    def normalize(self):
        from .normalize import normalize

        return normalize(self)

    def semantic_digest(self):
        from .digest import semantic_digest

        return semantic_digest(self)


@dataclass(frozen=True, slots=True)
class RationalConstant(Expr):
    numerator: int
    denominator: int = 1
    sort: Sort = RATIONAL

    def __post_init__(self):
        if self.denominator == 0:
            from .errors import InvalidConstantError

            raise InvalidConstantError("rational denominator cannot be zero")
        f = Fraction(self.numerator, self.denominator)
        object.__setattr__(self, "numerator", f.numerator)
        object.__setattr__(self, "denominator", f.denominator)
        if self.sort not in (NATURAL, INTEGER, RATIONAL, REAL):
            raise SortMismatchError("rational constant requires numeric scalar sort")
        if self.sort == NATURAL and f.denominator != 1 or self.sort == NATURAL and f < 0:
            raise SortMismatchError("natural constant must be a non-negative integer")
        if self.sort == INTEGER and f.denominator != 1:
            raise SortMismatchError("integer constant must be integral")

    @property
    def value(self):
        return Fraction(self.numerator, self.denominator)


@dataclass(frozen=True, slots=True)
class NamedConstant(Expr):
    constant: NamedConstantKind
    sort: Sort = REAL


@dataclass(frozen=True, slots=True)
class Variable(Expr):
    symbol: Symbol

    @property
    def sort(self):
        return self.symbol.sort

    @property
    def name(self):
        return self.symbol.display_name


@dataclass(frozen=True, slots=True)
class Cast(Expr):
    expression: Expr
    target: Sort

    def __post_init__(self):
        if not can_cast(self.expression.sort, self.target):
            raise SortMismatchError(
                "invalid numeric cast", expected=self.target, actual=self.expression.sort
            )

    @property
    def sort(self):
        return self.target

    def children(self):
        return (self.expression,)


@dataclass(frozen=True, slots=True)
class Neg(Expr):
    expression: Expr

    @property
    def sort(self):
        return self.expression.sort

    def children(self):
        return (self.expression,)


@dataclass(frozen=True, slots=True)
class Add(Expr):
    terms: tuple[Expr, ...]
    _sort: Sort = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "terms", tuple(self.terms))
        if len(self.terms) < 2:
            raise ArityError("Add requires at least two terms")
        s = self.terms[0].sort
        for t in self.terms[1:]:
            s = common_sort(s, t.sort)
        object.__setattr__(self, "_sort", s)

    @property
    def sort(self):
        return self._sort

    def children(self):
        return self.terms


@dataclass(frozen=True, slots=True)
class Mul(Expr):
    factors: tuple[Expr, ...]
    _sort: Sort = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "factors", tuple(self.factors))
        if len(self.factors) < 2:
            raise ArityError("Mul requires at least two factors")
        s = self.factors[0].sort
        for t in self.factors[1:]:
            s = common_sort(s, t.sort)
        object.__setattr__(self, "_sort", s)

    @property
    def sort(self):
        return self._sort

    def children(self):
        return self.factors


@dataclass(frozen=True, slots=True)
class Div(Expr):
    numerator: Expr
    denominator: Expr
    _sort: Sort

    @classmethod
    def coerce(cls, a, b):
        a, b = as_expr(a), as_expr(b)
        s = common_sort(a.sort, b.sort)
        if s in (NATURAL, INTEGER):
            s = RATIONAL
        return cls(cast(a, s), cast(b, s), s)

    @property
    def sort(self):
        return self._sort

    def children(self):
        return (self.numerator, self.denominator)


@dataclass(frozen=True, slots=True)
class Pow(Expr):
    base: Expr
    exponent: Expr

    def __post_init__(self):
        if not isinstance(self.exponent, RationalConstant) or self.exponent.denominator != 1:
            raise AstValidationError("powers require an exact integer exponent")

    @property
    def sort(self):
        return self.base.sort

    def children(self):
        return (self.base, self.exponent)


@dataclass(frozen=True, slots=True)
class FunctionCall(Expr):
    function: BuiltinFunctionRef | ExternalFunctionRef
    arguments: tuple[Expr, ...]

    def __post_init__(self):
        object.__setattr__(self, "arguments", tuple(self.arguments))
        if len(self.arguments) != len(self.function.signature.arguments):
            raise ArityError(
                "function arity mismatch",
                expected=len(self.function.signature.arguments),
                actual=len(self.arguments),
            )
        args = []
        for i, (a, s) in enumerate(
            zip(self.arguments, self.function.signature.arguments, strict=True)
        ):
            if not can_cast(a.sort, s):
                raise SortMismatchError(
                    f"{self.function.name if isinstance(self.function, BuiltinFunctionRef) else self.function.lean_name} argument {i} has wrong sort",
                    path=("arguments", i),
                    expected=s,
                    actual=a.sort,
                )
            args.append(cast(a, s))
        object.__setattr__(self, "arguments", tuple(args))

    @property
    def sort(self):
        return self.function.signature.result

    def children(self):
        return self.arguments


@dataclass(frozen=True, slots=True)
class Vector(Expr):
    elements: tuple[Expr, ...]
    _sort: Sort = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "elements", tuple(self.elements))
        if not self.elements:
            raise DimensionMismatchError("vector cannot be empty")
        s = self.elements[0].sort
        for e in self.elements[1:]:
            s = common_sort(s, e.sort)
        object.__setattr__(self, "_sort", VectorSort(s, len(self.elements)))

    @property
    def sort(self):
        return self._sort

    def children(self):
        return self.elements


@dataclass(frozen=True, slots=True)
class Integral(Expr):
    integrand: Expr
    variable: Variable
    domain: Any

    def __post_init__(self):
        from .domains import Interval

        if self.integrand.sort != REAL or self.variable.sort != REAL:
            raise SortMismatchError(
                "integrals currently require a real integrand and variable",
                expected=REAL,
                actual=(self.integrand.sort, self.variable.sort),
            )
        if not isinstance(self.domain, Interval):
            raise AstValidationError("integrals currently require an interval domain")
        object.__setattr__(
            self,
            "domain",
            Interval(
                cast(self.domain.lower, REAL),
                cast(self.domain.upper, REAL),
                self.domain.lower_closed,
                self.domain.upper_closed,
            ),
        )

    @property
    def sort(self):
        return self.integrand.sort

    def children(self):
        return (self.integrand, self.variable, self.domain)


@dataclass(frozen=True, slots=True)
class Derivative(Expr):
    """The partial derivative of ``expression`` with respect to ``variable``."""

    expression: Expr
    variable: Variable

    def __post_init__(self):
        if self.expression.sort != REAL or self.variable.sort != REAL:
            raise SortMismatchError(
                "derivatives currently require real expressions and variables",
                expected=REAL,
                actual=(self.expression.sort, self.variable.sort),
            )

    @property
    def sort(self):
        return REAL

    def children(self):
        return (self.expression, self.variable)


def cast(e: Expr, target: Sort) -> Expr:
    return e if e.sort == target else Cast(e, target)


def as_expr(x: Any) -> Expr:
    if isinstance(x, Expr):
        return x
    if isinstance(x, float):
        from .numeric import exact_fraction

        exact_fraction(x)
    if isinstance(x, (int, Fraction)):
        f = Fraction(x)
        s = (
            NATURAL
            if f.denominator == 1 and f >= 0
            else INTEGER
            if f.denominator == 1
            else RATIONAL
        )
        return RationalConstant(f.numerator, f.denominator, s)
    raise TypeError(f"cannot convert {type(x).__name__} to an AST expression")


def _binary(cls, a, b):
    a, b = as_expr(a), as_expr(b)
    s = common_sort(a.sort, b.sort)
    a, b = cast(a, s), cast(b, s)
    return cls((a, b))


def _compare(a, rel, b):
    from .claims import ComparisonClaim
    from .relations import Relation

    a, b = as_expr(a), as_expr(b)
    s = common_sort(a.sort, b.sort)
    return ComparisonClaim(cast(a, s), Relation(rel), cast(b, s))
