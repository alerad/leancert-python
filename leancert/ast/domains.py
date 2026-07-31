from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._base import Node
from .errors import InvalidDomainError, SortMismatchError
from .expressions import Expr, RationalConstant, Variable, as_expr, cast
from .sorts import NATURAL, ScalarSort, common_sort


class Domain(Node):
    pass


@dataclass(frozen=True, slots=True)
class Interval(Domain):
    lower: Expr
    upper: Expr
    lower_closed: bool = True
    upper_closed: bool = True

    def __post_init__(self):
        object.__setattr__(self, "lower", as_expr(self.lower))
        object.__setattr__(self, "upper", as_expr(self.upper))
        common_sort(self.lower.sort, self.upper.sort)
        if not isinstance(self.lower.sort, ScalarSort):
            raise SortMismatchError("interval endpoints must be scalar")
        if (
            isinstance(self.lower, RationalConstant)
            and isinstance(self.upper, RationalConstant)
            and self.lower.value > self.upper.value
        ):
            raise InvalidDomainError("empty constant interval")

    @classmethod
    def closed(cls, a, b):
        return cls(as_expr(a), as_expr(b), True, True)

    @classmethod
    def open(cls, a, b):
        return cls(as_expr(a), as_expr(b), False, False)

    @classmethod
    def left_open(cls, a, b):
        return cls(as_expr(a), as_expr(b), False, True)

    @classmethod
    def right_open(cls, a, b):
        return cls(as_expr(a), as_expr(b), True, False)

    def children(self):
        return (self.lower, self.upper)


@dataclass(frozen=True, slots=True)
class AxisDomain(Node):
    variable: Variable
    interval: Interval

    def __post_init__(self):
        if not isinstance(self.variable.sort, ScalarSort):
            raise InvalidDomainError("box axes must be scalar variables")
        common_sort(self.variable.sort, self.interval.lower.sort)
        object.__setattr__(
            self,
            "interval",
            Interval(
                cast(self.interval.lower, self.variable.sort),
                cast(self.interval.upper, self.variable.sort),
                self.interval.lower_closed,
                self.interval.upper_closed,
            ),
        )

    def children(self):
        return (self.variable, self.interval)


@dataclass(frozen=True, slots=True)
class Box(Domain):
    axes: tuple[AxisDomain, ...]

    def __post_init__(self):
        axes = tuple(self.axes)
        if not axes:
            raise InvalidDomainError("box cannot be empty")
        ids = [a.variable.symbol.identifier for a in axes]
        if len(ids) != len(set(ids)):
            raise InvalidDomainError("duplicate box axis")
        object.__setattr__(self, "axes", axes)

    def children(self):
        return self.axes


@dataclass(frozen=True, slots=True)
class NaturalTail(Domain):
    variable: Variable
    lower: Expr

    def __post_init__(self):
        object.__setattr__(self, "lower", as_expr(self.lower))
        if self.variable.sort != NATURAL or self.lower.sort != NATURAL:
            raise InvalidDomainError("natural tail requires natural variable and cutoff")

    def children(self):
        return (self.variable, self.lower)


@dataclass(frozen=True, slots=True)
class SingletonDomain(Domain):
    value: Expr

    def __post_init__(self):
        object.__setattr__(self, "value", as_expr(self.value))

    def children(self):
        return (self.value,)


@dataclass(frozen=True, slots=True)
class FiniteSetDomain(Domain):
    values: tuple[Expr, ...]

    def __post_init__(self):
        vals = tuple(as_expr(v) for v in self.values)
        if not vals:
            raise InvalidDomainError("finite domain cannot be empty")
        for v in vals[1:]:
            common_sort(vals[0].sort, v.sort)
        object.__setattr__(self, "values", vals)

    def children(self):
        return self.values


@dataclass(frozen=True, slots=True)
class ProductDomain(Domain):
    domains: tuple[Domain, ...]

    def __post_init__(self):
        object.__setattr__(self, "domains", tuple(self.domains))

    def children(self):
        return self.domains


def box(mapping: Mapping[Variable, Interval | tuple[Any, Any]]) -> Box:
    return Box(
        tuple(
            AxisDomain(v, i if isinstance(i, Interval) else Interval.closed(*i))
            for v, i in mapping.items()
        )
    )
