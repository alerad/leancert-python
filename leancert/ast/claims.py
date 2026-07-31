from __future__ import annotations

from dataclasses import dataclass

from ._base import Node, reject_bool
from .domains import Box, Domain, Interval
from .errors import AstValidationError, DimensionMismatchError
from .expressions import Expr, Variable, cast
from .relations import Relation
from .sorts import NATURAL, common_sort


class Claim(Node):
    def __bool__(self):
        reject_bool("claim")

    def normalize(self):
        from .normalize import normalize

        return normalize(self)

    def semantic_digest(self):
        from .digest import semantic_digest

        return semantic_digest(self)


@dataclass(frozen=True, slots=True)
class TrueClaim(Claim):
    pass


@dataclass(frozen=True, slots=True)
class FalseClaim(Claim):
    pass


@dataclass(frozen=True, slots=True)
class ComparisonClaim(Claim):
    lhs: Expr
    relation: Relation
    rhs: Expr

    def __post_init__(self):
        common_sort(self.lhs.sort, self.rhs.sort)

    def children(self):
        return (self.lhs, self.rhs)


@dataclass(frozen=True, slots=True)
class ConjunctionClaim(Claim):
    claims: tuple[Claim, ...]

    def __post_init__(self):
        object.__setattr__(self, "claims", tuple(self.claims))
        if not self.claims:
            raise AstValidationError("conjunction cannot be empty")

    def children(self):
        return self.claims


@dataclass(frozen=True, slots=True)
class DisjunctionClaim(Claim):
    claims: tuple[Claim, ...]

    def __post_init__(self):
        object.__setattr__(self, "claims", tuple(self.claims))
        if not self.claims:
            raise AstValidationError("disjunction cannot be empty")

    def children(self):
        return self.claims


@dataclass(frozen=True, slots=True)
class NegationClaim(Claim):
    claim: Claim

    def children(self):
        return (self.claim,)


@dataclass(frozen=True, slots=True)
class Binder(Node):
    variable: Variable
    domain: Domain

    def __post_init__(self):
        if isinstance(self.domain, Interval):
            object.__setattr__(
                self,
                "domain",
                Interval(
                    cast(self.domain.lower, self.variable.sort),
                    cast(self.domain.upper, self.variable.sort),
                    self.domain.lower_closed,
                    self.domain.upper_closed,
                ),
            )

    def children(self):
        return (self.variable, self.domain)


@dataclass(frozen=True, slots=True)
class BoundedForAllClaim(Claim):
    binder: Binder
    body: Claim

    def children(self):
        return (self.binder, self.body)


@dataclass(frozen=True, slots=True)
class RootExistsClaim(Claim):
    expression: Expr
    variable: Variable
    domain: Interval

    def __post_init__(self):
        from .sorts import REAL

        if self.expression.sort != REAL or self.variable.sort != REAL:
            raise AstValidationError("scalar root claims require a real expression and variable")
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

    def children(self):
        return (self.expression, self.variable, self.domain)


@dataclass(frozen=True, slots=True)
class UniqueRootClaim(RootExistsClaim):
    pass


@dataclass(frozen=True, slots=True)
class RootExcludedClaim(RootExistsClaim):
    pass


@dataclass(frozen=True, slots=True)
class SystemRootClaim(Claim):
    equations: tuple[Expr, ...]
    variables: tuple[Variable, ...]
    domain: Box
    uniqueness: bool = False

    def __post_init__(self):
        object.__setattr__(self, "equations", tuple(self.equations))
        object.__setattr__(self, "variables", tuple(self.variables))
        if len(self.equations) != len(self.variables) or len(self.variables) != len(
            self.domain.axes
        ):
            raise DimensionMismatchError(
                "system equations, variables, and box dimensions must agree"
            )
        from .sorts import REAL

        if any(e.sort != REAL for e in self.equations) or any(
            v.sort != REAL for v in self.variables
        ):
            raise AstValidationError("system root claims require real equations and variables")
        variable_ids = {v.symbol.identifier for v in self.variables}
        axis_ids = {axis.variable.symbol.identifier for axis in self.domain.axes}
        if variable_ids != axis_ids:
            raise DimensionMismatchError(
                "system variables and box axes must identify the same coordinates"
            )

    def children(self):
        return self.equations + self.variables + (self.domain,)


@dataclass(frozen=True, slots=True)
class EventualClaim(Claim):
    variable: Variable
    body: Claim
    explicit_cutoff: Expr | None = None

    def __post_init__(self):
        if self.variable.sort != NATURAL:
            raise AstValidationError("eventual variable must have Natural sort")
        if self.explicit_cutoff is not None and self.explicit_cutoff.sort != NATURAL:
            raise AstValidationError("eventual cutoff must have Natural sort")

    def children(self):
        return (
            (self.variable, self.body)
            if self.explicit_cutoff is None
            else (self.variable, self.body, self.explicit_cutoff)
        )
