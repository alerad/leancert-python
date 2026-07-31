from __future__ import annotations

from dataclasses import dataclass

from ._base import AstNode
from .claims import Claim, SystemRootClaim
from .errors import (
    ArityError,
    AstValidationError,
    DimensionMismatchError,
    DuplicateBinderError,
    FreeVariableError,
)
from .expressions import FunctionCall, Integral
from .traversal import walk


def validate_ast(node, *, require_closed=False):
    if not isinstance(node, AstNode):
        raise AstValidationError("value is not an AST node")
    for n in walk(node):
        if isinstance(n, FunctionCall) and len(n.arguments) != len(n.function.signature.arguments):
            raise ArityError("function arity mismatch")
        if isinstance(n, SystemRootClaim) and len(n.equations) != len(n.variables):
            raise DimensionMismatchError("system dimensions disagree")
    from .claims import BoundedForAllClaim, EventualClaim, RootExistsClaim
    from .expressions import Derivative

    def bind(identifier, scope):
        if identifier in scope:
            raise DuplicateBinderError("the same SymbolId cannot be rebound in a nested scope")
        return scope | {identifier}

    def scopes(n, scope):
        if isinstance(n, BoundedForAllClaim):
            scopes(n.binder.domain, scope)
            scopes(n.body, bind(n.binder.variable.symbol.identifier, scope))
            return
        if isinstance(n, EventualClaim):
            scopes(n.body, bind(n.variable.symbol.identifier, scope))
            if n.explicit_cutoff is not None:
                scopes(n.explicit_cutoff, scope)
            return
        if isinstance(n, RootExistsClaim):
            scopes(n.domain, scope)
            scopes(n.expression, bind(n.variable.symbol.identifier, scope))
            return
        if isinstance(n, SystemRootClaim):
            identifiers = [v.symbol.identifier for v in n.variables]
            if len(identifiers) != len(set(identifiers)) or any(
                identifier in scope for identifier in identifiers
            ):
                raise DuplicateBinderError(
                    "system-root binders must be distinct and cannot shadow an active binder"
                )
            inner = scope | set(identifiers)
            scopes(n.domain, inner)
            for equation in n.equations:
                scopes(equation, inner)
            return
        if isinstance(n, Integral):
            scopes(n.domain, scope)
            scopes(n.integrand, bind(n.variable.symbol.identifier, scope))
            return
        if isinstance(n, Derivative):
            scopes(n.expression, bind(n.variable.symbol.identifier, scope))
            return
        for child in n.children():
            scopes(child, scope)

    scopes(node, set())
    if require_closed:
        from .claims import Claim
        from .traversal import free_variables

        if isinstance(node, Claim) and free_variables(node):
            raise FreeVariableError("claim must be closed before bridge transmission")
    return node


@dataclass(frozen=True, slots=True)
class AstRequirements:
    builtins: frozenset[str]
    external_functions: frozenset
    sorts: frozenset[str]
    claim_features: frozenset[str]
    domain_features: frozenset[str]
    dimensions: frozenset[int]

    @property
    def features(self):
        return frozenset(
            {
                *(f"builtin.{x}" for x in self.builtins),
                *self.sorts,
                *self.claim_features,
                *self.domain_features,
            }
        )


def infer_requirements(node):
    from .domains import Box, Interval
    from .functions import BuiltinFunctionRef
    from .sorts import MatrixSort, VectorSort

    built = set()
    external = set()
    sorts = set()
    claims = set()
    domains = set()
    dimensions = set()
    for n in walk(node):
        if isinstance(n, FunctionCall):
            (
                built.add(n.function.name)
                if isinstance(n.function, BuiltinFunctionRef)
                else external.add(n.function)
            )
        if hasattr(n, "sort"):
            s = n.sort
            sorts.add(f"sort.{type(s).__name__.removesuffix('Sort').lower()}")
            if isinstance(s, VectorSort):
                dimensions.add(s.dimension)
            if isinstance(s, MatrixSort):
                dimensions |= {s.rows, s.columns}
        if isinstance(n, Claim):
            claims.add("claim." + n.node_kind.removesuffix("Claim").lower())
        if isinstance(n, Interval):
            domains.add("domain.interval")
        if isinstance(n, Box):
            domains.add("domain.box")
            dimensions.add(len(n.axes))
    return AstRequirements(
        frozenset(built),
        frozenset(external),
        frozenset(sorts),
        frozenset(claims),
        frozenset(domains),
        frozenset(dimensions),
    )


def check_capabilities(node, capability_manifest):
    req = infer_requirements(node)
    available = set(capability_manifest)
    return frozenset(req.features - available)
