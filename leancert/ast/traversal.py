from __future__ import annotations

from dataclasses import fields, is_dataclass, replace

from ._base import AstNode
from .claims import BoundedForAllClaim, EventualClaim, RootExistsClaim, SystemRootClaim
from .errors import SortMismatchError
from .expressions import Derivative, Expr, Integral, Variable


def children(node):
    return node.children()


def walk(node):
    yield node
    for child in node.children():
        yield from walk(child)


def node_count(node):
    return sum(1 for _ in walk(node))


def max_depth(node):
    cs = node.children()
    return 1 + (max(map(max_depth, cs)) if cs else 0)


def free_variables(node):
    result = set()

    def visit(n, bound):
        if isinstance(n, Variable):
            if n.symbol.identifier not in bound:
                result.add(n)
            return
        if isinstance(n, BoundedForAllClaim):
            visit(n.binder.domain, bound)
            visit(n.body, bound | {n.binder.variable.symbol.identifier})
            return
        if isinstance(n, EventualClaim):
            visit(n.body, bound | {n.variable.symbol.identifier})
            if n.explicit_cutoff is not None:
                visit(n.explicit_cutoff, bound)
            return
        if isinstance(n, RootExistsClaim):
            visit(n.domain, bound)
            visit(n.expression, bound | {n.variable.symbol.identifier})
            return
        if isinstance(n, SystemRootClaim):
            identifiers = {v.symbol.identifier for v in n.variables}
            visit(n.domain, bound | identifiers)
            for equation in n.equations:
                visit(equation, bound | identifiers)
            return
        if isinstance(n, Integral):
            visit(n.domain, bound)
            visit(n.integrand, bound | {n.variable.symbol.identifier})
            return
        if isinstance(n, Derivative):
            visit(n.expression, bound | {n.variable.symbol.identifier})
            return
        for c in n.children():
            visit(c, bound)

    visit(node, set())
    return frozenset(result)


def bound_variables(node):
    result = set()
    for n in walk(node):
        if isinstance(n, BoundedForAllClaim):
            result.add(n.binder.variable)
        elif isinstance(n, (EventualClaim, RootExistsClaim, Integral, Derivative)):
            result.add(n.variable)
        elif isinstance(n, SystemRootClaim):
            result.update(n.variables)
    return frozenset(result)


def collect_functions(node):
    from .expressions import FunctionCall

    return frozenset(n.function for n in walk(node) if isinstance(n, FunctionCall))


def collect_external_functions(node):
    from .functions import ExternalFunctionRef

    return frozenset(f for f in collect_functions(node) if isinstance(f, ExternalFunctionRef))


def collect_named_constants(node):
    from .expressions import NamedConstant

    return frozenset(n.constant for n in walk(node) if isinstance(n, NamedConstant))


def contains_node_type(node, kind):
    return any(isinstance(n, kind) for n in walk(node))


def fold(node, visitor):
    return visitor(node, tuple(fold(c, visitor) for c in node.children()))


def transform(node, fn):
    replacement = fn(node)
    if replacement is not node:
        return replacement
    if not is_dataclass(node):
        return node
    changes = {}
    for f in fields(node):
        if not f.init:
            continue
        v = getattr(node, f.name)
        if isinstance(v, AstNode):
            nv = transform(v, fn)
        elif isinstance(v, tuple):
            nv = tuple(transform(x, fn) if isinstance(x, AstNode) else x for x in v)
        else:
            continue
        if nv != v:
            changes[f.name] = nv
    return replace(node, **changes) if changes else node


def substitute(node, mapping):
    for old, new in mapping.items():
        if not isinstance(old, Variable):
            raise TypeError("substitution keys must be variables")
        if isinstance(new, Expr) and old.sort != new.sort:
            raise SortMismatchError(
                "substitution sort mismatch", expected=old.sort, actual=new.sort
            )

    def visit(n, bound):
        if isinstance(n, Variable):
            return n if n.symbol.identifier in bound else mapping.get(n, n)
        if isinstance(n, BoundedForAllClaim):
            identifier = n.binder.variable.symbol.identifier
            return BoundedForAllClaim(
                replace(n.binder, domain=visit(n.binder.domain, bound)),
                visit(n.body, bound | {identifier}),
            )
        if isinstance(n, EventualClaim):
            identifier = n.variable.symbol.identifier
            cutoff = None if n.explicit_cutoff is None else visit(n.explicit_cutoff, bound)
            return EventualClaim(n.variable, visit(n.body, bound | {identifier}), cutoff)
        if isinstance(n, RootExistsClaim):
            identifier = n.variable.symbol.identifier
            return type(n)(
                visit(n.expression, bound | {identifier}), n.variable, visit(n.domain, bound)
            )
        if isinstance(n, SystemRootClaim):
            identifiers = {v.symbol.identifier for v in n.variables}
            scope = bound | identifiers
            return SystemRootClaim(
                tuple(visit(e, scope) for e in n.equations),
                n.variables,
                visit(n.domain, scope),
                n.uniqueness,
            )
        if isinstance(n, Integral):
            identifier = n.variable.symbol.identifier
            return Integral(
                visit(n.integrand, bound | {identifier}), n.variable, visit(n.domain, bound)
            )
        if isinstance(n, Derivative):
            identifier = n.variable.symbol.identifier
            return Derivative(visit(n.expression, bound | {identifier}), n.variable)
        if not is_dataclass(n):
            return n
        changes = {}
        for f in fields(n):
            if not f.init:
                continue
            value = getattr(n, f.name)
            if isinstance(value, AstNode):
                new = visit(value, bound)
            elif isinstance(value, tuple):
                new = tuple(visit(x, bound) if isinstance(x, AstNode) else x for x in value)
            else:
                continue
            if new != value:
                changes[f.name] = new
        return replace(n, **changes) if changes else n

    return visit(node, set())


def rename_symbol(node, old, new):
    if not isinstance(old, Variable) or not isinstance(new, Variable):
        raise TypeError("rename_symbol expects variables")
    if old.sort != new.sort:
        raise SortMismatchError(
            "renamed variables must have the same sort", expected=old.sort, actual=new.sort
        )
    return transform(node, lambda n: new if isinstance(n, Variable) and n == old else n)


def map_expressions(node, function):
    return transform(node, lambda n: function(n) if isinstance(n, Expr) else n)
