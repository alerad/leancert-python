# ruff: noqa: F403, F405
from __future__ import annotations

from fractions import Fraction
from functools import cache

from .claims import *
from .domains import *
from .expressions import *
from .relations import Relation


@cache
def _key(node):
    import json

    from .codec import _encode_node

    return json.dumps(_encode_node(node), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _const(v: Fraction, sort=RATIONAL):
    if sort == NATURAL and (v < 0 or v.denominator != 1):
        sort = INTEGER if v.denominator == 1 else RATIONAL
    if sort == INTEGER and v.denominator != 1:
        sort = RATIONAL
    return RationalConstant(v.numerator, v.denominator, sort)


def normalize(node):
    if isinstance(node, (RationalConstant, NamedConstant, Variable, TrueClaim, FalseClaim)):
        return node
    if isinstance(node, Cast):
        e = normalize(node.expression)
        if e.sort == node.target:
            return e
        if isinstance(e, Cast):
            return normalize(Cast(e.expression, node.target))
        if isinstance(e, RationalConstant):
            return _const(e.value, node.target)
        return node if e is node.expression else Cast(e, node.target)
    if isinstance(node, Neg):
        e = normalize(node.expression)
        if isinstance(e, RationalConstant):
            return _const(-e.value, e.sort)
        if isinstance(e, Neg):
            return e.expression
        return node if e is node.expression else Neg(e)
    if isinstance(node, Add):
        raw = []
        for t in node.terms:
            t = normalize(t)
            raw.extend(t.terms if isinstance(t, Add) else (t,))
        sort = node.sort
        c = Fraction(0)
        terms = []
        for t in raw:
            if isinstance(t, RationalConstant):
                c += t.value
            else:
                terms.append(cast(t, sort))
        terms.sort(key=_key)
        if c:
            terms.append(_const(c, sort))
        if not terms:
            return _const(Fraction(0), sort)
        if len(terms) == 1:
            return terms[0]
        result = Add(tuple(terms))
        return node if result == node else result
    if isinstance(node, Mul):
        raw = []
        for t in node.factors:
            t = normalize(t)
            raw.extend(t.factors if isinstance(t, Mul) else (t,))
        sort = node.sort
        c = Fraction(1)
        factors = []
        for t in raw:
            if isinstance(t, RationalConstant):
                c *= t.value
            else:
                factors.append(cast(t, sort))
        if c == 0:
            return _const(c, sort)
        factors.sort(key=_key)
        if c != 1:
            factors.insert(0, _const(c, sort))
        if not factors:
            return _const(c, sort)
        if len(factors) == 1:
            return factors[0]
        result = Mul(tuple(factors))
        return node if result == node else result
    if isinstance(node, Div):
        a, b = normalize(node.numerator), normalize(node.denominator)
        if isinstance(a, RationalConstant) and isinstance(b, RationalConstant) and b.value:
            return _const(a.value / b.value, node.sort)
        if isinstance(b, RationalConstant) and b.value == 1:
            return a
        return node if (a, b) == (node.numerator, node.denominator) else Div(a, b, node.sort)
    if isinstance(node, Pow):
        b, e = normalize(node.base), normalize(node.exponent)
        if isinstance(e, RationalConstant):
            if e.value == 1:
                return b
            if e.value == 0:
                return _const(Fraction(1), b.sort)
            if (
                isinstance(b, RationalConstant)
                and e.value.denominator == 1
                and (e.value >= 0 or b.value)
            ):
                return _const(b.value ** int(e.value), b.sort)
        return node if (b, e) == (node.base, node.exponent) else Pow(b, e)
    if isinstance(node, FunctionCall):
        args = tuple(normalize(a) for a in node.arguments)
        name = getattr(node.function, "name", None)
        if len(args) == 1 and isinstance(args[0], RationalConstant):
            v = args[0].value
            folds = {
                ("sin", Fraction(0)): 0,
                ("cos", Fraction(0)): 1,
                ("exp", Fraction(0)): 1,
                ("log", Fraction(1)): 0,
                ("abs", Fraction(0)): 0,
            }
            if (name, v) in folds:
                return _const(Fraction(folds[name, v]), REAL)
        return node if args == node.arguments else FunctionCall(node.function, args)
    if isinstance(node, Integral):
        e, d = normalize(node.integrand), normalize(node.domain)
        return node if (e, d) == (node.integrand, node.domain) else Integral(e, node.variable, d)
    if isinstance(node, Derivative):
        e = normalize(node.expression)
        return node if e is node.expression else Derivative(e, node.variable)
    if isinstance(node, Interval):
        a, b = normalize(node.lower), normalize(node.upper)
        return (
            node
            if (a, b) == (node.lower, node.upper)
            else Interval(a, b, node.lower_closed, node.upper_closed)
        )
    if isinstance(node, AxisDomain):
        return AxisDomain(node.variable, normalize(node.interval))
    if isinstance(node, Box):
        return Box(tuple(sorted((normalize(a) for a in node.axes), key=lambda a: _key(a.variable))))
    if isinstance(node, NaturalTail):
        return NaturalTail(node.variable, normalize(node.lower))
    if isinstance(node, ComparisonClaim):
        a, b = normalize(node.lhs), normalize(node.rhs)
        rel = node.relation
        if rel == Relation.GE:
            a, b, rel = b, a, Relation.LE
        elif rel == Relation.GT:
            a, b, rel = b, a, Relation.LT
        if rel in (Relation.EQ, Relation.NE) and _key(b) < _key(a):
            a, b = b, a
        if a == b:
            return TrueClaim() if rel in (Relation.LE, Relation.EQ) else FalseClaim()
        if isinstance(a, RationalConstant) and isinstance(b, RationalConstant):
            ops = {
                Relation.LT: lambda: x < y,
                Relation.LE: lambda: x <= y,
                Relation.EQ: lambda: x == y,
                Relation.NE: lambda: x != y,
            }
            x, y = a.value, b.value
            if rel in ops:
                return TrueClaim() if ops[rel]() else FalseClaim()
        return ComparisonClaim(a, rel, b)
    if isinstance(node, ConjunctionClaim):
        items = []
        for c in node.claims:
            c = normalize(c)
            if isinstance(c, FalseClaim):
                return c
            if isinstance(c, TrueClaim):
                continue
            items.extend(c.claims if isinstance(c, ConjunctionClaim) else (c,))
        items = sorted(set(items), key=_key)
        if not items:
            return TrueClaim()
        if len(items) == 1:
            return items[0]
        return ConjunctionClaim(tuple(items))
    if isinstance(node, DisjunctionClaim):
        items = tuple(normalize(c) for c in node.claims)
        if any(isinstance(c, TrueClaim) for c in items):
            return TrueClaim()
        items = tuple(sorted(set(c for c in items if not isinstance(c, FalseClaim)), key=_key))
        return (
            FalseClaim() if not items else items[0] if len(items) == 1 else DisjunctionClaim(items)
        )
    if isinstance(node, NegationClaim):
        return NegationClaim(normalize(node.claim))
    if isinstance(node, BoundedForAllClaim):
        return BoundedForAllClaim(
            Binder(node.binder.variable, normalize(node.binder.domain)), normalize(node.body)
        )
    if isinstance(node, (UniqueRootClaim, RootExcludedClaim, RootExistsClaim)):
        return type(node)(normalize(node.expression), node.variable, normalize(node.domain))
    if isinstance(node, SystemRootClaim):
        axes = {axis.variable.symbol.identifier: normalize(axis) for axis in node.domain.axes}
        domain = Box(tuple(axes[v.symbol.identifier] for v in node.variables))
        return SystemRootClaim(
            tuple(normalize(e) for e in node.equations), node.variables, domain, node.uniqueness
        )
    if isinstance(node, EventualClaim):
        return EventualClaim(
            node.variable,
            normalize(node.body),
            None if node.explicit_cutoff is None else normalize(node.explicit_cutoff),
        )
    if isinstance(node, Node):
        return node
    raise TypeError(f"not an AST node: {type(node).__name__}")


def semantically_equal(a, b):
    return normalize(a) == normalize(b)


def alpha_equivalent(a, b):
    from .codec import canonical_bytes

    return canonical_bytes(a) == canonical_bytes(b)
