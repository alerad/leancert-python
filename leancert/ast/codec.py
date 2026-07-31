from __future__ import annotations

import json
from dataclasses import dataclass

from .errors import AstDecodeError, AstDecodeLimitError, NonCanonicalAstError, UnknownAstNodeVersion
from .version import AST_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class AstDecodeLimits:
    max_bytes: int = 10_000_000
    max_nodes: int = 100_000
    max_depth: int = 512
    max_string_length: int = 100_000
    max_integer_digits: int = 100_000
    max_collection_length: int = 100_000


DEFAULT_AST_DECODE_LIMITS = AstDecodeLimits()


def _sort(s):
    from .sorts import (
        BooleanSort,
        IntegerSort,
        MatrixSort,
        NaturalSort,
        RationalSort,
        RealSort,
        TupleSort,
        VectorSort,
    )

    names = {
        RealSort: "real",
        RationalSort: "rational",
        IntegerSort: "integer",
        NaturalSort: "natural",
        BooleanSort: "boolean",
    }
    if type(s) in names:
        return {"kind": names[type(s)]}
    if isinstance(s, VectorSort):
        return {"kind": "vector_sort", "element": _sort(s.element), "dimension": str(s.dimension)}
    if isinstance(s, MatrixSort):
        return {
            "kind": "matrix_sort",
            "element": _sort(s.element),
            "rows": str(s.rows),
            "columns": str(s.columns),
        }
    if isinstance(s, TupleSort):
        return {"kind": "tuple_sort", "elements": [_sort(x) for x in s.elements]}
    raise TypeError(type(s))


def _function(f):
    from .functions import BuiltinFunctionRef

    sig = {
        "arguments": [_sort(x) for x in f.signature.arguments],
        "result": _sort(f.signature.result),
    }
    if isinstance(f, BuiltinFunctionRef):
        return {
            "kind": "builtin_function",
            "name": f.name,
            "semantic_id": f.semantic_id,
            "signature": sig,
        }
    return {
        "kind": "external_function",
        "lean_name": f.lean_name,
        "semantic_id": f.semantic_id,
        "declaration_digest": f.declaration_digest,
        "signature": sig,
        "package": {
            "name": f.package.name,
            "source": f.package.source,
            "revision": f.package.revision,
            "environment_digest": f.package.environment_digest,
        },
    }


def _encode_node(n, bound=()):
    from .claims import (
        BoundedForAllClaim,
        ComparisonClaim,
        ConjunctionClaim,
        DisjunctionClaim,
        EventualClaim,
        FalseClaim,
        NegationClaim,
        RootExcludedClaim,
        RootExistsClaim,
        SystemRootClaim,
        TrueClaim,
        UniqueRootClaim,
    )
    from .domains import (
        AxisDomain,
        Box,
        FiniteSetDomain,
        Interval,
        NaturalTail,
        ProductDomain,
        SingletonDomain,
    )
    from .expressions import (
        Add,
        Cast,
        Derivative,
        Div,
        FunctionCall,
        Integral,
        Mul,
        NamedConstant,
        Neg,
        Pow,
        RationalConstant,
        Variable,
        Vector,
    )

    if isinstance(n, RationalConstant):
        return {
            "kind": "rational",
            "numerator": str(n.numerator),
            "denominator": str(n.denominator),
            "sort": _sort(n.sort),
        }
    if isinstance(n, NamedConstant):
        return {"kind": "named_constant", "constant": n.constant.value}
    if isinstance(n, Variable):
        sid = n.symbol.identifier
        for depth, b in enumerate(reversed(bound)):
            if sid == b:
                return {"kind": "bound_variable", "depth": str(depth), "sort": _sort(n.sort)}
        return {
            "kind": "variable",
            "namespace": sid.namespace,
            "name": sid.name,
            "display_name": n.name,
            "sort": _sort(n.sort),
        }
    if isinstance(n, Cast):
        return {
            "kind": "cast",
            "expression": _encode_node(n.expression, bound),
            "target": _sort(n.target),
        }
    if isinstance(n, Neg):
        return {"kind": "neg", "expression": _encode_node(n.expression, bound)}
    if isinstance(n, Add):
        return {"kind": "add", "terms": [_encode_node(x, bound) for x in n.terms]}
    if isinstance(n, Mul):
        return {"kind": "mul", "factors": [_encode_node(x, bound) for x in n.factors]}
    if isinstance(n, Div):
        return {
            "kind": "div",
            "numerator": _encode_node(n.numerator, bound),
            "denominator": _encode_node(n.denominator, bound),
            "sort": _sort(n.sort),
        }
    if isinstance(n, Pow):
        return {
            "kind": "pow",
            "base": _encode_node(n.base, bound),
            "exponent": _encode_node(n.exponent, bound),
        }
    if isinstance(n, FunctionCall):
        return {
            "kind": "function_call",
            "function": _function(n.function),
            "arguments": [_encode_node(x, bound) for x in n.arguments],
        }
    if isinstance(n, Vector):
        return {"kind": "vector", "elements": [_encode_node(x, bound) for x in n.elements]}
    if isinstance(n, Integral):
        sid = n.variable.symbol.identifier
        return {
            "kind": "integral",
            "variable_sort": _sort(n.variable.sort),
            "domain": _encode_node(n.domain, bound),
            "integrand": _encode_node(n.integrand, bound + (sid,)),
        }
    if isinstance(n, Derivative):
        sid = n.variable.symbol.identifier
        return {
            "kind": "derivative",
            "variable_sort": _sort(n.variable.sort),
            "expression": _encode_node(n.expression, bound + (sid,)),
        }
    if isinstance(n, Interval):
        return {
            "kind": "interval",
            "lower": _encode_node(n.lower, bound),
            "upper": _encode_node(n.upper, bound),
            "lower_closed": n.lower_closed,
            "upper_closed": n.upper_closed,
        }
    if isinstance(n, AxisDomain):
        return {
            "kind": "axis",
            "variable": _encode_node(n.variable, bound),
            "interval": _encode_node(n.interval, bound),
        }
    if isinstance(n, Box):
        return {"kind": "box", "axes": [_encode_node(x, bound) for x in n.axes]}
    if isinstance(n, NaturalTail):
        return {
            "kind": "natural_tail",
            "variable": _encode_node(n.variable, bound),
            "lower": _encode_node(n.lower, bound),
        }
    if isinstance(n, SingletonDomain):
        return {"kind": "singleton_domain", "value": _encode_node(n.value, bound)}
    if isinstance(n, FiniteSetDomain):
        return {"kind": "finite_set_domain", "values": [_encode_node(x, bound) for x in n.values]}
    if isinstance(n, ProductDomain):
        return {"kind": "product_domain", "domains": [_encode_node(x, bound) for x in n.domains]}
    if isinstance(n, TrueClaim):
        return {"kind": "true"}
    if isinstance(n, FalseClaim):
        return {"kind": "false"}
    if isinstance(n, ComparisonClaim):
        return {
            "kind": "comparison",
            "lhs": _encode_node(n.lhs, bound),
            "relation": n.relation.value,
            "rhs": _encode_node(n.rhs, bound),
        }
    if isinstance(n, ConjunctionClaim):
        return {"kind": "conjunction", "claims": [_encode_node(x, bound) for x in n.claims]}
    if isinstance(n, DisjunctionClaim):
        return {"kind": "disjunction", "claims": [_encode_node(x, bound) for x in n.claims]}
    if isinstance(n, NegationClaim):
        return {"kind": "not", "claim": _encode_node(n.claim, bound)}
    if isinstance(n, BoundedForAllClaim):
        sid = n.binder.variable.symbol.identifier
        return {
            "kind": "forall",
            "variable_sort": _sort(n.binder.variable.sort),
            "domain": _encode_node(n.binder.domain, bound),
            "body": _encode_node(n.body, bound + (sid,)),
        }
    roots = {
        UniqueRootClaim: "unique_root",
        RootExcludedClaim: "root_excluded",
        RootExistsClaim: "root_exists",
    }
    if type(n) in roots:
        return {
            "kind": roots[type(n)],
            "expression": _encode_node(n.expression, bound + (n.variable.symbol.identifier,)),
            "variable_sort": _sort(n.variable.sort),
            "domain": _encode_node(n.domain, bound),
        }
    if isinstance(n, SystemRootClaim):
        identifiers = tuple(v.symbol.identifier for v in n.variables)
        scope = bound + identifiers
        axes = {axis.variable.symbol.identifier: axis for axis in n.domain.axes}
        ordered_domain = Box(tuple(axes[identifier] for identifier in identifiers))
        return {
            "kind": "system_root",
            "variable_sorts": [_sort(v.sort) for v in n.variables],
            "equations": [_encode_node(x, scope) for x in n.equations],
            "domain": _encode_node(ordered_domain, scope),
            "uniqueness": n.uniqueness,
        }
    if isinstance(n, EventualClaim):
        return {
            "kind": "eventual",
            "variable_sort": _sort(n.variable.sort),
            "body": _encode_node(n.body, bound + (n.variable.symbol.identifier,)),
            "explicit_cutoff": None
            if n.explicit_cutoff is None
            else _encode_node(n.explicit_cutoff, bound),
        }
    raise TypeError(f"unsupported AST node {type(n).__name__}")


def encode_canonical(node):
    from .annotations import Annotated
    from .normalize import normalize

    if isinstance(node, Annotated):
        node = node.value
    return {
        "schema": "leancert.ast",
        "version": AST_SCHEMA_VERSION,
        "root": _encode_node(normalize(node)),
    }


def canonical_bytes(node):
    return json.dumps(
        encode_canonical(node),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise AstDecodeError(f"duplicate key: {k}")
        d[k] = v
    return d


def _expect(d, keys):
    if set(d) != set(keys):
        raise AstDecodeError(f"fields mismatch: expected {sorted(keys)}, got {sorted(d)}")


def _ds(d):
    from .sorts import BOOLEAN, INTEGER, NATURAL, RATIONAL, REAL, MatrixSort, TupleSort, VectorSort

    k = d.get("kind")
    simple = {
        "real": REAL,
        "rational": RATIONAL,
        "integer": INTEGER,
        "natural": NATURAL,
        "boolean": BOOLEAN,
    }
    if k in simple:
        _expect(d, {"kind"})
        return simple[k]
    if k == "vector_sort":
        _expect(d, {"kind", "element", "dimension"})
        return VectorSort(_ds(d["element"]), int(d["dimension"]))
    if k == "matrix_sort":
        _expect(d, {"kind", "element", "rows", "columns"})
        return MatrixSort(_ds(d["element"]), int(d["rows"]), int(d["columns"]))
    if k == "tuple_sort":
        _expect(d, {"kind", "elements"})
        return TupleSort(tuple(_ds(x) for x in d["elements"]))
    raise AstDecodeError("unknown sort")


def _df(d):
    from .functions import (
        BuiltinFunctionRef,
        ExternalFunctionRef,
        FunctionSignature,
        PackageIdentity,
    )

    _expect(d["signature"], {"arguments", "result"})
    sig = FunctionSignature(
        tuple(_ds(x) for x in d["signature"]["arguments"]), _ds(d["signature"]["result"])
    )
    if d["kind"] == "builtin_function":
        _expect(d, {"kind", "name", "semantic_id", "signature"})
        return BuiltinFunctionRef(d["name"], sig, d["semantic_id"])
    if d["kind"] != "external_function":
        raise AstDecodeError("unknown function kind")
    _expect(d, {"kind", "lean_name", "semantic_id", "declaration_digest", "signature", "package"})
    p = d["package"]
    _expect(p, {"name", "source", "revision", "environment_digest"})
    return ExternalFunctionRef(
        d["lean_name"],
        sig,
        PackageIdentity(p["name"], p["source"], p["revision"], p["environment_digest"]),
        d["semantic_id"],
        d["declaration_digest"],
    )


def _decode(d, bound=()):
    from .claims import (
        Binder,
        BoundedForAllClaim,
        ComparisonClaim,
        ConjunctionClaim,
        DisjunctionClaim,
        EventualClaim,
        FalseClaim,
        NegationClaim,
        RootExcludedClaim,
        RootExistsClaim,
        SystemRootClaim,
        TrueClaim,
        UniqueRootClaim,
    )
    from .constants import NamedConstantKind
    from .domains import (
        AxisDomain,
        Box,
        FiniteSetDomain,
        Interval,
        NaturalTail,
        ProductDomain,
        SingletonDomain,
    )
    from .expressions import (
        Add,
        Cast,
        Derivative,
        Div,
        FunctionCall,
        Integral,
        Mul,
        NamedConstant,
        Neg,
        Pow,
        RationalConstant,
        Variable,
        Vector,
    )
    from .relations import Relation
    from .symbols import Symbol, SymbolId

    k = d.get("kind")
    if k == "rational":
        return RationalConstant(int(d["numerator"]), int(d["denominator"]), _ds(d["sort"]))
    if k == "named_constant":
        return NamedConstant(NamedConstantKind(d["constant"]))
    if k == "variable":
        return Variable(
            Symbol(SymbolId(d["namespace"], d["name"]), d["display_name"], _ds(d["sort"]))
        )
    if k == "bound_variable":
        return bound[-1 - int(d["depth"])]
    if k == "cast":
        return Cast(_decode(d["expression"], bound), _ds(d["target"]))
    if k == "neg":
        return Neg(_decode(d["expression"], bound))
    if k == "add":
        return Add(tuple(_decode(x, bound) for x in d["terms"]))
    if k == "mul":
        return Mul(tuple(_decode(x, bound) for x in d["factors"]))
    if k == "div":
        return Div(_decode(d["numerator"], bound), _decode(d["denominator"], bound), _ds(d["sort"]))
    if k == "pow":
        return Pow(_decode(d["base"], bound), _decode(d["exponent"], bound))
    if k == "function_call":
        return FunctionCall(_df(d["function"]), tuple(_decode(x, bound) for x in d["arguments"]))
    if k == "vector":
        return Vector(tuple(_decode(x, bound) for x in d["elements"]))
    if k == "derivative":
        from .symbols import Symbol, SymbolId

        v = Variable(
            Symbol(SymbolId("decoded", f"b{len(bound)}"), f"b{len(bound)}", _ds(d["variable_sort"]))
        )
        return Derivative(_decode(d["expression"], bound + (v,)), v)
    if k == "interval":
        return Interval(
            _decode(d["lower"], bound),
            _decode(d["upper"], bound),
            d["lower_closed"],
            d["upper_closed"],
        )
    if k == "axis":
        return AxisDomain(_decode(d["variable"], bound), _decode(d["interval"], bound))
    if k == "box":
        return Box(tuple(_decode(x, bound) for x in d["axes"]))
    if k == "natural_tail":
        return NaturalTail(_decode(d["variable"], bound), _decode(d["lower"], bound))
    if k == "singleton_domain":
        return SingletonDomain(_decode(d["value"], bound))
    if k == "finite_set_domain":
        return FiniteSetDomain(tuple(_decode(x, bound) for x in d["values"]))
    if k == "product_domain":
        return ProductDomain(tuple(_decode(x, bound) for x in d["domains"]))
    if k == "true":
        return TrueClaim()
    if k == "false":
        return FalseClaim()
    if k == "comparison":
        return ComparisonClaim(
            _decode(d["lhs"], bound), Relation(d["relation"]), _decode(d["rhs"], bound)
        )
    if k == "conjunction":
        return ConjunctionClaim(tuple(_decode(x, bound) for x in d["claims"]))
    if k == "disjunction":
        return DisjunctionClaim(tuple(_decode(x, bound) for x in d["claims"]))
    if k == "not":
        return NegationClaim(_decode(d["claim"], bound))
    if k in ("forall", "eventual", "root_exists", "unique_root", "root_excluded", "integral"):
        v = Variable(
            Symbol(SymbolId("decoded", f"b{len(bound)}"), f"b{len(bound)}", _ds(d["variable_sort"]))
        )
        if k == "forall":
            return BoundedForAllClaim(
                Binder(v, _decode(d["domain"], bound)), _decode(d["body"], bound + (v,))
            )
        if k == "eventual":
            return EventualClaim(
                v,
                _decode(d["body"], bound + (v,)),
                None if d["explicit_cutoff"] is None else _decode(d["explicit_cutoff"], bound),
            )
        if k == "integral":
            return Integral(_decode(d["integrand"], bound + (v,)), v, _decode(d["domain"], bound))
        cls = {
            "root_exists": RootExistsClaim,
            "unique_root": UniqueRootClaim,
            "root_excluded": RootExcludedClaim,
        }[k]
        return cls(_decode(d["expression"], bound + (v,)), v, _decode(d["domain"], bound))
    if k == "system_root":
        variables = tuple(
            Variable(
                Symbol(SymbolId("decoded", f"b{len(bound) + i}"), f"b{len(bound) + i}", _ds(s))
            )
            for i, s in enumerate(d["variable_sorts"])
        )
        scope = bound + variables
        return SystemRootClaim(
            tuple(_decode(x, scope) for x in d["equations"]),
            variables,
            _decode(d["domain"], scope),
            d["uniqueness"],
        )
    raise AstDecodeError(f"unknown node kind: {k!r}")


def decode_canonical(payload, limits=DEFAULT_AST_DECODE_LIMITS):
    try:
        if isinstance(payload, (bytes, str)):
            raw = payload if isinstance(payload, bytes) else payload.encode()
            if len(raw) > limits.max_bytes:
                raise AstDecodeLimitError("payload exceeds max_bytes")
            payload = json.loads(raw, object_pairs_hook=_pairs)
        _expect(payload, {"schema", "version", "root"})
        if payload["schema"] != "leancert.ast" or payload["version"] != AST_SCHEMA_VERSION:
            raise UnknownAstNodeVersion("unsupported AST schema/version")
        seen = 0

        def check(x, depth=0):
            nonlocal seen
            seen += 1
            if seen > limits.max_nodes:
                raise AstDecodeLimitError("payload exceeds max_nodes")
            if depth > limits.max_depth:
                raise AstDecodeLimitError("payload exceeds max_depth")
            if isinstance(x, str) and len(x) > limits.max_string_length:
                raise AstDecodeLimitError("string too long")
            if (
                isinstance(x, str)
                and x.lstrip("-").isdigit()
                and len(x.lstrip("-")) > limits.max_integer_digits
            ):
                raise AstDecodeLimitError("integer exceeds max_integer_digits")
            if isinstance(x, (list, dict)) and len(x) > limits.max_collection_length:
                raise AstDecodeLimitError("collection too long")
            for v in x.values() if isinstance(x, dict) else x if isinstance(x, list) else ():
                check(v, depth + 1)

        check(payload)
        return _decode(payload["root"])
    except (AstDecodeError, AstDecodeLimitError, UnknownAstNodeVersion):
        raise
    except Exception as exc:
        raise AstDecodeError(str(exc)) from exc


def decode_canonical_strict(payload, limits=DEFAULT_AST_DECODE_LIMITS):
    """Decode only canonical, normalized v1 payloads with no ignored fields."""
    decoded = decode_canonical(payload, limits)
    try:
        original = (
            json.loads(payload, object_pairs_hook=_pairs)
            if isinstance(payload, (str, bytes))
            else payload
        )
    except Exception as exc:
        raise AstDecodeError(str(exc)) from exc
    if original != encode_canonical(decoded):
        raise NonCanonicalAstError("payload is valid but not in canonical normalized form")
    return decoded


def decode_and_normalize(payload, limits=DEFAULT_AST_DECODE_LIMITS):
    from .normalize import normalize

    return normalize(decode_canonical(payload, limits))
