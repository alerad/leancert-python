"""Single-source semantic AST compilation and canonical Core lowering."""

from __future__ import annotations

from typing import Any

from . import ast
from .exceptions import ProtocolViolation


class UnsupportedSemanticExpression(ValueError):
    pass


NAMED_CONSTANT_WIRE_NAMES = {
    ast.NamedConstantKind.PI: "pi",
    ast.NamedConstantKind.EULER_MASCHERONI: "euler_mascheroni",
}


def _rat(value) -> dict[str, int]:
    return {"n": value.numerator, "d": value.denominator}


def compile_semantic_expression(
    expression: ast.Expr,
    indices: dict[ast.SymbolId, int],
    advertised_nodes: frozenset[str],
) -> dict[str, Any]:
    """Compile an exact semantic expression to the negotiated Bridge schema."""

    def fold(kind: str, values: tuple[ast.Expr, ...]) -> dict[str, Any]:
        compiled = compile_one(values[0])
        for value in values[1:]:
            compiled = {"kind": kind, "e1": compiled, "e2": compile_one(value)}
        return compiled

    def compile_one(node: ast.Expr) -> dict[str, Any]:
        if isinstance(node, ast.RationalConstant):
            result = {"kind": "const", "val": _rat(node.value)}
        elif isinstance(node, ast.NamedConstant):
            try:
                name = NAMED_CONSTANT_WIRE_NAMES[node.constant]
            except KeyError as exc:
                raise UnsupportedSemanticExpression(
                    f"named constant {node.constant.value!r} has no Lean Core wire identity"
                ) from exc
            result = {"kind": "named_const", "name": name}
        elif isinstance(node, ast.Variable):
            try:
                index = indices[node.symbol.identifier]
            except KeyError as exc:
                raise UnsupportedSemanticExpression(
                    f"expression variable {node.name!r} is not bound by the claim domain"
                ) from exc
            result = {"kind": "var", "idx": index}
        elif isinstance(node, ast.Cast):
            return compile_one(node.expression)
        elif isinstance(node, ast.Neg):
            result = {"kind": "neg", "e": compile_one(node.expression)}
        elif isinstance(node, ast.Add):
            result = fold("add", node.terms)
        elif isinstance(node, ast.Mul):
            result = fold("mul", node.factors)
        elif isinstance(node, ast.Div):
            result = {
                "kind": "div",
                "e1": compile_one(node.numerator),
                "e2": compile_one(node.denominator),
            }
        elif isinstance(node, ast.Pow):
            exponent = node.exponent.value
            if exponent.denominator != 1 or exponent < 0:
                raise UnsupportedSemanticExpression(
                    "the checked bridge expression schema requires a non-negative integer power"
                )
            result = {"kind": "pow", "base": compile_one(node.base), "exp": int(exponent)}
        elif isinstance(node, ast.FunctionCall):
            if not isinstance(node.function, ast.BuiltinFunctionRef):
                raise UnsupportedSemanticExpression(
                    "external functions require a negotiated extension capability"
                )
            name = node.function.name
            arguments = tuple(compile_one(value) for value in node.arguments)
            if len(arguments) == 1:
                result = {"kind": name, "e": arguments[0]}
            elif len(arguments) == 2 and name in {"min", "max"}:
                result = {"kind": name, "e1": arguments[0], "e2": arguments[1]}
            else:
                raise UnsupportedSemanticExpression(
                    f"builtin function {name!r} has no bridge encoding"
                )
        else:
            raise UnsupportedSemanticExpression(
                f"expression node {type(node).__name__} is not supported by the checked Bridge"
            )
        if result["kind"] not in advertised_nodes:
            raise UnsupportedSemanticExpression(
                f"bridge did not advertise expression node {result['kind']!r}"
            )
        return result

    return compile_one(expression)


def lower_bridge_expression(value: dict[str, Any]) -> dict[str, Any]:
    """Lower one Bridge request expression to the canonical Lean Core AST."""
    kind = value["kind"]
    if kind in {"const", "var"}:
        return dict(value)
    if kind in {"add", "mul"}:
        return {
            "kind": kind,
            "e1": lower_bridge_expression(value["e1"]),
            "e2": lower_bridge_expression(value["e2"]),
        }
    if kind == "sub":
        return {
            "kind": "add",
            "e1": lower_bridge_expression(value["e1"]),
            "e2": {"kind": "neg", "e": lower_bridge_expression(value["e2"])},
        }
    if kind == "div":
        return {
            "kind": "mul",
            "e1": lower_bridge_expression(value["e1"]),
            "e2": {"kind": "inv", "e": lower_bridge_expression(value["e2"])},
        }
    if kind == "pow":
        base = lower_bridge_expression(value["base"])
        result: dict[str, Any] = {"kind": "const", "val": {"n": 1, "d": 1}}
        for _ in range(value["exp"]):
            result = {"kind": "mul", "e1": base, "e2": result}
        return result
    if kind == "tan":
        expression = lower_bridge_expression(value["e"])
        return {
            "kind": "mul",
            "e1": {"kind": "sin", "e": expression},
            "e2": {"kind": "inv", "e": {"kind": "cos", "e": expression}},
        }
    if kind == "sqrt":
        expression = lower_bridge_expression(value["e"])
        return {
            "kind": "exp",
            "e": {
                "kind": "mul",
                "e1": {"kind": "log", "e": expression},
                "e2": {"kind": "inv", "e": {"kind": "const", "val": {"n": 2, "d": 1}}},
            },
        }
    if kind == "abs":
        expression = lower_bridge_expression(value["e"])
        return {"kind": "sqrt", "e": {"kind": "mul", "e1": expression, "e2": expression}}
    if kind in {"min", "max"}:
        left = lower_bridge_expression(value["e1"])
        right = lower_bridge_expression(value["e2"])
        difference = {"kind": "add", "e1": left, "e2": {"kind": "neg", "e": right}}
        absolute = {"kind": "sqrt", "e": {"kind": "mul", "e1": difference, "e2": difference}}
        signed = absolute if kind == "max" else {"kind": "neg", "e": absolute}
        return {
            "kind": "mul",
            "e1": {"kind": "add", "e1": {"kind": "add", "e1": left, "e2": right}, "e2": signed},
            "e2": {"kind": "inv", "e": {"kind": "const", "val": {"n": 2, "d": 1}}},
        }
    if kind in {
        "neg",
        "inv",
        "exp",
        "sin",
        "cos",
        "log",
        "atan",
        "arsinh",
        "atanh",
        "sinc",
        "erf",
        "sinh",
        "cosh",
        "tanh",
    }:
        return {"kind": kind, "e": lower_bridge_expression(value["e"])}
    if kind == "named_const":
        if value.get("name") not in set(NAMED_CONSTANT_WIRE_NAMES.values()):
            raise ProtocolViolation(f"unsupported named constant: {value.get('name')!r}")
        return {"kind": kind, "name": value["name"]}
    raise ProtocolViolation(f"unsupported expression kind in checked lowering: {kind!r}")


__all__ = [
    "NAMED_CONSTANT_WIRE_NAMES",
    "UnsupportedSemanticExpression",
    "compile_semantic_expression",
    "lower_bridge_expression",
]
