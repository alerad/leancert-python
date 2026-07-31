import json
import random
from fractions import Fraction
from pathlib import Path

import pytest

import leancert.ast as ast
from leancert import domain as legacy_domain
from leancert import expr as legacy_expr


def test_close_claim_is_closed_and_mapping_order_independent():
    x = ast.var("x")
    y = ast.var("y")
    claim = x + y <= 2
    left = ast.close_claim(claim, {x: (0, 1), y: (0, 1)})
    right = ast.close_claim(claim, {y: (0, 1), x: (0, 1)})
    assert not ast.free_variables(left)
    assert ast.canonical_bytes(left) == ast.canonical_bytes(right)
    assert isinstance(ast.semantic_digest(left), ast.ClaimDigest)


def test_close_claim_requires_exact_variable_identity_and_coverage():
    x = ast.var("x", namespace="model")
    lookalike = ast.var("x", namespace="other")
    with pytest.raises(ast.FreeVariableError, match="missing"):
        ast.close_claim(x <= 1, {lookalike: (0, 1)})
    with pytest.raises(ast.FreeVariableError):
        ast.ensure_closed_claim(x <= 1)


def test_system_roots_and_calculus_binders_are_alpha_equivalent():
    x, y = ast.var("x"), ast.var("y")
    a, b = ast.var("a", namespace="renamed"), ast.var("b", namespace="renamed")
    first = ast.unique_system_root(
        (x + y, x - y), variables=(x, y), within=ast.box({x: (-1, 1), y: (-1, 1)})
    )
    second = ast.unique_system_root(
        (a + b, a - b), variables=(a, b), within=ast.box({a: (-1, 1), b: (-1, 1)})
    )
    assert ast.alpha_equivalent(first, second)
    derivative = ast.derivative(ast.sin(x), x)
    assert ast.alpha_equivalent(derivative, ast.decode_canonical(ast.encode_canonical(derivative)))
    integral = ast.integral(x * x, x, 0, 1)
    assert ast.alpha_equivalent(integral, ast.decode_canonical(ast.encode_canonical(integral)))


def test_system_box_must_name_exactly_the_system_coordinates():
    x, y = ast.var("x"), ast.var("y")
    with pytest.raises(ast.DimensionMismatchError):
        ast.system_root_exists((x,), variables=(x,), within=ast.box({y: (0, 1)}))


def test_strict_decoder_and_resource_limits():
    x = ast.var("x")
    payload = ast.encode_canonical(x <= 1)
    payload["root"]["ignored"] = True
    assert ast.semantically_equal(ast.decode_canonical(payload), x <= 1)
    with pytest.raises(ast.NonCanonicalAstError):
        ast.decode_canonical_strict(payload)
    canonical = ast.encode_canonical(x <= 1)
    with pytest.raises(ast.AstDecodeLimitError, match="max_nodes"):
        ast.decode_canonical(canonical, ast.AstDecodeLimits(max_nodes=2))
    large = ast.encode_canonical(ast.const(10**20))
    with pytest.raises(ast.AstDecodeLimitError, match="max_integer_digits"):
        ast.decode_canonical(large, ast.AstDecodeLimits(max_integer_digits=10))


def test_legacy_adapter_preserves_exact_values_and_symbol_sharing():
    x = legacy_expr.var("x")
    expression = legacy_expr.sin(x) + Fraction(1, 3) * x**2
    domain = legacy_domain.Box({"x": (Fraction(0), Fraction(1))})
    claim, converted_domain, symbols = ast.legacy_bound_claim(expression, domain, upper=1)
    converted_x = symbols["x"]
    assert converted_x in ast.free_variables(claim)
    assert converted_domain.axes[0].variable == converted_x
    assert not ast.free_variables(
        ast.close_claim(claim, {converted_x: converted_domain.axes[0].interval})
    )


def test_new_builtin_adapters_have_authoritative_semantic_ids():
    x = ast.var("x")
    for expression in (ast.atan(x), ast.arsinh(x), ast.atanh(x), ast.inv(x)):
        assert isinstance(ast.semantic_digest(expression), ast.ExpressionDigest)


def test_substitution_does_not_rewrite_bound_occurrences():
    x, y = ast.var("x"), ast.var("y")
    quantified = ast.bounded_forall(x, ast.interval(0, 1), x + y <= 2)
    replaced = ast.substitute(quantified, {x: ast.const(10, ast.REAL), y: ast.const(1, ast.REAL)})
    assert ast.free_variables(replaced) == frozenset()
    assert ast.alpha_equivalent(replaced, ast.bounded_forall(x, ast.interval(0, 1), x + 1 <= 2))


def test_validation_rejects_nested_rebinding_of_one_symbol_identity():
    x = ast.var("x")
    nested = ast.bounded_forall(
        x, ast.interval(0, 1), ast.bounded_forall(x, ast.interval(0, 1), x <= 1)
    )
    with pytest.raises(ast.DuplicateBinderError):
        ast.validate_ast(nested)


def test_v1_golden_payloads_and_digests_are_stable():
    fixtures = Path(__file__).parent / "fixtures" / "ast-v1"
    expected = json.loads((fixtures / "digests.json").read_text())
    for filename, digest in expected.items():
        payload = (fixtures / filename).read_bytes()
        decoded = ast.decode_canonical_strict(payload)
        assert ast.canonical_bytes(decoded) == payload.rstrip(b"\n")
        assert str(ast.semantic_digest(decoded)) == digest


def test_deterministic_expression_corpus_is_idempotent_and_round_trips():
    rng = random.Random(4310)
    x, y = ast.var("x"), ast.var("y")
    expressions = [x, y, ast.const(0, ast.REAL), ast.const(1, ast.REAL)]
    for _ in range(100):
        left, right = rng.choice(expressions), rng.choice(expressions)
        operation = rng.randrange(5)
        if operation == 0:
            expression = left + right
        elif operation == 1:
            expression = left * right
        elif operation == 2:
            expression = left - right
        elif operation == 3:
            expression = ast.sin(left)
        else:
            expression = left ** rng.randrange(0, 4)
        expressions.append(expression)
        normalized = ast.normalize(expression)
        assert ast.normalize(normalized) == normalized
        decoded = ast.decode_canonical(ast.encode_canonical(expression))
        assert ast.canonical_bytes(decoded) == ast.canonical_bytes(expression)
