"""Unified semantic claim proving through Bridge Contract 2.0."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import leancert as lc
from leancert import ast
from leancert.protocol import BridgeHandshake

FIXTURES = Path(__file__).parent / "fixtures" / "bridge-contract-2.0"


class FakeCheckedClient:
    def __init__(
        self,
        statuses: tuple[str, ...] = ("verified",),
        *,
        request_schema: str = "check-bound-request/1",
    ):
        info = json.loads((FIXTURES / "handshake.json").read_text())
        info["expression_nodes"].extend(
            ["neg", "mul", "div", "pow", "sin", "cos", "exp", "log", "sqrt"]
        )
        info["capabilities"]["check_bound"]["request_schema"] = request_schema
        self.bridge_contract = BridgeHandshake.parse(info)
        self.bridge_info = info
        self.statuses = list(statuses)
        self.calls: list[dict] = []

    def check_bound(
        self,
        expr_json,
        box_json,
        bound,
        is_upper_bound,
        taylor_depth=10,
    ):
        direction = "upper" if is_upper_bound else "lower"
        status = self.statuses.pop(0)
        self.calls.append(
            {
                "expr": expr_json,
                "box": box_json,
                "bound": bound,
                "direction": direction,
                "taylor_depth": taylor_depth,
            }
        )
        response = json.loads((FIXTURES / "verified-bound.json").read_text())
        response["direction"] = direction
        response["status"] = status
        response["verified"] = status == "verified"
        if status != "verified":
            response["certificate"] = None
        return response


def test_public_prove_checks_normalized_upper_bound():
    x = ast.var("x")
    client = FakeCheckedClient()

    result = lc.prove(ast.sin(x) <= 1, where={x: (0, 1)}, client=client)

    assert isinstance(result, lc.Verified)
    assert isinstance(result, lc.ProofResult)
    assert result.original_claim == (ast.sin(x) <= 1)
    assert not ast.free_variables(result.normalized_claim)
    assert result.claim_id == ast.semantic_digest(result.normalized_claim)
    assert result.provenance.protocol_version == "2.0.0"
    assert client.calls == [
        {
            "expr": {"kind": "sin", "e": {"kind": "var", "idx": 0}},
            "box": [{"lo": {"n": 0, "d": 1}, "hi": {"n": 1, "d": 1}}],
            "bound": {"n": 1, "d": 1},
            "direction": "upper",
            "taylor_depth": 10,
        }
    ]


def test_two_sided_claim_checks_each_bound_once():
    x = ast.var("x")
    client = FakeCheckedClient(("verified", "verified"))
    claim = ast.all_of(0 <= x**2, x**2 <= 1)  # noqa: SIM300 - canonical lower-bound syntax

    result = lc.prove(claim, where={x: (-1, 1)}, client=client)

    assert isinstance(result, lc.Verified)
    assert [call["direction"] for call in client.calls] == ["lower", "upper"]
    assert [check.direction for check in result.checks] == ["lower", "upper"]


def test_normalization_gives_equivalent_claims_the_same_identity():
    x = ast.var("x")
    left = lc.prove(x >= 0, where={x: (0, 1)}, client=FakeCheckedClient())
    right = lc.prove(
        0 <= x,  # noqa: SIM300 - intentionally exercises reversed normalization
        where={x: (0, 1)},
        client=FakeCheckedClient(),
    )
    assert left.claim_id == right.claim_id


@pytest.mark.parametrize(
    "claim",
    [
        lambda x: x < 1,
        lambda x: ast.root_exists(x, variable=x, within=ast.interval(0, 1)),
    ],
)
def test_unwired_claim_families_are_typed_unsupported_without_bridge_call(claim):
    x = ast.var("x")
    client = FakeCheckedClient()
    value = claim(x)
    where = {x: (0, 1)} if ast.free_variables(value) else None

    result = lc.prove(value, where=where, client=client)

    assert isinstance(result, lc.Unsupported)
    assert result.claim_id == ast.semantic_digest(result.normalized_claim)
    assert client.calls == []


def test_unadvertised_expression_node_is_unsupported_after_negotiation():
    x = ast.var("x")
    client = FakeCheckedClient()

    result = lc.prove(ast.arcsin(x) <= 1, where={x: (0, 1)}, client=client)

    assert isinstance(result, lc.Unsupported)
    assert "arcsin" in result.reason
    assert result.provenance.protocol_version == "2.0.0"
    assert client.calls == []


def test_unknown_checked_request_schema_is_not_sent():
    x = ast.var("x")
    client = FakeCheckedClient(request_schema="check-bound-request/2")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=client)
    assert isinstance(result, lc.Unsupported)
    assert "schemas" in result.reason
    assert client.calls == []


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        ("inconclusive", lc.Inconclusive),
        ("unsupported", lc.Unsupported),
        ("domain_obstruction", lc.DomainObstruction),
    ],
)
def test_checked_non_success_remains_typed(status, outcome):
    x = ast.var("x")
    result = lc.prove(x <= 1, where={x: (0, 1)}, client=FakeCheckedClient((status,)))
    assert isinstance(result, outcome)
    assert not isinstance(result, lc.Verified)


def test_prove_rejects_legacy_expressions_and_inexact_domains():
    legacy_x = lc.var("x")
    with pytest.raises(TypeError, match="leancert.ast.Claim"):
        lc.prove(legacy_x)

    x = ast.var("x")
    with pytest.raises(ast.InexactFloatError):
        lc.prove(x <= 1, where={x: (0.0, 1.0)}, client=FakeCheckedClient())


def test_prove_config_is_immutable_and_controls_checked_effort():
    x = ast.var("x")
    client = FakeCheckedClient()
    result = lc.prove(
        x <= 1,
        where={x: (0, 1)},
        config=lc.ProveConfig(taylor_depth=17),
        client=client,
    )
    assert isinstance(result, lc.Verified)
    assert client.calls[0]["taylor_depth"] == 17
    with pytest.raises(ValueError):
        lc.ProveConfig(taylor_depth=-1)


def test_solver_prove_reuses_its_client():
    x = ast.var("x")
    client = FakeCheckedClient()
    solver = lc.Solver(client=client)
    result = solver.prove(x <= 1, where={x: (0, 1)})
    assert isinstance(result, lc.Verified)
    assert len(client.calls) == 1
