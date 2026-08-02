"""Safety regressions for typed bound verification outcomes."""

from fractions import Fraction
from unittest.mock import patch

import pytest

from leancert import (
    DomainObstruction,
    Inconclusive,
    Rejected,
    Solver,
    Unsupported,
    Verified,
    var,
)
from leancert.domain import Box, Interval
from leancert.exceptions import VerificationInconclusive
from leancert.expr import _evaluate_batch
from leancert.validation import CounterexampleVerifier, ValidationVerdict


def rat(value: Fraction | int) -> dict[str, int]:
    value = Fraction(value)
    return {"n": value.numerator, "d": value.denominator}


class FakeClient:
    bridge_info = {
        "bridge_api_version": "1.0.0",
        "bridge_version": "test",
        "lean_version": "4.31.0",
    }

    def __init__(self, check_responses, optimize_response=None):
        self.check_responses = list(check_responses)
        self.optimize_response = optimize_response
        self.check_calls = []

    def check_bound(self, *args, **kwargs):
        self.check_calls.append((args, kwargs))
        return self.check_responses.pop(0)

    def global_max(self, *args, **kwargs):
        return self.optimize_response

    def global_min(self, *args, **kwargs):
        return self.optimize_response


class V2FakeClient(FakeClient):
    bridge_info = {
        "bridge_api_version": "2.0.0",
        "protocol_version": "2.0.0",
        "bridge_version": "0.3.0",
        "lean_version": "4.31.0",
        "leancert_version": "4.31.0",
        "build": {
            "source_revision": "abc123",
            "source_digest": "sha256:source",
            "environment_digest": "sha256:environment",
            "profile": "release",
        },
    }


def enclosure(lo, hi, verified):
    return {"verified": verified, "computed_lo": rat(lo), "computed_hi": rat(hi)}


def test_checked_success_is_verified():
    solver = Solver(client=FakeClient([enclosure(0, 1, True)]))
    x = var("x")

    result = solver.verify_bound(x, {"x": (0, 1)}, upper=1)

    assert isinstance(result, Verified)
    assert result.provenance.lean_version == "4.31.0"


def test_checked_result_retains_v2_build_provenance():
    result = Solver(client=V2FakeClient([enclosure(0, 1, True)])).verify_bound(
        var("x"), {"x": (0, 1)}, upper=1
    )

    assert result.provenance.protocol_version == "2.0.0"
    assert result.provenance.source_revision == "abc123"
    assert result.provenance.environment_digest == "sha256:environment"
    assert result.provenance.build_profile == "release"


def test_checked_overlap_is_inconclusive_not_false():
    solver = Solver(client=FakeClient([enclosure(0, Fraction(11, 10), False)]))
    x = var("x")

    result = solver.verify_bound(x, {"x": (0, 1)}, upper=1)

    assert isinstance(result, Inconclusive)
    with pytest.raises(TypeError):
        bool(result)


@pytest.mark.parametrize(
    ("status", "outcome_type"),
    [("unsupported", Unsupported), ("domain_obstruction", DomainObstruction)],
)
def test_checked_typed_non_success(status, outcome_type):
    response = enclosure(0, 1, False) | {
        "status": status,
        "backend": "rational_global_optimization",
        "certificate": None,
    }
    result = Solver(client=FakeClient([response])).verify_bound(
        var("x"), {"x": (0, 1)}, upper=1
    )

    assert isinstance(result, outcome_type)
    assert result.checks[0].backend == "rational_global_optimization"


def test_both_bounds_must_be_checked():
    client = FakeClient([enclosure(0, 1, True), enclosure(0, 2, False)])
    result = Solver(client=client).verify_bound(
        var("x"), {"x": (0, 1)}, lower=0, upper=1
    )
    assert isinstance(result, Inconclusive)
    assert [check.status for check in result.checks] == ["verified", "inconclusive"]


def test_adaptive_safe_midpoint_never_becomes_verified():
    # Search enclosure crosses the limit, while the checked midpoint enclosure
    # is safe. The removed implementation treated this as proof and returned True.
    optimize = {
        "lo": rat(0),
        "hi": rat(Fraction(11, 10)),
        "bestBox": [{"lo": rat(0), "hi": rat(1)}],
    }
    client = FakeClient([enclosure(Fraction(1, 2), Fraction(1, 2), True)], optimize)

    result = Solver(client=client).verify_bound(
        var("x"), {"x": (0, 1)}, upper=1, method="adaptive"
    )

    assert isinstance(result, Inconclusive)
    assert result.candidate_counterexample is not None


def test_adaptive_checked_point_can_reject_bound():
    optimize = {
        "lo": rat(0),
        "hi": rat(2),
        "bestBox": [{"lo": rat(1), "hi": rat(1)}],
    }
    client = FakeClient([enclosure(2, 2, False)], optimize)

    result = Solver(client=client).verify_bound(
        var("x") * 2, {"x": (0, 1)}, upper=1, method="adaptive"
    )

    assert isinstance(result, Rejected)
    assert result.counterexample.enclosure.lo > 1


def test_adaptive_refines_candidate_before_exact_checked_rejection():
    optimize = {
        "lo": rat(-1),
        "hi": rat(0),
        "bestBox": [{"lo": rat(Fraction(2, 5)), "hi": rat(Fraction(2, 5))}],
    }
    client = FakeClient([enclosure(0, 0, False)], optimize)
    x = var("x")

    result = Solver(client=client).verify_bound(
        -(x - Fraction(4, 5)) ** 2,
        {"x": (0, 1)},
        upper=Fraction(-1, 20),
        method="adaptive",
    )

    assert isinstance(result, Rejected)
    point_box = client.check_calls[0][0][1]
    checked_point = Fraction(point_box[0]["lo"]["n"], point_box[0]["lo"]["d"])
    assert Fraction(3, 4) <= checked_point <= Fraction(17, 20)
    assert result.counterexample.values["x"] == checked_point


def test_monte_carlo_evaluates_candidates_as_one_batch():
    x = var("x")
    domain = Box({"x": Interval(Fraction(0), Fraction(1))})
    verifier = CounterexampleVerifier()

    with patch("leancert.validation._evaluate_batch", wraps=_evaluate_batch) as evaluate:
        result = verifier.monte_carlo_verify(
            x**2,
            domain,
            claimed_min=0,
            claimed_max=1,
            num_samples=32,
        )

    assert result.verdict is ValidationVerdict.CONFIRMED
    evaluate.assert_called_once()


def test_compatibility_wrapper_distinguishes_outcomes():
    x = var("x")
    solver = Solver(client=FakeClient([enclosure(0, 1, True)]))
    with pytest.deprecated_call():
        assert solver.verify_bound_or_raise(x, {"x": (0, 1)}, upper=1) is True

    solver = Solver(client=FakeClient([enclosure(0, 2, False)]))
    with pytest.deprecated_call(), pytest.raises(VerificationInconclusive):
        solver.verify_bound_or_raise(x, {"x": (0, 1)}, upper=1)
