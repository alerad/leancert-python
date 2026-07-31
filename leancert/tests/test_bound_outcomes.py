"""Safety regressions for typed bound verification outcomes."""

from fractions import Fraction

import pytest

from leancert import (
    DomainObstruction, Inconclusive, Rejected, Solver, Unsupported, Verified, var,
)
from leancert.exceptions import VerificationInconclusive


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

    def check_bound(self, *args, **kwargs):
        return self.check_responses.pop(0)

    def global_max(self, *args, **kwargs):
        return self.optimize_response

    def global_min(self, *args, **kwargs):
        return self.optimize_response


def enclosure(lo, hi, verified):
    return {"verified": verified, "computed_lo": rat(lo), "computed_hi": rat(hi)}


def test_checked_success_is_verified():
    solver = Solver(client=FakeClient([enclosure(0, 1, True)]))
    x = var("x")

    result = solver.verify_bound(x, {"x": (0, 1)}, upper=1)

    assert isinstance(result, Verified)
    assert result.provenance.lean_version == "4.31.0"


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


def test_compatibility_wrapper_distinguishes_outcomes():
    x = var("x")
    solver = Solver(client=FakeClient([enclosure(0, 1, True)]))
    with pytest.deprecated_call():
        assert solver.verify_bound_or_raise(x, {"x": (0, 1)}, upper=1) is True

    solver = Solver(client=FakeClient([enclosure(0, 2, False)]))
    with pytest.deprecated_call(), pytest.raises(VerificationInconclusive):
        solver.verify_bound_or_raise(x, {"x": (0, 1)}, upper=1)
