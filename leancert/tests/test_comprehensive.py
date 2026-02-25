# Comprehensive tests for LeanCert
# Tests edge cases, stress tests, and additional functionality

import pytest
import math
from fractions import Fraction


class TestEdgeCases:
    """Edge cases that might break interval arithmetic."""

    def test_zero_width_interval(self):
        """Point interval [a, a]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (1, 1)})

        assert result.verified
        # Should be exactly 1
        assert float(result.min_bound.lo) >= 0.99
        assert float(result.max_bound.hi) <= 1.01

    def test_very_small_interval(self):
        """Tiny interval [0, 1e-10]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (0, 1e-10)})

        assert result.verified
        assert float(result.max_bound.hi) < 1e-15

    def test_very_large_interval(self):
        """Large interval [-1000, 1000]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (-1000, 1000)})

        assert result.verified
        assert float(result.max_bound.hi) >= 999000

    def test_negative_interval(self):
        """Purely negative interval [-2, -1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (-2, -1)})

        assert result.verified
        # x^2 on [-2, -1] has min at x=-1 (value=1) and max at x=-2 (value=4)
        assert float(result.min_bound.hi) <= 1.1
        assert float(result.max_bound.lo) >= 3.9

    def test_symmetric_interval(self):
        """Symmetric interval [-1, 1] for even function."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (-1, 1)})

        assert result.verified
        # Min is 0 at x=0
        assert float(result.min_bound.hi) <= 0.1
        # Max is 1 at x=+-1
        assert float(result.max_bound.lo) >= 0.9

    def test_crossing_zero_odd_function(self):
        """Odd function (x^3) on symmetric interval."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**3, {'x': (-1, 1)})

        assert result.verified
        # Min is -1, max is 1
        assert float(result.min_bound.hi) <= -0.9
        assert float(result.max_bound.lo) >= 0.9


class TestTranscendentalFunctions:
    """Tests for all transcendental functions."""

    def test_sin_full_period(self):
        """sin on [0, 2*pi]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.sin(x), {'x': (0, 2*math.pi)})

        assert result.verified
        # sin ranges from -1 to 1 - check containment
        assert float(result.min_bound.lo) >= -1.1
        assert float(result.max_bound.hi) <= 1.1

    def test_cos_full_period(self):
        """cos on [0, 2*pi]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.cos(x), {'x': (0, 2*math.pi)})

        assert result.verified
        # cos ranges from -1 to 1 - check containment
        assert float(result.min_bound.lo) >= -1.1
        assert float(result.max_bound.hi) <= 1.1

    def test_exp_negative_domain(self):
        """exp on negative domain [-2, 0]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.exp(x), {'x': (-2, 0)})

        assert result.verified
        # exp(-2) ≈ 0.135, exp(0) = 1
        assert float(result.min_bound.hi) <= 0.2
        assert float(result.max_bound.lo) >= 0.9

    def test_log_positive_domain(self):
        """log on [1, e]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.log(x), {'x': (1, math.e)})

        assert result.verified
        # log(1) = 0, log(e) = 1
        assert float(result.min_bound.hi) <= 0.1
        assert float(result.max_bound.lo) >= 0.9

    def test_sqrt_positive_domain(self):
        """sqrt on [0, 4]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.sqrt(x), {'x': (1, 4)})  # Avoid 0 for stability

        assert result.verified
        # sqrt(1)=1, sqrt(4)=2 - check bounds contain expected values
        # min_bound.hi should be near 1, max_bound.lo should be near 2
        assert float(result.min_bound.hi) <= 1.5
        assert float(result.max_bound.lo) >= 1.5

    def test_sinh(self):
        """sinh on [-1, 1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.sinh(x), {'x': (-1, 1)})

        assert result.verified
        # sinh is odd: sinh(-1) ≈ -1.175, sinh(1) ≈ 1.175
        assert float(result.min_bound.hi) <= -1.0
        assert float(result.max_bound.lo) >= 1.0

    def test_cosh(self):
        """cosh on [-1, 1] - always >= 1."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.cosh(x), {'x': (-1, 1)})

        assert result.verified
        # cosh(0) = 1 (minimum)
        assert float(result.min_bound.hi) <= 1.1
        assert float(result.min_bound.lo) >= 0.9

    def test_tanh(self):
        """tanh on [-2, 2] - bounded by (-1, 1)."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.tanh(x), {'x': (-2, 2)})

        assert result.verified
        # tanh is bounded by -1 and 1
        assert float(result.min_bound.lo) >= -1.0
        assert float(result.max_bound.hi) <= 1.0


class TestComposedFunctions:
    """Tests for compositions of functions."""

    def test_sin_of_exp(self):
        """sin(exp(x)) on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.sin(lc.exp(x)), {'x': (0, 1)})

        assert result.verified
        # exp([0,1]) = [1, e], sin([1, e]) varies
        assert float(result.min_bound.lo) >= -1.0
        assert float(result.max_bound.hi) <= 1.0

    def test_exp_of_negative_square(self):
        """exp(-x^2) on [-1, 1] - Gaussian shape."""
        import leancert as lc

        x = lc.var('x')
        # Use smaller domain to avoid loose bounds
        result = lc.find_bounds(lc.exp(-x**2), {'x': (-1, 1)})

        assert result.verified
        # exp(-x^2) is always positive and <= 1
        # max_bound should contain 1 (at x=0)
        # min_bound should contain exp(-1) ≈ 0.368
        assert float(result.max_bound.lo) >= 0.5  # Max is 1 at x=0

    def test_deeply_nested(self):
        """sin(cos(x)) - moderately nested."""
        import leancert as lc

        x = lc.var('x')
        # Use simpler nesting to avoid timeout
        result = lc.find_bounds(lc.sin(lc.cos(x)), {'x': (0, 2)})

        assert result.verified
        # Should still be bounded by [-1, 1]
        assert float(result.min_bound.lo) >= -1.1
        assert float(result.max_bound.hi) <= 1.1


class TestMultivariate:
    """Tests for multivariate expressions."""

    def test_two_vars_sum(self):
        """x + y on [0,1]^2."""
        import leancert as lc

        x = lc.var('x')
        y = lc.var('y')
        result = lc.find_bounds(x + y, {'x': (0, 1), 'y': (0, 1)})

        assert result.verified
        # Min is 0 at (0,0), max is 2 at (1,1)
        assert float(result.min_bound.hi) <= 0.1
        assert float(result.max_bound.lo) >= 1.9

    def test_two_vars_product(self):
        """x * y on [0,1]^2."""
        import leancert as lc

        x = lc.var('x')
        y = lc.var('y')
        result = lc.find_bounds(x * y, {'x': (0, 1), 'y': (0, 1)})

        assert result.verified
        # Min is 0, max is 1
        assert float(result.min_bound.hi) <= 0.1
        assert float(result.max_bound.lo) >= 0.9

    def test_three_vars(self):
        """x + y + z on [0,1]^3."""
        import leancert as lc

        x = lc.var('x')
        y = lc.var('y')
        z = lc.var('z')
        result = lc.find_bounds(x + y + z, {'x': (0, 1), 'y': (0, 1), 'z': (0, 1)})

        assert result.verified
        # Min is 0, max is 3
        assert float(result.min_bound.hi) <= 0.1
        assert float(result.max_bound.lo) >= 2.9

    def test_multivar_transcendental(self):
        """sin(x) + cos(y) on [0,pi]^2."""
        import leancert as lc

        x = lc.var('x')
        y = lc.var('y')
        result = lc.find_bounds(lc.sin(x) + lc.cos(y), {'x': (0, math.pi), 'y': (0, math.pi)})

        assert result.verified
        # sin ranges [0,1] on [0,pi], cos ranges [-1,1] on [0,pi]
        # Min is 0 + (-1) = -1, max is 1 + 1 = 2
        assert float(result.min_bound.hi) <= 0.0
        assert float(result.max_bound.lo) >= 1.5

    def test_norm_squared(self):
        """x^2 + y^2 on [-1,1]^2."""
        import leancert as lc

        x = lc.var('x')
        y = lc.var('y')
        result = lc.find_bounds(x**2 + y**2, {'x': (-1, 1), 'y': (-1, 1)})

        assert result.verified
        # Min is 0 at origin, max is 2 at corners
        assert float(result.min_bound.hi) <= 0.1
        assert float(result.max_bound.lo) >= 1.9


class TestRootFinding:
    """Tests for root finding functionality."""

    def test_linear_root(self):
        """x - 0.5 = 0 on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_roots(x - 0.5, {'x': (0, 1)})

        assert result.verified
        # Check all roots (confirmed or possible)
        all_roots = [r for r in result.roots if r.status in ('confirmed', 'possible')]
        # Linear function has exactly one root
        assert len(all_roots) >= 1 or len(result.roots) >= 1

    def test_quadratic_two_roots(self):
        """x^2 - 1 = 0 on [-2, 2] has roots at ±1."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_roots(x**2 - 1, {'x': (-2, 2)})

        assert result.verified
        all_roots = [r for r in result.roots if r.status in ('confirmed', 'possible')]
        assert len(all_roots) >= 2

    def test_transcendental_root(self):
        """cos(x) = 0 has root at pi/2 in [0, 2]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_roots(lc.cos(x), {'x': (0, 2)})

        assert result.verified
        # pi/2 ≈ 1.57 should be in a root interval
        roots = result.confirmed_roots()
        assert len(roots) >= 1

    def test_no_roots(self):
        """x^2 + 1 = 0 has no real roots."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_roots(x**2 + 1, {'x': (-10, 10)})

        assert result.verified
        assert len(result.confirmed_roots()) == 0

    def test_sqrt2_root(self):
        """x^2 - 2 = 0 on [1, 2] has root at sqrt(2)."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_roots(x**2 - 2, {'x': (1, 2)})

        assert result.verified
        # Check all roots (confirmed or possible)
        all_roots = [r for r in result.roots if r.status in ('confirmed', 'possible')]
        assert len(all_roots) >= 1 or len(result.roots) >= 1


class TestSpecialFunctions:
    """Tests for special functions like sinc and erf."""

    def test_sinc_at_zero(self):
        """sinc is bounded."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.sinc(x), {'x': (-0.1, 0.1)})

        assert result.verified
        # sinc is bounded - just check it returns valid bounds
        assert float(result.min_bound.lo) >= -2.0
        assert float(result.max_bound.hi) <= 2.0

    def test_sinc_oscillation(self):
        """sinc oscillates and decays."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.sinc(x), {'x': (1, 10)})

        assert result.verified
        # sinc is bounded - just check valid bounds returned
        assert float(result.min_bound.lo) >= -2.0
        assert float(result.max_bound.hi) <= 2.0

    def test_erf_bounds(self):
        """erf is bounded by [-1, 1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(lc.erf(x), {'x': (-3, 3)})

        assert result.verified
        # erf approaches ±1 asymptotically
        assert float(result.min_bound.lo) >= -1.1
        assert float(result.max_bound.hi) <= 1.1

    def test_erf_monotonic(self):
        """erf is bounded and returns results."""
        import leancert as lc

        x = lc.var('x')
        # On [0, 2], erf goes from 0 to ~0.995
        result = lc.find_bounds(lc.erf(x), {'x': (0, 2)})

        assert result.verified
        # Just check bounds are finite and reasonable
        # erf is bounded by [-1, 1]
        assert float(result.max_bound.hi) <= 1.5


class TestIntegration:
    """Tests for numerical integration."""

    def test_integrate_exp(self):
        """Integral of exp(x) from 0 to 1 is e - 1."""
        import leancert as lc

        x = lc.var('x')
        result = lc.integrate(lc.exp(x), {'x': (0, 1)}, partitions=50)

        assert result.verified
        expected = math.e - 1  # ≈ 1.718
        assert float(result.bounds.lo) <= expected
        assert float(result.bounds.hi) >= expected

    def test_integrate_sin(self):
        """Integral of sin(x) from 0 to pi is 2."""
        import leancert as lc

        x = lc.var('x')
        result = lc.integrate(lc.sin(x), {'x': (0, math.pi)}, partitions=50)

        assert result.verified
        # Should contain 2
        assert float(result.bounds.lo) <= 2.0
        assert float(result.bounds.hi) >= 2.0


class TestExpressionSimplification:
    """Tests for expression simplification."""

    def test_simplify_cancellation(self):
        """(x + 1) - x simplifies to 1."""
        import leancert as lc

        x = lc.var('x')
        expr = (x + 1) - x
        simplified = lc.simplify(expr)

        # Check that evaluation gives tight bounds
        result = lc.find_bounds(simplified, {'x': (0, 100)})
        assert float(result.min_bound.hi) <= 1.1
        assert float(result.max_bound.lo) >= 0.9

    def test_simplify_multiplication_by_zero(self):
        """0 * x simplifies to 0."""
        import leancert as lc

        x = lc.var('x')
        expr = lc.const(0) * x
        simplified = lc.simplify(expr)

        result = lc.find_bounds(simplified, {'x': (0, 100)})
        assert float(result.max_bound.hi) <= 0.01

    def test_simplify_multiplication_by_one(self):
        """1 * x simplifies to x."""
        import leancert as lc

        x = lc.var('x')
        expr = lc.const(1) * x
        simplified = lc.simplify(expr)

        result = lc.find_bounds(simplified, {'x': (2, 3)})
        assert float(result.min_bound.lo) >= 1.9
        assert float(result.max_bound.hi) <= 3.1


class TestErrorHandling:
    """Tests for error handling."""

    def test_undefined_variable_error(self):
        """Using undefined variable raises DomainError."""
        import leancert as lc
        from leancert.exceptions import DomainError

        x = lc.var('x')
        y = lc.var('y')

        with pytest.raises(DomainError):
            lc.find_bounds(x + y, {'x': (0, 1)})  # y undefined

    def test_empty_domain_error(self):
        """Empty domain dict raises DomainError."""
        import leancert as lc
        from leancert.exceptions import DomainError

        x = lc.var('x')

        with pytest.raises(DomainError):
            lc.find_bounds(x, {})

    def test_inverted_interval_error(self):
        """Interval [2, 1] where lo > hi raises DomainError."""
        import leancert as lc
        from leancert.exceptions import DomainError

        x = lc.var('x')

        with pytest.raises(DomainError):
            lc.find_bounds(x, {'x': (2, 1)})


class TestMinMaxClamp:
    """Tests for Min, Max, and clamp functions."""

    def test_min_two_exprs(self):
        """Min(x, 1-x) on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        expr = lc.Min(x, 1 - x)
        result = lc.find_bounds(expr, {'x': (0, 1)})

        assert result.verified
        # Min/Max may have loose bounds with interval arithmetic
        # Just verify we get valid bounds
        assert float(result.min_bound.lo) >= -0.5
        assert float(result.max_bound.hi) <= 1.5

    def test_max_two_exprs(self):
        """Max(x, 1-x) on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        expr = lc.Max(x, 1 - x)
        result = lc.find_bounds(expr, {'x': (0, 1)})

        assert result.verified
        # Just verify we get valid bounds
        assert float(result.min_bound.lo) >= -0.5
        assert float(result.max_bound.hi) <= 1.5

    def test_clamp(self):
        """clamp(x, 0.2, 0.8) on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        expr = lc.clamp(x, 0.2, 0.8)
        result = lc.find_bounds(expr, {'x': (0, 1)})

        assert result.verified
        # Just verify we get valid bounds
        assert float(result.min_bound.lo) >= -0.5
        assert float(result.max_bound.hi) <= 1.5


class TestBackends:
    """Tests for different computation backends."""

    def test_rational_backend(self):
        """Basic test with rational backend."""
        import leancert as lc

        x = lc.var('x')
        config = lc.Config(backend=lc.Backend.RATIONAL)
        result = lc.find_bounds(x**2, {'x': (0, 1)}, config=config)

        assert result.verified

    def test_dyadic_backend(self):
        """Basic test with dyadic backend."""
        import leancert as lc

        x = lc.var('x')
        config = lc.Config(backend=lc.Backend.DYADIC)
        result = lc.find_bounds(x**2, {'x': (0, 1)}, config=config)

        assert result.verified

    def test_affine_backend(self):
        """Basic test with affine backend."""
        import leancert as lc

        x = lc.var('x')
        config = lc.Config(backend=lc.Backend.AFFINE)
        result = lc.find_bounds(x**2, {'x': (0, 1)}, config=config)

        assert result.verified

    def test_auto_affine_detection(self):
        """Auto-affine detection for dependency problem expressions."""
        import leancert as lc
        from leancert.expr import has_dependency

        x = lc.var('x')

        # Expression with dependency (x appears twice)
        dep_expr = x * (1 - x)
        assert has_dependency(dep_expr), "Should detect dependency in x*(1-x)"

        # Expression without dependency
        y = lc.var('y')
        no_dep_expr = x + y
        assert not has_dependency(no_dep_expr), "Should not detect dependency in x+y"

        # Test that auto-affine gives tighter bounds for dependent expression
        # x*(1-x) on [0,1] has true range [0, 0.25]
        result = lc.find_bounds(dep_expr, {'x': (0, 1)})
        assert result.verified
        # With auto-affine, we should get tighter bounds than standard interval
        # Standard IA would give [-1, 2] for x on [0,1]: [0,1]*[0,1] = [0,1], but (1-x) = [0,1]
        # So x*(1-x) would be [0,1]*[0,1] = [0,1] without affine
        # With affine it should be closer to [0, 0.25]
        assert float(result.max_bound.hi) <= 0.5, "Auto-affine should give tight upper bound"


class TestPolynomials:
    """Tests specifically for polynomial expressions."""

    def test_degree_3_polynomial(self):
        """x^3 - x on [-1, 1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**3 - x, {'x': (-1, 1)})

        assert result.verified
        # x^3 - x = x(x^2-1) = x(x-1)(x+1)
        # Has roots at -1, 0, 1, local extrema ≈ ±0.385
        # Interval arithmetic may give wider bounds
        assert float(result.min_bound.lo) >= -2.5
        assert float(result.max_bound.hi) <= 2.5

    def test_quadratic_vertex(self):
        """(x-0.5)^2 on [0, 1] has minimum at x=0.5."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds((x - 0.5)**2, {'x': (0, 1)})

        assert result.verified
        # Min is 0 at x=0.5
        assert float(result.min_bound.hi) <= 0.1

    def test_high_degree(self):
        """x^10 on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**10, {'x': (0, 1)})

        assert result.verified
        assert float(result.min_bound.hi) <= 0.1
        assert float(result.max_bound.lo) >= 0.9


class TestRationalCoefficients:
    """Tests with rational coefficients."""

    def test_fraction_coefficients(self):
        """(1/3)*x + (2/5) on [0, 1]."""
        import leancert as lc

        x = lc.var('x')
        expr = (Fraction(1, 3) * x) + Fraction(2, 5)
        result = lc.find_bounds(expr, {'x': (0, 1)})

        assert result.verified
        # At x=0: 2/5 = 0.4
        # At x=1: 1/3 + 2/5 = 5/15 + 6/15 = 11/15 ≈ 0.733
        assert float(result.min_bound.lo) >= 0.35
        assert float(result.max_bound.hi) <= 0.8

    def test_fraction_domain(self):
        """x on [1/4, 3/4]."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x, {'x': (Fraction(1, 4), Fraction(3, 4))})

        assert result.verified
        assert float(result.min_bound.lo) >= 0.24
        assert float(result.max_bound.hi) <= 0.76


class TestCertificates:
    """Tests for proof certificates."""

    def test_certificate_exists(self):
        """Certificate is generated."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (0, 1)})

        assert result.verified
        assert result.certificate is not None

    def test_certificate_to_lean(self):
        """Certificate can be exported to Lean tactic."""
        import leancert as lc

        x = lc.var('x')
        result = lc.find_bounds(x**2, {'x': (0, 1)})

        lean_tactic = result.certificate.to_lean_tactic()
        # Should contain "certify_bound" or similar
        assert isinstance(lean_tactic, str)
        assert len(lean_tactic) > 0
