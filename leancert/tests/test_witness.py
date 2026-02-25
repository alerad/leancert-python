# LeanCert v2 SDK - Witness Synthesis Tests
# Copyright (c) 2024 LeanCert Contributors. All rights reserved.

"""
TDD tests for auto-witness synthesis feature.

This feature allows Lean to delegate existential witness construction to Python,
which then returns a certificate-checked witness.

Goal forms supported:
- ∃ m, ∀ x ∈ I, f(x) ≥ m  (global minimum witness)
- ∃ M, ∀ x ∈ I, f(x) ≤ M  (global maximum witness)
- ∃ x ∈ I, f(x) = 0       (root witness)
"""

import pytest
from fractions import Fraction

from leancert import var, sin, cos, exp
from leancert.solver import Solver
from leancert.result import (
    WitnessResult,
    WitnessPoint,
    MinWitnessResult,
    MaxWitnessResult,
    RootWitnessResult,
)
from leancert.config import Config


class TestWitnessResult:
    """Test the WitnessResult data structures."""

    def test_witness_point_creation(self):
        """WitnessPoint should store variable values and function value."""
        wp = WitnessPoint(
            values={'x': Fraction(1, 2)},
            function_value=Fraction(1, 4),
            interval={'x': (Fraction(0), Fraction(1))},
        )
        assert wp.values == {'x': Fraction(1, 2)}
        assert wp.function_value == Fraction(1, 4)
        assert 'x' in wp.interval

    def test_witness_point_float_accessors(self):
        """WitnessPoint should have float convenience accessors."""
        wp = WitnessPoint(
            values={'x': Fraction(1, 2)},
            function_value=Fraction(1, 4),
            interval={'x': (Fraction(0), Fraction(1))},
        )
        assert wp.value_at('x') == 0.5
        assert wp.function_value_float == 0.25

    def test_min_witness_result(self):
        """MinWitnessResult should contain the witness for ∃ m, ∀ x ∈ I, f(x) ≥ m."""
        result = MinWitnessResult(
            witness_value=Fraction(0),
            witness_point=WitnessPoint(
                values={'x': Fraction(0)},
                function_value=Fraction(0),
                interval={'x': (Fraction(-1, 1000), Fraction(1, 1000))},
            ),
            proven_bound=Fraction(-1, 1000),  # Rigorous lower bound
            verified=True,
        )
        assert result.witness_value == Fraction(0)
        assert result.verified
        # The witness value should be >= the proven bound
        assert result.witness_value >= result.proven_bound

    def test_max_witness_result(self):
        """MaxWitnessResult should contain the witness for ∃ M, ∀ x ∈ I, f(x) ≤ M."""
        result = MaxWitnessResult(
            witness_value=Fraction(1),
            witness_point=WitnessPoint(
                values={'x': Fraction(1)},
                function_value=Fraction(1),
                interval={'x': (Fraction(999, 1000), Fraction(1001, 1000))},
            ),
            proven_bound=Fraction(1001, 1000),  # Rigorous upper bound
            verified=True,
        )
        assert result.witness_value == Fraction(1)
        assert result.verified
        # The witness value should be <= the proven bound
        assert result.witness_value <= result.proven_bound


class TestSynthesizeWitness:
    """Test the synthesize_witness method on Solver."""

    def test_synthesize_min_witness_x_squared(self):
        """Should find witness m=0 for ∃ m, ∀ x ∈ [0,1], x² ≥ m."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_min_witness(x**2, {'x': (0, 1)})

        assert isinstance(result, MinWitnessResult)
        assert result.verified
        # Witness should be close to 0 (the actual minimum)
        assert abs(float(result.witness_value)) < 0.01
        # The witness point should be near x=0
        assert abs(result.witness_point.value_at('x')) < 0.1

    def test_synthesize_max_witness_x_squared(self):
        """Should find witness M=1 for ∃ M, ∀ x ∈ [0,1], x² ≤ M."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_max_witness(x**2, {'x': (0, 1)})

        assert isinstance(result, MaxWitnessResult)
        assert result.verified
        # Witness should be close to 1 (the actual maximum)
        assert abs(float(result.witness_value) - 1.0) < 0.01
        # The witness point should be near x=1
        assert abs(result.witness_point.value_at('x') - 1.0) < 0.1

    def test_synthesize_min_witness_exp(self):
        """Should find witness for exp(x) minimum on [-1, 1]."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_min_witness(exp(x), {'x': (-1, 1)})

        assert result.verified
        # Min of exp(x) on [-1, 1] is exp(-1) ≈ 0.368
        # The witness_value is a proven lower bound, may be looser than actual min
        # but the witness_point should be near x = -1
        assert result.witness_point is not None
        assert abs(result.witness_point.value_at('x') - (-1.0)) < 0.5  # Near x=-1

    def test_synthesize_root_witness(self):
        """Should find witness x for ∃ x ∈ I, f(x) = 0."""
        x = var('x')
        # x² - 1 has roots at x = ±1
        with Solver() as solver:
            result = solver.synthesize_root_witness(x**2 - 1, {'x': (0.5, 1.5)})

        assert isinstance(result, RootWitnessResult)
        assert result.verified
        # Root should be near x=1
        assert abs(result.witness_point.value_at('x') - 1.0) < 0.01
        # Function value at witness should be near 0
        assert abs(result.witness_point.function_value_float) < 0.01

    def test_synthesize_witness_multivariate(self):
        """Should work with multivariate expressions."""
        x, y = var('x'), var('y')
        with Solver() as solver:
            result = solver.synthesize_min_witness(
                x**2 + y**2,
                {'x': (-1, 1), 'y': (-1, 1)}
            )

        assert result.verified
        # Min of x² + y² is 0 at (0, 0)
        # The witness_value is the proven lower bound (may be loose)
        # but the witness_point should be near (0, 0)
        assert result.witness_point is not None
        assert abs(result.witness_point.value_at('x')) < 0.5
        assert abs(result.witness_point.value_at('y')) < 0.5


class TestWitnessToLean:
    """Test Lean code generation for witness proofs."""

    def test_min_witness_to_lean(self):
        """Should generate Lean proof for ∃ m, ∀ x ∈ I, f(x) ≥ m."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_min_witness(x**2, {'x': (0, 1)})

        lean_code = result.to_lean_tactic()

        # Should contain existential statement
        assert '∃' in lean_code or 'Exists' in lean_code
        # Should contain the witness value
        assert 'exact' in lean_code.lower() or 'use' in lean_code.lower()
        # Should contain interval membership proof
        assert 'interval' in lean_code.lower()

    def test_root_witness_to_lean(self):
        """Should generate Lean proof for ∃ x ∈ I, f(x) = 0."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_root_witness(x**2 - 1, {'x': (0.5, 1.5)})

        lean_code = result.to_lean_tactic()

        # Should contain existential and root-specific tactics
        assert '∃' in lean_code or 'Exists' in lean_code
        assert 'root' in lean_code.lower() or 'zero' in lean_code.lower()


class TestProofStrategyRacing:
    """Test parallel proof strategy racing."""

    def test_race_backends_returns_fastest(self):
        """Racing multiple backends should return the first to succeed."""
        x = var('x')
        with Solver() as solver:
            # race_strategies should try multiple approaches in parallel
            result = solver.synthesize_min_witness(
                x**2,
                {'x': (0, 1)},
                config=Config(race_strategies=True),
            )

        assert result.verified
        # Should record which strategy won
        assert result.strategy_used in ('dyadic', 'affine', 'rational', 'taylor')

    def test_race_with_timeout(self):
        """Racing should respect timeout."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_min_witness(
                x**2,
                {'x': (0, 1)},
                config=Config(race_strategies=True, timeout_ms=1000),
            )

        assert result.verified


class TestIncrementalRefinement:
    """Test incremental bound refinement protocol."""

    def test_incremental_refinement_returns_tightest(self):
        """Incremental refinement should return the tightest provable bound."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_max_witness(
                exp(x),
                {'x': (0, 1)},
                config=Config(incremental_refinement=True),
            )

        assert result.verified
        # exp(1) ≈ 2.718, should get tight bound
        assert 2.7 < float(result.witness_value) < 2.72
        # Should record refinement history
        assert len(result.refinement_history) > 0

    def test_incremental_stops_at_provable(self):
        """Should stop refining when bound becomes unprovable."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_max_witness(
                exp(x),
                {'x': (0, 1)},
                config=Config(incremental_refinement=True, target_bound=2.71829),
            )

        # If target is too tight, should return best provable
        assert result.verified
        # The final bound might be slightly looser than target
        assert float(result.witness_value) >= 2.718


class TestFailureDiagnosis:
    """Test failure diagnosis API for CEGPR support."""

    def test_failure_diagnosis_bound_too_tight(self):
        """Should diagnose when a bound is too tight."""
        x = var('x')
        with Solver() as solver:
            # Try to prove exp(x) ≤ 2.5 on [0, 1] - this should fail
            # because max(exp(x)) ≈ 2.718
            diagnosis = solver.diagnose_bound_failure(
                exp(x),
                {'x': (0, 1)},
                upper=2.5,
            )

        assert diagnosis.failure_type == 'bound_too_tight'
        assert diagnosis.margin < 0  # Negative margin means bound is violated
        assert 0.9 < diagnosis.worst_point['x'] < 1.1  # Near x=1
        assert 2.7 < diagnosis.suggested_bound < 2.8

    def test_failure_diagnosis_returns_none_on_success(self):
        """Should return None when bound is satisfied."""
        x = var('x')
        with Solver() as solver:
            diagnosis = solver.diagnose_bound_failure(
                x**2,
                {'x': (0, 1)},
                upper=2.0,  # This is easily satisfied
            )

        assert diagnosis is None  # No failure to diagnose


class TestCertificateWithWitness:
    """Test that certificates include witness information."""

    def test_certificate_contains_witness(self):
        """Certificate should include witness data for existential proofs."""
        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_min_witness(x**2, {'x': (0, 1)})

        cert = result.certificate
        assert cert is not None
        assert cert.operation == 'synthesize_min_witness'
        assert 'witness' in cert.result_json
        assert 'witness_point' in cert.result_json

    def test_certificate_round_trip(self):
        """Certificate should survive save/load round trip."""
        import tempfile
        import os

        x = var('x')
        with Solver() as solver:
            result = solver.synthesize_min_witness(x**2, {'x': (0, 1)})

        cert = result.certificate

        # Save and reload
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            cert.save(f.name)
            from leancert.result import Certificate
            loaded = Certificate.load(f.name)
            os.unlink(f.name)

        assert loaded.operation == cert.operation
        assert loaded.result_json['witness'] == cert.result_json['witness']
