# LeanCert v2 SDK - Configuration
# Copyright (c) 2024 LeanCert Contributors. All rights reserved.

"""Configuration settings for LeanCert v2."""

from __future__ import annotations
from dataclasses import dataclass, field
from fractions import Fraction
from enum import Enum
from typing import Optional


class Backend(Enum):
    """
    Backend selection for interval arithmetic.

    - RATIONAL: Standard rational arithmetic. Exact but can suffer from
                denominator explosion on deep expressions.
    - DYADIC: High-performance dyadic arithmetic (n * 2^e). Avoids
              denominator explosion by using fixed-precision outward rounding.
              10-100x faster for complex expressions like neural networks.
    - AFFINE: Affine arithmetic that tracks correlations between variables.
              Solves the "dependency problem" (e.g., x-x gives [0,0] not [-2,2]).
              50-90% tighter bounds for expressions with repeated variables.
    """
    RATIONAL = "rational"
    DYADIC = "dyadic"
    AFFINE = "affine"


@dataclass
class DyadicConfig:
    """
    Configuration for Dyadic arithmetic backend.

    Attributes:
        precision: Minimum exponent for outward rounding. -53 gives IEEE
                  double-like precision (~15 decimal digits). Use -100 for
                  higher precision, -30 for faster computation.
        round_after_ops: Round after this many operations. 0 means round
                        after every operation (most sound, slightly slower).
    """
    precision: int = -53
    round_after_ops: int = 0

    @classmethod
    def ieee_double(cls) -> DyadicConfig:
        """IEEE double-like precision (~15 decimal digits)."""
        return cls(precision=-53)

    @classmethod
    def high_precision(cls) -> DyadicConfig:
        """High precision (~30 decimal digits)."""
        return cls(precision=-100)

    @classmethod
    def fast(cls) -> DyadicConfig:
        """Fast mode with lower precision (~9 decimal digits)."""
        return cls(precision=-30)


@dataclass
class AffineConfig:
    """
    Configuration for Affine arithmetic backend.

    Affine arithmetic tracks correlations between variables, solving the
    "dependency problem" in interval arithmetic. For example:
    - Interval: x - x on [-1, 1] gives [-2, 2]
    - Affine: x - x on [-1, 1] gives [0, 0] (exact!)

    Attributes:
        max_noise_symbols: Maximum noise symbols before consolidation.
                          0 means no limit. Higher limits give tighter
                          bounds but use more memory.
    """
    max_noise_symbols: int = 0

    @classmethod
    def default(cls) -> AffineConfig:
        """Default configuration with no symbol limit."""
        return cls()

    @classmethod
    def compact(cls) -> AffineConfig:
        """Compact mode that consolidates noise symbols."""
        return cls(max_noise_symbols=100)


@dataclass
class Config:
    """
    Configuration for verification requests.

    Attributes:
        taylor_depth: Depth of Taylor expansion for interval arithmetic.
                     Higher values give tighter bounds but are slower.
        max_iters: Maximum iterations for optimization/root finding.
        tolerance: Desired precision (as a fraction).
        use_monotonicity: Use monotonicity pruning in optimization.
        timeout_sec: Timeout in seconds.
        backend: Interval arithmetic backend (RATIONAL, DYADIC, or AFFINE).
        dyadic_config: Configuration for Dyadic backend (if backend is DYADIC).
        affine_config: Configuration for Affine backend (if backend is AFFINE).
        race_strategies: If True, race multiple backends in parallel and use
                        the first to succeed. Useful for unknown expressions.
        incremental_refinement: If True, iteratively refine bounds to find the
                               tightest provable bound.
        target_bound: Optional target bound for incremental refinement. If set,
                     refinement stops when this bound is proven or exceeded.
        timeout_ms: Timeout in milliseconds for racing/refinement operations.
    """
    taylor_depth: int = 10
    max_iters: int = 1000
    tolerance: Fraction = Fraction(1, 1000)
    use_monotonicity: bool = True
    timeout_sec: float = 60.0
    backend: Backend = Backend.DYADIC
    dyadic_config: Optional[DyadicConfig] = None
    affine_config: Optional[AffineConfig] = None
    # Witness synthesis options
    race_strategies: bool = False
    incremental_refinement: bool = False
    target_bound: Optional[float] = None
    timeout_ms: int = 30000

    def __post_init__(self):
        # Convert tolerance to Fraction if given as float
        if isinstance(self.tolerance, float):
            self.tolerance = Fraction(self.tolerance).limit_denominator(10**12)
        # Auto-create dyadic config if using dyadic backend
        if self.backend == Backend.DYADIC and self.dyadic_config is None:
            self.dyadic_config = DyadicConfig()
        # Auto-create affine config if using affine backend
        if self.backend == Backend.AFFINE and self.affine_config is None:
            self.affine_config = AffineConfig()

    @classmethod
    def low_precision(cls) -> Config:
        """Fast, lower precision configuration."""
        return cls(
            taylor_depth=5,
            max_iters=100,
            tolerance=Fraction(1, 100),
        )

    @classmethod
    def medium_precision(cls) -> Config:
        """Balanced precision/speed configuration (default)."""
        return cls()

    @classmethod
    def high_precision(cls) -> Config:
        """High precision configuration."""
        return cls(
            taylor_depth=20,
            max_iters=5000,
            tolerance=Fraction(1, 100000),
        )

    @classmethod
    def dyadic(cls, precision: int = -53) -> Config:
        """
        Configuration using Dyadic backend for high performance.

        Recommended for deep expressions, neural networks, or when
        rational arithmetic is too slow.

        Args:
            precision: Dyadic precision (default -53, IEEE double-like).
        """
        return cls(
            backend=Backend.DYADIC,
            dyadic_config=DyadicConfig(precision=precision),
        )

    @classmethod
    def dyadic_fast(cls) -> Config:
        """Fast Dyadic configuration with lower precision."""
        return cls(
            taylor_depth=8,
            max_iters=500,
            tolerance=Fraction(1, 100),
            backend=Backend.DYADIC,
            dyadic_config=DyadicConfig.fast(),
        )

    @classmethod
    def dyadic_high_precision(cls) -> Config:
        """High precision Dyadic configuration."""
        return cls(
            taylor_depth=20,
            max_iters=5000,
            tolerance=Fraction(1, 100000),
            backend=Backend.DYADIC,
            dyadic_config=DyadicConfig.high_precision(),
        )

    @classmethod
    def affine(cls) -> Config:
        """
        Configuration using Affine backend for tight bounds.

        Recommended for expressions with repeated variables where the
        dependency problem causes interval over-approximation.

        Example:
            x - x on [-1, 1]:
            - Interval gives [-2, 2]
            - Affine gives [0, 0] (exact!)
        """
        return cls(
            backend=Backend.AFFINE,
            affine_config=AffineConfig(),
        )

    @classmethod
    def affine_compact(cls) -> Config:
        """Affine configuration with noise symbol consolidation."""
        return cls(
            backend=Backend.AFFINE,
            affine_config=AffineConfig.compact(),
        )

    def to_kernel(self) -> dict:
        """Convert to kernel-compatible format."""
        return {
            'taylorDepth': self.taylor_depth,
            'maxIters': self.max_iters,
            'tolerance': {'n': self.tolerance.numerator, 'd': self.tolerance.denominator},
            'useMonotonicity': self.use_monotonicity,
        }

    def to_dyadic_kernel(self) -> dict:
        """Convert Dyadic config to kernel-compatible format."""
        dc = self.dyadic_config or DyadicConfig()
        return {
            'precision': dc.precision,
            'taylorDepth': self.taylor_depth,
            'roundAfterOps': dc.round_after_ops,
        }

    def to_affine_kernel(self) -> dict:
        """Convert Affine config to kernel-compatible format."""
        ac = self.affine_config or AffineConfig()
        return {
            'taylorDepth': self.taylor_depth,
            'maxNoiseSymbols': ac.max_noise_symbols,
        }

    def __repr__(self) -> str:
        backend_str = f", backend={self.backend.value}" if self.backend != Backend.DYADIC else ""
        return (
            f"Config(taylor_depth={self.taylor_depth}, "
            f"max_iters={self.max_iters}, "
            f"tolerance={self.tolerance}{backend_str})"
        )
