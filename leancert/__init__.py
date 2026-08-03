# LeanCert v2 SDK
# Copyright (c) 2024 LeanCert Contributors. All rights reserved.

"""
LeanCert Python SDK - Rigorous Numerical Verification.

This SDK provides a user-friendly interface to the LeanCert verification engine,
allowing you to compute rigorous bounds, find roots, and verify mathematical
properties with machine-checked proofs.

Example:
    >>> import leancert_v2 as lf
    >>> x = lf.var('x')
    >>> result = lf.find_bounds(x**2, {'x': (0, 1)})
    >>> print(result.min_bound)  # Contains 0
    >>> print(result.max_bound)  # Contains 1

Key Features:
    - Named symbolic variables (no De Bruijn indices)
    - Automatic domain inference
    - Rich result objects with certificates
    - Context manager support for resource management
"""

from . import ast as ast

# Neural network export
from . import nn
from ._version import __version__

# Adaptive verification (CEGAR)
from .adaptive import (
    AdaptiveConfig,
    AdaptiveResult,
    AlgebraicAnalyzer,
    SplitCandidate,
    SplitStrategy,
    Subdomain,
    SubdomainResult,
    verify_bound_adaptive,
)

# Client (for advanced users)
from .client import LeanClient

# Configuration
from .config import AffineConfig, Backend, Config, DyadicConfig
from .doctor import DoctorCheck, DoctorReport, diagnose

# Domain types
from .domain import (
    Box,
    Interval,
    normalize_domain,
)

# Exceptions
from .exceptions import (
    PARTIAL_FUNCTIONS,
    SUPPORTED_KINDS,
    BridgeError,
    CompilationError,
    DomainError,
    ExpressionError,
    LeanCertError,
    PartialFunctionError,
    UnsupportedExpressionError,
    VerificationFailed,
    VerificationInconclusive,
    VerificationTimeout,
)

# Core expression types and constructors
from .expr import (
    Const,
    Expr,
    Max,
    # Min/Max/Clamp
    Min,
    Variable,
    abs,
    arsinh,
    atan,
    atanh,
    clamp,
    const,
    cos,
    cosh,
    erf,
    exp,
    # New functions
    inv,
    log,
    sin,
    # Special functions
    sinc,
    sinh,
    sqrt,
    tan,
    tanh,
    var,
)
from .nn import (
    FFNBlock,
    # Core network types
    Layer,
    # Transformer components
    LayerNormParams,
    LinearLayer,
    SequentialNetwork,
    TransformerBlock,
    TransformerEncoder,
    TwoLayerReLUNetwork,
    from_pytorch,
    from_pytorch_sequential,
    from_pytorch_transformer,
)

# Unified semantic-claim proving API
from .proving import (
    EventualConfig,
    KrawczykCandidate,
    ProveConfig,
    RefutationConfig,
    SystemRootConfig,
    prove,
)

# Quantifier pattern synthesis
from .quantifier import (
    QuantifierPattern,
    QuantifierResult,
    QuantifierSynthesizer,
    Witness,
    prove_limit,
    prove_sign,
    synthesize_bound,
    synthesize_maximum,
    synthesize_minimum,
)

# Rational utilities
from .rational import to_fraction

# Result types
from .result import (
    BoundCheck,
    BoundCheckEvidence,
    BoundComparisonLowering,
    BoundsResult,
    BridgeProvenance,
    CandidateCounterexample,
    CandidateRejected,
    Certificate,
    CheckedCounterexample,
    ConjunctionResult,
    DomainObstruction,
    EventualBoundResult,
    EventualCandidateRejected,
    EventualSearchEvidence,
    ExactLogicalResult,
    ExportDependencyUnavailable,
    ExportPrepared,
    ExportResourceLimit,
    ExportUnsupported,
    ExportVerificationMismatch,
    ExportVerified,
    IncompleteConjunction,
    Inconclusive,
    InconclusiveEventualBound,
    IntegralResult,
    KrawczykSearchEvidence,
    LeanProjectArtifact,
    LipschitzResult,
    NormalizedFalse,
    NormalizedTrue,
    ProofResult,
    Rejected,
    ReplayableBoundCertificate,
    ReplayableEventualCertificate,
    ReplayableKrawczykCertificate,
    ReplayBoundConfig,
    RootInterval,
    RootsResult,
    SystemRootResult,
    UniqueRootResult,
    Unsupported,
    UnsupportedEventualBound,
    UnsupportedSystemRoot,
    Verified,
    VerifiedConjunction,
    VerifiedEventualBound,
    VerifiedSystemRoot,
    VerifyResult,
)

# Simplification utilities
from .simplify import expand, simplify

# Solver
from .solver import (
    Solver,
    eval_interval,
    find_bounds,
    find_roots,
    find_unique_root,
    forward_interval,
    integrate,
    verify_bound,
    verify_bound_or_raise,
    verify_nn_bounds,
)

# Bug validation and false positive filtering
from .validation import (
    BugReport,
    BugValidator,
    CommentAnalyzer,
    CounterexampleVerifier,
    IntervalExplosionDetector,
    ValidationResult,
    ValidationVerdict,
    detect_interval_explosion,
    is_intentional_behavior,
    verify_counterexample_concrete,
)
from .verification import (
    ArtifactVerification,
    VerificationExitCode,
    VerificationReport,
    discover_exported_projects,
    verify_exported_projects,
)

__all__ = [
    # Version
    "__version__",
    "ast",
    # Expression types
    "Expr",
    "Variable",
    "Const",
    # Expression constructors
    "var",
    "const",
    "sin",
    "cos",
    "exp",
    "log",
    "sqrt",
    "tan",
    "atan",
    "abs",
    # New functions
    "inv",
    "sinh",
    "cosh",
    "tanh",
    "arsinh",
    "atanh",
    # Special functions
    "sinc",
    "erf",
    # Min/Max/Clamp
    "Min",
    "Max",
    "clamp",
    # Domain types
    "Interval",
    "Box",
    "normalize_domain",
    # Rational utilities
    "to_fraction",
    # Configuration
    "Config",
    "Backend",
    "DyadicConfig",
    "AffineConfig",
    # Result types
    "BoundsResult",
    "RootsResult",
    "RootInterval",
    "IntegralResult",
    "Certificate",
    "UniqueRootResult",
    "VerifyResult",
    "BoundCheck",
    "ProofResult",
    "ExactLogicalResult",
    "NormalizedTrue",
    "NormalizedFalse",
    "ConjunctionResult",
    "VerifiedConjunction",
    "IncompleteConjunction",
    "BoundComparisonLowering",
    "BoundCheckEvidence",
    "BridgeProvenance",
    "CandidateCounterexample",
    "CheckedCounterexample",
    "Verified",
    "Rejected",
    "Inconclusive",
    "Unsupported",
    "DomainObstruction",
    "ReplayableBoundCertificate",
    "ReplayBoundConfig",
    "LeanProjectArtifact",
    "ExportPrepared",
    "ExportVerified",
    "ExportUnsupported",
    "ExportDependencyUnavailable",
    "ExportResourceLimit",
    "ExportVerificationMismatch",
    "KrawczykSearchEvidence",
    "ReplayableKrawczykCertificate",
    "SystemRootResult",
    "VerifiedSystemRoot",
    "CandidateRejected",
    "UnsupportedSystemRoot",
    "EventualSearchEvidence",
    "ReplayableEventualCertificate",
    "EventualBoundResult",
    "VerifiedEventualBound",
    "EventualCandidateRejected",
    "InconclusiveEventualBound",
    "UnsupportedEventualBound",
    # Adaptive verification (CEGAR)
    "AdaptiveResult",
    "AdaptiveConfig",
    "SplitStrategy",
    "Subdomain",
    "SubdomainResult",
    "verify_bound_adaptive",
    # Solver
    "Solver",
    "find_bounds",
    "verify_bound",
    "verify_bound_or_raise",
    "ProveConfig",
    "RefutationConfig",
    "SystemRootConfig",
    "KrawczykCandidate",
    "EventualConfig",
    "prove",
    "find_roots",
    "find_unique_root",
    "integrate",
    "eval_interval",
    "forward_interval",
    "verify_nn_bounds",
    # Client
    "LeanClient",
    "DoctorCheck",
    "DoctorReport",
    "diagnose",
    "ArtifactVerification",
    "VerificationExitCode",
    "VerificationReport",
    "discover_exported_projects",
    "verify_exported_projects",
    # Simplification
    "simplify",
    "expand",
    # Exceptions
    "LeanCertError",
    "CompilationError",
    "DomainError",
    "VerificationFailed",
    "VerificationInconclusive",
    "VerificationTimeout",
    "BridgeError",
    "ExpressionError",
    "UnsupportedExpressionError",
    "PartialFunctionError",
    "SUPPORTED_KINDS",
    "PARTIAL_FUNCTIONS",
    # Bug validation
    "ValidationVerdict",
    "ValidationResult",
    "IntervalExplosionDetector",
    "CommentAnalyzer",
    "CounterexampleVerifier",
    "BugValidator",
    "BugReport",
    "detect_interval_explosion",
    "is_intentional_behavior",
    "verify_counterexample_concrete",
    # Neural network export
    "nn",
    # Core network types
    "Layer",
    "TwoLayerReLUNetwork",
    "SequentialNetwork",
    "from_pytorch",
    "from_pytorch_sequential",
    # Transformer components
    "LayerNormParams",
    "LinearLayer",
    "FFNBlock",
    "TransformerBlock",
    "TransformerEncoder",
    "from_pytorch_transformer",
]
