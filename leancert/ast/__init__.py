"""LeanCert's immutable, exact, bridge-independent semantic AST."""
# ruff: noqa: F401, F403

from ._base import AstNode
from .annotations import Annotated, SourceSpan
from .builders import (
    abs,
    all_of,
    any_of,
    arccos,
    arcsin,
    arsinh,
    atan,
    atanh,
    bounded_forall,
    box,
    const,
    cos,
    cosh,
    derivative,
    e,
    eq,
    erf,
    eventually,
    exp,
    external_function,
    external_unary,
    integral,
    interval,
    inv,
    log,
    log_two,
    max,
    min,
    ne,
    pi,
    rational,
    root_excluded,
    root_exists,
    sin,
    sinc,
    sinh,
    sqrt,
    system_root_exists,
    tan,
    tanh,
    unique_root,
    unique_system_root,
    var,
    vector,
)
from .claims import (
    Binder,
    BoundedForAllClaim,
    Claim,
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
from .codec import (
    AstDecodeLimits,
    canonical_bytes,
    decode_and_normalize,
    decode_canonical,
    decode_canonical_strict,
    encode_canonical,
)
from .constants import NamedConstantKind
from .digest import (
    ClaimDigest,
    ExpressionDigest,
    SemanticDigest,
    semantic_digest,
    structural_digest,
)
from .domains import (
    AxisDomain,
    Box,
    Domain,
    FiniteSetDomain,
    Interval,
    NaturalTail,
    ProductDomain,
    SingletonDomain,
)
from .elaboration import close_claim, ensure_closed_claim
from .errors import *
from .expressions import (
    Add,
    Cast,
    Derivative,
    Div,
    Expr,
    FunctionCall,
    Integral,
    Mul,
    NamedConstant,
    Neg,
    Pow,
    RationalConstant,
    Variable,
    Vector,
    as_expr,
)
from .functions import BuiltinFunctionRef, ExternalFunctionRef, FunctionSignature, PackageIdentity
from .legacy import legacy_bound_claim, legacy_box, legacy_expression, legacy_interval
from .normalize import alpha_equivalent, normalize, semantically_equal
from .relations import Relation
from .sorts import (
    BOOLEAN,
    INTEGER,
    NATURAL,
    RATIONAL,
    REAL,
    BooleanSort,
    IntegerSort,
    MatrixSort,
    NaturalSort,
    RationalSort,
    RealSort,
    ScalarSort,
    Sort,
    TupleSort,
    VectorSort,
)
from .symbols import Symbol, SymbolId, SymbolTable
from .traversal import (
    bound_variables,
    children,
    collect_external_functions,
    collect_functions,
    collect_named_constants,
    contains_node_type,
    fold,
    free_variables,
    map_expressions,
    max_depth,
    node_count,
    rename_symbol,
    substitute,
    transform,
    walk,
)
from .validation import AstRequirements, check_capabilities, infer_requirements, validate_ast
from .version import AST_SCHEMA_VERSION, CANONICAL_CODEC_VERSION, NORMALIZATION_VERSION

__all__ = [name for name in globals() if not name.startswith("_")]
