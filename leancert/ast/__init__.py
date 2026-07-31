"""LeanCert's immutable, exact, bridge-independent semantic AST."""
from ._base import AstNode
from .annotations import Annotated,SourceSpan
from .builders import (var,const,rational,pi,e,log_two,sin,cos,tan,exp,log,sqrt,arcsin,arccos,sinh,cosh,tanh,sinc,erf,abs,min,max,vector,derivative,eq,ne,all_of,any_of,interval,box,integral,root_exists,unique_root,root_excluded,system_root_exists,unique_system_root,eventually,external_function,external_unary)
from .claims import (Claim,TrueClaim,FalseClaim,ComparisonClaim,ConjunctionClaim,DisjunctionClaim,NegationClaim,Binder,BoundedForAllClaim,RootExistsClaim,UniqueRootClaim,RootExcludedClaim,SystemRootClaim,EventualClaim)
from .codec import AstDecodeLimits,encode_canonical,canonical_bytes,decode_canonical,decode_canonical_strict,decode_and_normalize
from .constants import NamedConstantKind
from .digest import SemanticDigest,ClaimDigest,ExpressionDigest,semantic_digest,structural_digest
from .domains import Domain,Interval,AxisDomain,Box,NaturalTail,SingletonDomain,FiniteSetDomain,ProductDomain
from .errors import *
from .expressions import (Expr,RationalConstant,NamedConstant,Variable,Cast,Neg,Add,Mul,Div,Pow,FunctionCall,Vector,Integral,Derivative,as_expr)
from .functions import FunctionSignature,BuiltinFunctionRef,ExternalFunctionRef,PackageIdentity
from .normalize import normalize,semantically_equal,alpha_equivalent
from .relations import Relation
from .sorts import (Sort,ScalarSort,RealSort,RationalSort,IntegerSort,NaturalSort,BooleanSort,VectorSort,MatrixSort,TupleSort,REAL,RATIONAL,INTEGER,NATURAL,BOOLEAN)
from .symbols import SymbolId,Symbol,SymbolTable
from .traversal import (walk,children,fold,transform,free_variables,bound_variables,collect_functions,collect_external_functions,collect_named_constants,substitute,rename_symbol,map_expressions,contains_node_type,node_count,max_depth)
from .validation import validate_ast,infer_requirements,check_capabilities,AstRequirements
from .version import AST_SCHEMA_VERSION,NORMALIZATION_VERSION,CANONICAL_CODEC_VERSION

__all__=[name for name in globals() if not name.startswith("_")]
