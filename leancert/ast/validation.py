from __future__ import annotations
from dataclasses import dataclass
from ._base import AstNode
from .traversal import walk,collect_functions
from .expressions import FunctionCall,Integral
from .claims import Claim,SystemRootClaim
from .errors import AstValidationError,ArityError,DimensionMismatchError

def validate_ast(node):
    if not isinstance(node,AstNode):raise AstValidationError("value is not an AST node")
    count=0
    for n in walk(node):
        count+=1
        if isinstance(n,FunctionCall) and len(n.arguments)!=len(n.function.signature.arguments):raise ArityError("function arity mismatch")
        if isinstance(n,SystemRootClaim) and len(n.equations)!=len(n.variables):raise DimensionMismatchError("system dimensions disagree")
    return node
@dataclass(frozen=True,slots=True)
class AstRequirements:
    builtins:frozenset[str]; external_functions:frozenset; sorts:frozenset[str]; claim_features:frozenset[str]; domain_features:frozenset[str]; dimensions:frozenset[int]
    @property
    def features(self):return frozenset({*(f"builtin.{x}" for x in self.builtins),*self.sorts,*self.claim_features,*self.domain_features})
def infer_requirements(node):
    from .functions import BuiltinFunctionRef,ExternalFunctionRef
    from .sorts import RealSort,VectorSort,MatrixSort
    from .domains import Interval,Box
    built=set(); external=set(); sorts=set(); claims=set(); domains=set(); dimensions=set()
    for n in walk(node):
        if isinstance(n,FunctionCall):
            (built.add(n.function.name) if isinstance(n.function,BuiltinFunctionRef) else external.add(n.function))
        if hasattr(n,"sort"):
            s=n.sort; sorts.add(f"sort.{type(s).__name__.removesuffix('Sort').lower()}")
            if isinstance(s,VectorSort):dimensions.add(s.dimension)
            if isinstance(s,MatrixSort):dimensions|={s.rows,s.columns}
        if isinstance(n,Claim):claims.add("claim."+n.node_kind.removesuffix("Claim").lower())
        if isinstance(n,Interval):domains.add("domain.interval")
        if isinstance(n,Box):domains.add("domain.box");dimensions.add(len(n.axes))
    return AstRequirements(frozenset(built),frozenset(external),frozenset(sorts),frozenset(claims),frozenset(domains),frozenset(dimensions))
def check_capabilities(node,capability_manifest):
    req=infer_requirements(node); available=set(capability_manifest)
    return frozenset(req.features-available)
