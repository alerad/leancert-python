from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
from .version import AST_SCHEMA_VERSION
from .errors import AstDecodeError,AstDecodeLimitError,UnknownAstNodeVersion

@dataclass(frozen=True,slots=True)
class AstDecodeLimits:
    max_bytes:int=10_000_000; max_nodes:int=100_000; max_depth:int=512; max_string_length:int=100_000; max_integer_digits:int=100_000; max_collection_length:int=100_000

def _sort(s):
    from .sorts import RealSort,RationalSort,IntegerSort,NaturalSort,BooleanSort,VectorSort,MatrixSort,TupleSort
    names={RealSort:"real",RationalSort:"rational",IntegerSort:"integer",NaturalSort:"natural",BooleanSort:"boolean"}
    if type(s) in names:return {"kind":names[type(s)]}
    if isinstance(s,VectorSort):return {"kind":"vector_sort","element":_sort(s.element),"dimension":str(s.dimension)}
    if isinstance(s,MatrixSort):return {"kind":"matrix_sort","element":_sort(s.element),"rows":str(s.rows),"columns":str(s.columns)}
    if isinstance(s,TupleSort):return {"kind":"tuple_sort","elements":[_sort(x) for x in s.elements]}
    raise TypeError(type(s))
def _function(f):
    from .functions import BuiltinFunctionRef
    sig={"arguments":[_sort(x) for x in f.signature.arguments],"result":_sort(f.signature.result)}
    if isinstance(f,BuiltinFunctionRef):return {"kind":"builtin_function","name":f.name,"semantic_id":f.semantic_id,"signature":sig}
    return {"kind":"external_function","lean_name":f.lean_name,"semantic_id":f.semantic_id,"declaration_digest":f.declaration_digest,"signature":sig,"package":{"name":f.package.name,"source":f.package.source,"revision":f.package.revision,"environment_digest":f.package.environment_digest}}

def _encode_node(n,bound=()):
    from .expressions import RationalConstant,NamedConstant,Variable,Cast,Neg,Add,Mul,Div,Pow,FunctionCall,Vector,Integral,Derivative
    from .domains import Interval,AxisDomain,Box,NaturalTail,SingletonDomain,FiniteSetDomain,ProductDomain
    from .claims import TrueClaim,FalseClaim,ComparisonClaim,ConjunctionClaim,DisjunctionClaim,NegationClaim,Binder,BoundedForAllClaim,RootExistsClaim,UniqueRootClaim,RootExcludedClaim,SystemRootClaim,EventualClaim
    if isinstance(n,RationalConstant):return {"kind":"rational","numerator":str(n.numerator),"denominator":str(n.denominator),"sort":_sort(n.sort)}
    if isinstance(n,NamedConstant):return {"kind":"named_constant","constant":n.constant.value}
    if isinstance(n,Variable):
        sid=n.symbol.identifier
        for depth,b in enumerate(reversed(bound)):
            if sid==b:return {"kind":"bound_variable","depth":str(depth),"sort":_sort(n.sort)}
        return {"kind":"variable","namespace":sid.namespace,"name":sid.name,"display_name":n.name,"sort":_sort(n.sort)}
    if isinstance(n,Cast):return {"kind":"cast","expression":_encode_node(n.expression,bound),"target":_sort(n.target)}
    if isinstance(n,Neg):return {"kind":"neg","expression":_encode_node(n.expression,bound)}
    if isinstance(n,Add):return {"kind":"add","terms":[_encode_node(x,bound) for x in n.terms]}
    if isinstance(n,Mul):return {"kind":"mul","factors":[_encode_node(x,bound) for x in n.factors]}
    if isinstance(n,Div):return {"kind":"div","numerator":_encode_node(n.numerator,bound),"denominator":_encode_node(n.denominator,bound),"sort":_sort(n.sort)}
    if isinstance(n,Pow):return {"kind":"pow","base":_encode_node(n.base,bound),"exponent":_encode_node(n.exponent,bound)}
    if isinstance(n,FunctionCall):return {"kind":"function_call","function":_function(n.function),"arguments":[_encode_node(x,bound) for x in n.arguments]}
    if isinstance(n,Vector):return {"kind":"vector","elements":[_encode_node(x,bound) for x in n.elements]}
    if isinstance(n,Integral):
        sid=n.variable.symbol.identifier; return {"kind":"integral","variable_sort":_sort(n.variable.sort),"domain":_encode_node(n.domain,bound),"integrand":_encode_node(n.integrand,bound+(sid,))}
    if isinstance(n,Derivative):
        sid=n.variable.symbol.identifier; return {"kind":"derivative","variable":_encode_node(n.variable,bound),"expression":_encode_node(n.expression,bound+(sid,))}
    if isinstance(n,Interval):return {"kind":"interval","lower":_encode_node(n.lower,bound),"upper":_encode_node(n.upper,bound),"lower_closed":n.lower_closed,"upper_closed":n.upper_closed}
    if isinstance(n,AxisDomain):return {"kind":"axis","variable":_encode_node(n.variable,bound),"interval":_encode_node(n.interval,bound)}
    if isinstance(n,Box):return {"kind":"box","axes":[_encode_node(x,bound) for x in n.axes]}
    if isinstance(n,NaturalTail):return {"kind":"natural_tail","variable":_encode_node(n.variable,bound),"lower":_encode_node(n.lower,bound)}
    if isinstance(n,SingletonDomain):return {"kind":"singleton_domain","value":_encode_node(n.value,bound)}
    if isinstance(n,FiniteSetDomain):return {"kind":"finite_set_domain","values":[_encode_node(x,bound) for x in n.values]}
    if isinstance(n,ProductDomain):return {"kind":"product_domain","domains":[_encode_node(x,bound) for x in n.domains]}
    if isinstance(n,TrueClaim):return {"kind":"true"}
    if isinstance(n,FalseClaim):return {"kind":"false"}
    if isinstance(n,ComparisonClaim):return {"kind":"comparison","lhs":_encode_node(n.lhs,bound),"relation":n.relation.value,"rhs":_encode_node(n.rhs,bound)}
    if isinstance(n,ConjunctionClaim):return {"kind":"conjunction","claims":[_encode_node(x,bound) for x in n.claims]}
    if isinstance(n,DisjunctionClaim):return {"kind":"disjunction","claims":[_encode_node(x,bound) for x in n.claims]}
    if isinstance(n,NegationClaim):return {"kind":"not","claim":_encode_node(n.claim,bound)}
    if isinstance(n,BoundedForAllClaim):
        sid=n.binder.variable.symbol.identifier; return {"kind":"forall","variable_sort":_sort(n.binder.variable.sort),"domain":_encode_node(n.binder.domain,bound),"body":_encode_node(n.body,bound+(sid,))}
    roots={UniqueRootClaim:"unique_root",RootExcludedClaim:"root_excluded",RootExistsClaim:"root_exists"}
    if type(n) in roots:return {"kind":roots[type(n)],"expression":_encode_node(n.expression,bound+(n.variable.symbol.identifier,)),"variable_sort":_sort(n.variable.sort),"domain":_encode_node(n.domain,bound)}
    if isinstance(n,SystemRootClaim):return {"kind":"system_root","equations":[_encode_node(x,bound) for x in n.equations],"variables":[_encode_node(x,bound) for x in n.variables],"domain":_encode_node(n.domain,bound),"uniqueness":n.uniqueness}
    if isinstance(n,EventualClaim):return {"kind":"eventual","variable_sort":_sort(n.variable.sort),"body":_encode_node(n.body,bound+(n.variable.symbol.identifier,)),"explicit_cutoff":None if n.explicit_cutoff is None else _encode_node(n.explicit_cutoff,bound)}
    raise TypeError(f"unsupported AST node {type(n).__name__}")

def encode_canonical(node):
    from .annotations import Annotated
    from .normalize import normalize
    if isinstance(node,Annotated):node=node.value
    return {"schema":"leancert.ast","version":AST_SCHEMA_VERSION,"root":_encode_node(normalize(node))}
def canonical_bytes(node):return json.dumps(encode_canonical(node),ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")

def _pairs(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise AstDecodeError(f"duplicate key: {k}")
        d[k]=v
    return d
def _expect(d,keys):
    if set(d)!=set(keys):raise AstDecodeError(f"fields mismatch: expected {sorted(keys)}, got {sorted(d)}")
def _ds(d):
    from .sorts import REAL,RATIONAL,INTEGER,NATURAL,BOOLEAN,VectorSort,MatrixSort,TupleSort
    k=d.get("kind"); simple={"real":REAL,"rational":RATIONAL,"integer":INTEGER,"natural":NATURAL,"boolean":BOOLEAN}
    if k in simple:_expect(d,{"kind"});return simple[k]
    if k=="vector_sort":_expect(d,{"kind","element","dimension"});return VectorSort(_ds(d["element"]),int(d["dimension"]))
    if k=="matrix_sort":_expect(d,{"kind","element","rows","columns"});return MatrixSort(_ds(d["element"]),int(d["rows"]),int(d["columns"]))
    if k=="tuple_sort":return TupleSort(tuple(_ds(x) for x in d["elements"]))
    raise AstDecodeError("unknown sort")
def _df(d):
    from .functions import FunctionSignature,BuiltinFunctionRef,ExternalFunctionRef,PackageIdentity
    sig=FunctionSignature(tuple(_ds(x) for x in d["signature"]["arguments"]),_ds(d["signature"]["result"]))
    if d["kind"]=="builtin_function":return BuiltinFunctionRef(d["name"],sig,d["semantic_id"])
    p=d["package"]; return ExternalFunctionRef(d["lean_name"],sig,PackageIdentity(p["name"],p["source"],p["revision"],p["environment_digest"]),d["semantic_id"],d["declaration_digest"])
def _decode(d,bound=()):
    from .expressions import RationalConstant,NamedConstant,Variable,Cast,Neg,Add,Mul,Div,Pow,FunctionCall,Vector,Integral,Derivative
    from .symbols import Symbol,SymbolId
    from .constants import NamedConstantKind
    from .domains import Interval,AxisDomain,Box,NaturalTail,SingletonDomain,FiniteSetDomain,ProductDomain
    from .claims import TrueClaim,FalseClaim,ComparisonClaim,ConjunctionClaim,DisjunctionClaim,NegationClaim,Binder,BoundedForAllClaim,RootExistsClaim,UniqueRootClaim,RootExcludedClaim,SystemRootClaim,EventualClaim
    from .relations import Relation
    k=d.get("kind")
    if k=="rational":return RationalConstant(int(d["numerator"]),int(d["denominator"]),_ds(d["sort"]))
    if k=="named_constant":return NamedConstant(NamedConstantKind(d["constant"]))
    if k=="variable":return Variable(Symbol(SymbolId(d["namespace"],d["name"]),d["display_name"],_ds(d["sort"])))
    if k=="bound_variable":return bound[-1-int(d["depth"])]
    if k=="cast":return Cast(_decode(d["expression"],bound),_ds(d["target"]))
    if k=="neg":return Neg(_decode(d["expression"],bound))
    if k=="add":return Add(tuple(_decode(x,bound) for x in d["terms"]))
    if k=="mul":return Mul(tuple(_decode(x,bound) for x in d["factors"]))
    if k=="div":return Div(_decode(d["numerator"],bound),_decode(d["denominator"],bound),_ds(d["sort"]))
    if k=="pow":return Pow(_decode(d["base"],bound),_decode(d["exponent"],bound))
    if k=="function_call":return FunctionCall(_df(d["function"]),tuple(_decode(x,bound) for x in d["arguments"]))
    if k=="vector":return Vector(tuple(_decode(x,bound) for x in d["elements"]))
    if k=="derivative":
        v=_decode(d["variable"],bound); return Derivative(_decode(d["expression"],bound+(v,)),v)
    if k=="interval":return Interval(_decode(d["lower"],bound),_decode(d["upper"],bound),d["lower_closed"],d["upper_closed"])
    if k=="axis":return AxisDomain(_decode(d["variable"],bound),_decode(d["interval"],bound))
    if k=="box":return Box(tuple(_decode(x,bound) for x in d["axes"]))
    if k=="natural_tail":return NaturalTail(_decode(d["variable"],bound),_decode(d["lower"],bound))
    if k=="singleton_domain":return SingletonDomain(_decode(d["value"],bound))
    if k=="finite_set_domain":return FiniteSetDomain(tuple(_decode(x,bound) for x in d["values"]))
    if k=="product_domain":return ProductDomain(tuple(_decode(x,bound) for x in d["domains"]))
    if k=="true":return TrueClaim()
    if k=="false":return FalseClaim()
    if k=="comparison":return ComparisonClaim(_decode(d["lhs"],bound),Relation(d["relation"]),_decode(d["rhs"],bound))
    if k=="conjunction":return ConjunctionClaim(tuple(_decode(x,bound) for x in d["claims"]))
    if k=="disjunction":return DisjunctionClaim(tuple(_decode(x,bound) for x in d["claims"]))
    if k=="not":return NegationClaim(_decode(d["claim"],bound))
    if k in ("forall","eventual","root_exists","unique_root","root_excluded","integral"):
        v=Variable(Symbol(SymbolId("decoded",f"b{len(bound)}"),f"b{len(bound)}",_ds(d["variable_sort"])))
        if k=="forall":return BoundedForAllClaim(Binder(v,_decode(d["domain"],bound)),_decode(d["body"],bound+(v,)))
        if k=="eventual":return EventualClaim(v,_decode(d["body"],bound+(v,)),None if d["explicit_cutoff"] is None else _decode(d["explicit_cutoff"],bound))
        if k=="integral":return Integral(_decode(d["integrand"],bound+(v,)),v,_decode(d["domain"],bound))
        cls={"root_exists":RootExistsClaim,"unique_root":UniqueRootClaim,"root_excluded":RootExcludedClaim}[k]
        return cls(_decode(d["expression"],bound+(v,)),v,_decode(d["domain"],bound))
    if k=="system_root":return SystemRootClaim(tuple(_decode(x,bound) for x in d["equations"]),tuple(_decode(x,bound) for x in d["variables"]),_decode(d["domain"],bound),d["uniqueness"])
    raise AstDecodeError(f"unknown node kind: {k!r}")

def decode_canonical(payload,limits=AstDecodeLimits()):
    try:
        if isinstance(payload,(bytes,str)):
            raw=payload if isinstance(payload,bytes) else payload.encode();
            if len(raw)>limits.max_bytes:raise AstDecodeLimitError("payload exceeds max_bytes")
            payload=json.loads(raw,object_pairs_hook=_pairs)
        _expect(payload,{"schema","version","root"})
        if payload["schema"]!="leancert.ast" or payload["version"]!=AST_SCHEMA_VERSION:raise UnknownAstNodeVersion("unsupported AST schema/version")
        def check(x,depth=0):
            if depth>limits.max_depth:raise AstDecodeLimitError("payload exceeds max_depth")
            if isinstance(x,str) and len(x)>limits.max_string_length:raise AstDecodeLimitError("string too long")
            if isinstance(x,(list,dict)) and len(x)>limits.max_collection_length:raise AstDecodeLimitError("collection too long")
            for v in (x.values() if isinstance(x,dict) else x if isinstance(x,list) else ()):check(v,depth+1)
        check(payload); return _decode(payload["root"])
    except (AstDecodeError,AstDecodeLimitError,UnknownAstNodeVersion):raise
    except Exception as exc:raise AstDecodeError(str(exc)) from exc
decode_canonical_strict=decode_canonical
def decode_and_normalize(payload,limits=AstDecodeLimits()):
    from .normalize import normalize
    return normalize(decode_canonical(payload,limits))
