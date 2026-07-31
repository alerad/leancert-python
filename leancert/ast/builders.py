from __future__ import annotations
from fractions import Fraction
from decimal import Decimal
from .sorts import Sort,REAL,NATURAL
from .symbols import Symbol,SymbolId,SymbolTable
from .expressions import *
from .functions import *
from .claims import *
from .domains import Interval,box as _box
from .relations import Relation
from .numeric import exact_fraction
from .constants import NamedConstantKind

pi=NamedConstant(NamedConstantKind.PI,REAL)
e=NamedConstant(NamedConstantKind.E,REAL)
log_two=NamedConstant(NamedConstantKind.LOG_TWO,REAL)

def var(name:str,sort:Sort=REAL,namespace:str="default")->Variable:return Variable(Symbol(SymbolId(namespace,name),name,sort))
def const(value,sort:Sort|None=None)->RationalConstant:
    f=exact_fraction(value)
    if sort is None:sort=NATURAL if f.denominator==1 and f>=0 else INTEGER if f.denominator==1 else RATIONAL
    return RationalConstant(f.numerator,f.denominator,sort)
def rational(value:str|Decimal|int|Fraction):return const(exact_fraction(value),RATIONAL)
def _call(f,*args):return FunctionCall(f,tuple(as_expr(a) for a in args))
def sin(x):return _call(SIN,x)
def cos(x):return _call(COS,x)
def tan(x):return _call(TAN,x)
def exp(x):return _call(EXP,x)
def log(x):return _call(LOG,x)
def sqrt(x):return _call(SQRT,x)
def arcsin(x):return _call(ARCSIN,x)
def arccos(x):return _call(ARCCOS,x)
def sinh(x):return _call(SINH,x)
def cosh(x):return _call(COSH,x)
def tanh(x):return _call(TANH,x)
def sinc(x):return _call(SINC,x)
def erf(x):return _call(ERF,x)
def abs(x):return _call(ABS,x)
def min(a,b):return _call(MIN,a,b)
def max(a,b):return _call(MAX,a,b)
def vector(*xs):return Vector(tuple(as_expr(x) for x in xs))
def eq(a,b):return _comparison(a,Relation.EQ,b)
def ne(a,b):return _comparison(a,Relation.NE,b)
def _comparison(a,r,b):
    a,b=as_expr(a),as_expr(b); s=common_sort(a.sort,b.sort); return ComparisonClaim(cast(a,s),r,cast(b,s))
def all_of(*claims):return ConjunctionClaim(tuple(claims))
def any_of(*claims):return DisjunctionClaim(tuple(claims))
def interval(a,b,*,lower_closed=True,upper_closed=True):return Interval(as_expr(a),as_expr(b),lower_closed,upper_closed)
def box(mapping):return _box(mapping)
def integral(integrand,variable,lower,upper):return Integral(as_expr(integrand),variable,Interval.closed(lower,upper))
def derivative(expression,variable):return Derivative(as_expr(expression),variable)
def root_exists(expression,*,variable,within):return RootExistsClaim(as_expr(expression),variable,within if isinstance(within,Interval) else Interval.closed(*within))
def unique_root(expression,*,variable,within):return UniqueRootClaim(as_expr(expression),variable,within if isinstance(within,Interval) else Interval.closed(*within))
def root_excluded(expression,*,variable,within):return RootExcludedClaim(as_expr(expression),variable,within if isinstance(within,Interval) else Interval.closed(*within))
def _zero_equations(equations):
    """Convert expressions ``f`` (meaning ``f = 0``) or equality claims to residuals."""
    result=[]
    for equation in equations:
        if isinstance(equation,ComparisonClaim):
            if equation.relation != Relation.EQ:
                raise TypeError("system roots accept expressions meaning f = 0 or equality claims from eq(lhs, rhs)")
            equation=equation.lhs-equation.rhs
        result.append(as_expr(equation))
    return tuple(result)
def system_root_exists(equations,*,variables,within):
    """State that the residual expressions have a simultaneous zero in ``within``."""
    return SystemRootClaim(_zero_equations(equations),tuple(variables),within,False)
def unique_system_root(equations,*,variables,within):
    """State that the residual expressions have exactly one simultaneous zero."""
    return SystemRootClaim(_zero_equations(equations),tuple(variables),within,True)
def eventually(body,*,variable,cutoff=None):
    """State an eventual claim, optionally at a user-supplied fixed cutoff."""
    return EventualClaim(variable,body,None if cutoff is None else as_expr(cutoff))
def external_function(lean_name,signature,package,semantic_id,*,declaration_digest=None):return ExternalFunctionRef(lean_name,signature,package,semantic_id,declaration_digest)
def external_unary(lean_name,package,semantic_id,*,declaration_digest=None):return external_function(lean_name,FunctionSignature((REAL,),REAL),package,semantic_id,declaration_digest=declaration_digest)
