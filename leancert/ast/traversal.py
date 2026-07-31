from __future__ import annotations
from dataclasses import fields,replace,is_dataclass
from ._base import AstNode
from .expressions import Variable,Expr
from .claims import BoundedForAllClaim,EventualClaim
from .errors import SortMismatchError

def children(node): return node.children()
def walk(node):
    yield node
    for child in node.children(): yield from walk(child)
def node_count(node): return sum(1 for _ in walk(node))
def max_depth(node):
    cs=node.children(); return 1+(max(map(max_depth,cs)) if cs else 0)
def free_variables(node):
    result=set()
    def visit(n,bound):
        if isinstance(n,Variable):
            if n.symbol.identifier not in bound: result.add(n)
            return
        if isinstance(n,BoundedForAllClaim):
            visit(n.binder.domain,bound); visit(n.body,bound|{n.binder.variable.symbol.identifier}); return
        if isinstance(n,EventualClaim): visit(n.body,bound|{n.variable.symbol.identifier}); return
        for c in n.children(): visit(c,bound)
    visit(node,set()); return frozenset(result)
def bound_variables(node):
    return frozenset(n.binder.variable for n in walk(node) if isinstance(n,BoundedForAllClaim))|frozenset(n.variable for n in walk(node) if isinstance(n,EventualClaim))
def collect_functions(node):
    from .expressions import FunctionCall
    return frozenset(n.function for n in walk(node) if isinstance(n,FunctionCall))
def collect_external_functions(node):
    from .functions import ExternalFunctionRef
    return frozenset(f for f in collect_functions(node) if isinstance(f,ExternalFunctionRef))
def collect_named_constants(node):
    from .expressions import NamedConstant
    return frozenset(n.constant for n in walk(node) if isinstance(n,NamedConstant))
def contains_node_type(node,kind): return any(isinstance(n,kind) for n in walk(node))
def fold(node,visitor):
    return visitor(node,tuple(fold(c,visitor) for c in node.children()))

def transform(node,fn):
    replacement=fn(node)
    if replacement is not node:return replacement
    if not is_dataclass(node):return node
    changes={}
    for f in fields(node):
        if not f.init:continue
        v=getattr(node,f.name)
        if isinstance(v,AstNode): nv=transform(v,fn)
        elif isinstance(v,tuple): nv=tuple(transform(x,fn) if isinstance(x,AstNode) else x for x in v)
        else:continue
        if nv!=v:changes[f.name]=nv
    return replace(node,**changes) if changes else node
def substitute(node,mapping):
    for old,new in mapping.items():
        if not isinstance(old,Variable):raise TypeError("substitution keys must be variables")
        if isinstance(new,Expr) and old.sort!=new.sort:raise SortMismatchError("substitution sort mismatch",expected=old.sort,actual=new.sort)
    return transform(node,lambda n:mapping.get(n,n) if isinstance(n,Variable) else n)
def rename_symbol(node,old,new): return substitute(node,{old:new})
def map_expressions(node,function): return transform(node,lambda n:function(n) if isinstance(n,Expr) else n)
