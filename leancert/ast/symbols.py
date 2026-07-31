from __future__ import annotations
from dataclasses import dataclass, field
import unicodedata
from ._base import Node
from .sorts import Sort, REAL
from .errors import AstValidationError

@dataclass(frozen=True, slots=True, order=True)
class SymbolId:
    namespace: str
    name: str

def _name(value: str, label: str) -> str:
    if not isinstance(value,str) or not value or value != value.strip() or any(unicodedata.category(c)=="Cc" for c in value) or value.startswith("__leancert"):
        raise AstValidationError(f"invalid {label}")
    return value

@dataclass(frozen=True, slots=True)
class Symbol(Node):
    identifier: SymbolId
    display_name: str
    sort: Sort
    def __post_init__(self): _name(self.display_name,"symbol name"); _name(self.identifier.namespace,"namespace")

class SymbolTable:
    def __init__(self, namespace: str="default"): self.namespace=_name(namespace,"namespace"); self._symbols={}
    def var(self, name: str, sort: Sort=REAL):
        from .expressions import Variable
        key=(name,sort)
        if key not in self._symbols: self._symbols[key]=Variable(Symbol(SymbolId(self.namespace,name),name,sort))
        return self._symbols[key]
