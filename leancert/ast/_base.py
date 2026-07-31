from __future__ import annotations
from typing import Any, Protocol, runtime_checkable

@runtime_checkable
class AstNode(Protocol):
    @property
    def node_kind(self) -> str: ...
    def children(self) -> tuple[AstNode, ...]: ...

class Node:
    @property
    def node_kind(self) -> str:
        return type(self).__name__
    def children(self) -> tuple[AstNode, ...]:
        return ()

def reject_bool(_: str) -> None:
    raise TypeError("symbolic values have no Python truth value; Python chained comparisons are not supported; use all_of(...)")
