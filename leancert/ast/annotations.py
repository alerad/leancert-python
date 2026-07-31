from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class SourceSpan:
    filename: str | None = None
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True, slots=True)
class Annotated(Generic[T]):
    value: T
    annotations: tuple[tuple[str, Any], ...] = ()

    def __init__(self, value: T, annotations: Mapping[str, Any] | tuple[tuple[str, Any], ...] = ()):
        object.__setattr__(self, "value", value)
        object.__setattr__(
            self,
            "annotations",
            tuple(annotations.items()) if isinstance(annotations, Mapping) else tuple(annotations),
        )
