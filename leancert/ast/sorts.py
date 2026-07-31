from __future__ import annotations

from dataclasses import dataclass

from ._base import Node
from .errors import InvalidDimensionError, SortMismatchError


class Sort(Node):
    pass


class ScalarSort(Sort):
    pass


@dataclass(frozen=True, slots=True)
class RealSort(ScalarSort):
    pass


@dataclass(frozen=True, slots=True)
class RationalSort(ScalarSort):
    pass


@dataclass(frozen=True, slots=True)
class IntegerSort(ScalarSort):
    pass


@dataclass(frozen=True, slots=True)
class NaturalSort(ScalarSort):
    pass


@dataclass(frozen=True, slots=True)
class BooleanSort(Sort):
    pass


@dataclass(frozen=True, slots=True)
class VectorSort(Sort):
    element: ScalarSort
    dimension: int

    def __post_init__(self):
        if (
            not isinstance(self.element, ScalarSort)
            or isinstance(self.element, BooleanSort)
            or self.dimension <= 0
        ):
            raise InvalidDimensionError("vector dimension must be positive")


@dataclass(frozen=True, slots=True)
class MatrixSort(Sort):
    element: ScalarSort
    rows: int
    columns: int

    def __post_init__(self):
        if not isinstance(self.element, ScalarSort) or self.rows <= 0 or self.columns <= 0:
            raise InvalidDimensionError("matrix dimensions must be positive")


@dataclass(frozen=True, slots=True)
class TupleSort(Sort):
    elements: tuple[Sort, ...]

    def __post_init__(self):
        object.__setattr__(self, "elements", tuple(self.elements))


REAL = RealSort()
RATIONAL = RationalSort()
INTEGER = IntegerSort()
NATURAL = NaturalSort()
BOOLEAN = BooleanSort()
_RANK = {NATURAL: 0, INTEGER: 1, RATIONAL: 2, REAL: 3}


def common_sort(a: Sort, b: Sort) -> Sort:
    if a == b:
        return a
    if a in _RANK and b in _RANK:
        return max((a, b), key=_RANK.__getitem__)
    raise SortMismatchError("incompatible sorts", expected=a, actual=b)


def can_cast(source: Sort, target: Sort) -> bool:
    return source == target or (
        source in _RANK and target in _RANK and _RANK[source] <= _RANK[target]
    )
