"""Elaboration from ergonomic, open claims to closed semantic claims."""

from __future__ import annotations

from collections.abc import Mapping

from .claims import Binder, BoundedForAllClaim, Claim
from .domains import Domain, Interval
from .errors import FreeVariableError
from .expressions import Variable
from .normalize import normalize
from .traversal import free_variables


def _domain(value: Domain | tuple[object, object]) -> Domain:
    return value if isinstance(value, Domain) else Interval.closed(*value)


def close_claim(
    claim: Claim,
    where: Mapping[Variable, Domain | tuple[object, object]] | None = None,
) -> Claim:
    """Bind every free variable using an exact domain from ``where``.

    Variable identity, not display name, is authoritative.  Binder order is
    canonicalized by ``SymbolId`` so mapping insertion order cannot affect the
    wire representation or semantic digest.
    """
    if not isinstance(claim, Claim):
        raise TypeError("close_claim expects a Claim")
    where = {} if where is None else dict(where)
    if any(not isinstance(variable, Variable) for variable in where):
        raise TypeError("where keys must be semantic AST Variable objects")
    free = free_variables(claim)
    missing = free - where.keys()
    extra = where.keys() - free
    if missing or extra:
        details = []
        if missing:
            details.append("missing: " + ", ".join(sorted(v.name for v in missing)))
        if extra:
            details.append("not free: " + ", ".join(sorted(v.name for v in extra)))
        raise FreeVariableError(
            "where must bind exactly the free variables (" + "; ".join(details) + ")"
        )
    result = claim
    ordered = sorted(free, key=lambda v: (v.symbol.identifier.namespace, v.symbol.identifier.name))
    for variable in reversed(ordered):
        result = BoundedForAllClaim(Binder(variable, _domain(where[variable])), result)
    return ensure_closed_claim(normalize(result))


def ensure_closed_claim(claim: Claim) -> Claim:
    """Return ``claim`` or raise when it contains an unbound variable."""
    free = free_variables(claim)
    if free:
        names = ", ".join(sorted(f"{v.symbol.identifier.namespace}:{v.name}" for v in free))
        raise FreeVariableError(f"claim contains free variables: {names}")
    return claim
