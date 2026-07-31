from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .codec import canonical_bytes
from .errors import UnresolvedExternalIdentityError
from .traversal import collect_external_functions
from .version import AST_SCHEMA_VERSION, NORMALIZATION_VERSION


@dataclass(frozen=True, slots=True)
class SemanticDigest:
    algorithm: str
    schema_version: int
    value: str

    def __str__(self):
        return f"lc-ast-v{self.schema_version}:{self.algorithm}:{self.value}"


@dataclass(frozen=True, slots=True)
class ClaimDigest(SemanticDigest):
    pass


@dataclass(frozen=True, slots=True)
class ExpressionDigest(SemanticDigest):
    pass


def semantic_digest(node):
    node = getattr(node, "value", node)
    unresolved = [f for f in collect_external_functions(node) if not f.declaration_digest]
    if unresolved:
        raise UnresolvedExternalIdentityError(
            "external functions require declaration_digest for authoritative semantic identity"
        )
    data = (
        b"LeanCert-AST\0"
        + f"schema={AST_SCHEMA_VERSION}\0normalization={NORMALIZATION_VERSION}\0".encode()
        + canonical_bytes(node)
    )
    from .claims import Claim
    from .expressions import Expr

    kind = (
        ClaimDigest
        if isinstance(node, Claim)
        else ExpressionDigest
        if isinstance(node, Expr)
        else SemanticDigest
    )
    return kind("sha256", AST_SCHEMA_VERSION, hashlib.sha256(data).hexdigest())


def structural_digest(node):
    return hashlib.sha256(canonical_bytes(node)).hexdigest()
