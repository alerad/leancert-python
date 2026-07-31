from __future__ import annotations
from dataclasses import dataclass
import hashlib
from .version import AST_SCHEMA_VERSION,NORMALIZATION_VERSION
from .codec import canonical_bytes
from .traversal import collect_external_functions
from .errors import UnresolvedExternalIdentityError

@dataclass(frozen=True,slots=True)
class SemanticDigest:
    algorithm:str; schema_version:int; value:str
    def __str__(self):return f"lc-ast-v{self.schema_version}:{self.algorithm}:{self.value}"
ClaimDigest=SemanticDigest; ExpressionDigest=SemanticDigest
def semantic_digest(node):
    unresolved=[f for f in collect_external_functions(getattr(node,"value",node)) if not f.declaration_digest]
    if unresolved:raise UnresolvedExternalIdentityError("external functions require declaration_digest for authoritative semantic identity")
    data=b"LeanCert-AST\0"+f"schema={AST_SCHEMA_VERSION}\0normalization={NORMALIZATION_VERSION}\0".encode()+canonical_bytes(node)
    return SemanticDigest("sha256",AST_SCHEMA_VERSION,hashlib.sha256(data).hexdigest())
def structural_digest(node):
    return hashlib.sha256(canonical_bytes(node)).hexdigest()
