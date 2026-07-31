"""Programmatically inspectable AST errors."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True, slots=True)
class AstPath:
    parts: tuple[str | int, ...] = ()
    def __str__(self) -> str:
        out = ""
        for p in self.parts:
            out += f"[{p}]" if isinstance(p, int) else (("." if out else "") + p)
        return out or "<root>"

class AstError(Exception):
    code = "LC_AST_ERROR"
    def __init__(self, summary: str, *, path: AstPath | tuple[str | int, ...] = AstPath(), expected: Any = None, actual: Any = None):
        self.summary = summary
        self.path = path if isinstance(path, AstPath) else AstPath(path)
        self.expected = expected
        self.actual = actual
        super().__init__(f"{self.code}: {summary} (at {self.path})")

class AstValidationError(AstError): code = "LC_AST_VALIDATION"
class SortMismatchError(AstValidationError): code = "LC_AST_SORT_MISMATCH"
class ArityError(AstValidationError): code = "LC_AST_ARITY"
class DimensionMismatchError(AstValidationError): code = "LC_AST_DIMENSION_MISMATCH"
class InvalidDimensionError(AstValidationError): code = "LC_AST_INVALID_DIMENSION"
class InvalidConstantError(AstValidationError): code = "LC_AST_INVALID_CONSTANT"
class InexactFloatError(InvalidConstantError): code = "LC_AST_INEXACT_FLOAT"
class InvalidDomainError(AstValidationError): code = "LC_AST_INVALID_DOMAIN"
class DuplicateBinderError(AstValidationError): code = "LC_AST_DUPLICATE_BINDER"
class FreeVariableError(AstValidationError): code = "LC_AST_FREE_VARIABLE"
class UnsupportedAstFeatureError(AstValidationError): code = "LC_AST_UNSUPPORTED_FEATURE"
class NonCanonicalAstError(AstValidationError): code = "LC_AST_NON_CANONICAL"
class AstDecodeError(AstError): code = "LC_AST_DECODE"
class AstDecodeLimitError(AstDecodeError): code = "LC_AST_DECODE_LIMIT"
class UnknownAstNodeVersion(AstDecodeError): code = "LC_AST_UNKNOWN_VERSION"
class UnresolvedExternalIdentityError(AstError): code = "LC_AST_UNRESOLVED_EXTERNAL_IDENTITY"
