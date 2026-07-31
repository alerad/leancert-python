# Semantic AST v1

`leancert.ast` is the bridge-independent meaning layer for LeanCert Python.
It represents mathematical expressions, domains, and claims; it does not
represent a successful proof and never sets a `verified` flag.

## Exact values and identities

Numeric literals are exact integers, decimal strings, `Decimal` values, or
`Fraction` values. Python `float` is rejected because its intended decimal
value cannot be recovered reliably. Variables are identified by
`SymbolId(namespace, name)`; display names are metadata. External functions
require package, revision, semantic, and declaration identities before an
authoritative semantic digest can be computed.

## Binders and closed claims

Quantifiers, scalar and system roots, integrals, derivatives, and eventual
claims bind variables. Canonical JSON encodes bound references with De Bruijn
depths, so alpha-renaming does not change meaning. Decoding may therefore
produce an alpha-equivalent object with generated local names rather than an
object equal to the source.

Use `close_claim(claim, where={x: (0, 1)})` before bridge transmission. It
requires exact variable coverage, orders binders deterministically, and rejects
remaining free variables. `validate_ast(..., require_closed=True)` enforces the
same boundary for already elaborated claims.

## Canonical encoding and digests

`encode_canonical` first normalizes the AST and emits the versioned
`leancert.ast` schema. Object keys are sorted only when bytes are materialized;
commutative operands and unordered box axes are normalized semantically.
`decode_canonical_strict` additionally rejects valid but noncanonical payloads.

A semantic digest commits to:

- AST schema version;
- normalization version;
- canonical semantic bytes;
- resolved external declaration identities.

Annotations and source spans do not affect it. Schema or normalization changes
that can alter meaning require a version bump and new golden fixtures.

## Compatibility

The functions `legacy_expression`, `legacy_interval`, `legacy_box`, and
`legacy_bound_claim` convert the pre-1.0 SDK objects explicitly. Conversion is
not verification. Legacy float values retain the exact rational value already
stored by the legacy object; new semantic AST construction rejects floats.

Golden v1 payloads live in `leancert/tests/fixtures/ast-v1`. They are protocol
fixtures: changing their canonical bytes or digests is a compatibility event,
not routine formatting cleanup.
