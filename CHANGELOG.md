# Changelog

Notable user-facing changes to LeanCert Python are recorded here.

## 2.0.0 — 2026-08-06

- Moved Lean execution and distribution onto Lean Runtime 2, using
  content-addressed ready-to-run Bridge programs for ordinary checks and exact
  full environments for independent replay and rebuilds.
- Kept the PyPI wheel pure Python and small; users install LeanCert normally,
  while the compatible checked program is downloaded lazily and reused.
- Added typed checked outcomes with explicit execution, checker, authority,
  environment, and program provenance.
- Made adaptive numerical work candidate generation only: success is reported
  only after the Lean Bridge accepts an exact certificate.
- Added independently replayable/exportable evidence for comparisons,
  conjunctions, eventual bounds, nonlinear and scalar roots, polynomial
  integrals, strict global bounds, and registered enclosure profiles.
- Added the `leancert verify` audit path for exported Lean projects.
- Required `lean-runtime>=2.0.0,<3.0.0`.

### Breaking changes

- Runtime and distribution vocabulary now follows Lean Runtime 2:
  environments, environment libraries, portable copies, and ready-to-run
  programs replace the former cache, bundle, and capsule terminology.
- Public results and provenance use program IDs and copy IDs instead of
  capsule and manifest identifiers.
- The v2 typed result and protocol model replaces legacy success paths that
  could blur numerical evidence with checked proof authority.

## 1.0.0 — 2026-08-02

- Introduced the exact semantic AST and unified `prove(...)` front door.
- Added typed Bridge protocol negotiation and checked-response invariants.
- Added exact provenance and independently exportable Lean evidence.
- Established the provisional evaluation license for post-baseline Python SDK
  work; earlier Apache-2.0 releases remain available under their original
  terms.
