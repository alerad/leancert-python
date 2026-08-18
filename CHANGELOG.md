# Changelog

Notable user-facing changes to LeanCert Python are recorded here.

## Unreleased

- Migrated the managed execution integration to `lean-runtime>=4.0.1,<5.0.0`.
  Ordinary checks continue to use a pinned ready program, while full Bridge
  environments now default to exact source materialization because Runtime 4
  environment libraries contain source-free check capsules that cannot launch
  interactive tools.
- Protocol JSON encode/decode no longer crashes on exact rationals whose
  integer parts exceed CPython's int<->str conversion guard (default 4300
  digits); the limit is raised locally, under a lock, for the encode/decode
  and restored afterwards. Found live: a Bridge response carrying a
  26,518-digit exact numerator aborted `json.loads` mid-proof.
- Documented that tight transcendental margins near function roots (e.g.
  `sin` near pi) may need `ProveConfig(taylor_depth=...)` above the default
  10, and that reformulating at a smaller argument (`cos` at pi/2 instead of
  `sin` near pi) is often cheaper than deeper Taylor enclosures.

## 2.2.0 — 2026-08-10

- Validate digest-pinned Bridge programs through content-addressed stack
  profiles derived from the built binary and resolved Core dependency.
- Carry exact Core and Bridge revisions from program provenance into checked
  result provenance instead of reconstructing them from SDK constants.

## 2.1.0 — 2026-08-10

- Reuse one managed Bridge session across module-level `prove` calls; expose
  `close_default_prove_client()` for applications that need explicit cleanup.
- Make replay export prepare-only by default. Independent kernel rebuilding is
  now explicit through `verify=True` or `leancert verify`.
- Separate managed-Bridge integration tests from the fast default suite, add a
  high-signal static gate, and correct public capability and NN-bound claims.
- Point package metadata and the README at the published documentation site.

## 2.0.3 — 2026-08-08

- Adopted Lean Runtime 2.0.6's line-oriented interactive transport while
  retaining LeanCert's strict finite-JSON encoding and Bridge envelope checks.
- Preserved failed interactive execution provenance and compiler diagnostics in
  Bridge transport errors, and retired malformed sessions before reuse.
- Pinned distribution CI to Runtime 2.0.6 and added release tag/package-version
  verification before building publication artifacts.

## 2.0.2 — 2026-08-07

- Preserved the Lean toolchain identity carried by ready-to-run Bridge programs
  when Contract 3.0 correctly omits Bridge-authored dependency provenance, so
  successful results can be exported for independent kernel replay.
- Required `lean-runtime>=2.0.3,<3.0.0`, whose verified environment importer
  accepts safe internal package symlinks while continuing to reject links that
  escape their extracted layer.

No `2.0.1` Python distribution was published. The corresponding repository tag
contains documentation only and retains `2.0.0` package metadata.

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
