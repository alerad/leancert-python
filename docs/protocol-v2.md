# LeanCert bridge contract 2.x

The Python SDK and `leancert-bridge` negotiate a typed, capability-driven
contract before any checked operation is sent. The wire format is a custom
newline-delimited JSON protocol named `leancert-line-json`; it is not JSON-RPC
2.0.

## Framing and errors

Each request contains `id`, `method`, and `params`. Each response repeats the
`id` and contains exactly one of `result` or `error`. Contract 2.0 errors are
objects with a stable `code`, human-readable `message`, and optional `data`.
Malformed envelopes and remote infrastructure failures raise exceptions.
Mathematical non-success is returned as a typed operation outcome.

## Negotiation

The `get_info` handshake identifies:

- protocol, bridge, Lean, and LeanCert versions;
- NDJSON framing and the protocol name;
- source revision, source digest, environment digest, and build profile;
- supported operations and expression nodes;
- certificate schemas and verification routes;
- each checked operation's request schema, result schema, outcomes, backends,
  certificate schemas, and verification routes.

The client refuses unadvertised operations and rejects responses whose backend,
certificate schema, or verification route was not negotiated. Contract 1.0 and
1.1 remain explicit compatibility modes while previously published bundled
bridge binaries are phased out. Unknown major versions are rejected.

## Checked bound outcomes

`check_bound` returns one of `verified`, `inconclusive`, `unsupported`, or
`domain_obstruction`. Only `verified` may carry a certificate. The SDK also
checks that the typed response agrees with retained legacy enclosure fields,
uses exact rationals with positive denominators, and matches the request
direction.

This validation does not prove the bound a second time. It ensures Python does
not misrepresent the checked result, authority, or provenance reported by the
bridge.

Contract 2.1 adds the resolved Lean toolchain and exact LeanCert source
revision, together with replayable `bound-check/2` payloads. Contract 2.2 adds
the typed `verify_adaptive` capability. Its successful outcomes retain the
checked rational optimizer, corresponding correctness theorem, exact request,
configuration, and candidate enclosure under `adaptive-bound-check/1`.

Contract 2.3 adds `check_unique_system_root` and replayable
`krawczyk-check/1` certificates. Candidate generation and externally supplied
centers or preconditioners are untrusted. The SDK accepts `verified` only when
the bridge returns the advertised `LeanCert.Engine.krawczykCheck` checker,
`LeanCert.Validity.verify_unique_system_root` verifier, compiled-checker route,
and a fixed payload matching the requested system and exact rational box.

Contract 2.4 adds `check_eventual_bound` and replayable
`eventual-bound-check/1` certificates for nonnegative rational multiples of
reciprocal powers. Cutoff search is untrusted. The SDK validates the exact
coefficient, bound, exponent, and retained cutoff against the request and
accepts success only from `checkReciprocalPowerUpper` paired with
`verify_reciprocal_power_upper`.

Contract 2.5 adds `check_scalar_root` and `scalar-root-check/1` certificates
for the `exists`, `unique`, and `excluded` claim kinds. The SDK requires the
claim, expression, interval, Taylor depth, checker, and verifier in the
certificate to match the negotiated request. A rejected interval carries no
certificate and is never upgraded to a refutation.

Contract 2.6 adds `check_integral` and `integral-check/1` certificates for
exact rational-polynomial equalities and fixed-partition lower or upper bounds.
Partition discovery is untrusted; exact equality never falls back to a
numerical enclosure.

The certificate families are intentionally distinct: adaptive evidence may
close checked subdivision leaves, while `bound-check/2` and
`krawczyk-check/1`, `eventual-bound-check/1`, `scalar-root-check/1`, and
`integral-check/1` support standalone project
export.

Golden fixtures live under
`leancert/tests/fixtures/bridge-contract-{1.1,2.0,2.1}`. Contract fixtures are
mirrored by the bridge repository's executable contract tests.
