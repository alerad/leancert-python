# Python protocol model v2

PR2 replaces ad-hoc dictionary inspection with an executable model of the
LeanCert bridge contract. The current interoperable wire version is Bridge
Contract `1.1.0`; “v2” here names the Python SDK architecture, not JSON-RPC or
a claim that the bridge wire major version is already `2`.

## Framing

The bridge consumes one JSON object per input line and emits one JSON object per
output line. A request contains `id`, `method`, and `params`. A response repeats
the `id` and contains exactly one of `result` or `error`. This protocol is not
JSON-RPC 2.0.

Transport failures and malformed envelopes raise `ProtocolViolation` or
`BridgeError`. Mathematical non-success remains data returned by an operation.

## Negotiation

`BridgeHandshake` validates semantic versions and capability identity before an
operation is sent. Contract `1.1.0` requires:

- bridge, Lean, and LeanCert versions;
- supported operations and expression nodes;
- certificate schema identities;
- verification routes;
- per-operation outcome and backend capabilities.

Contract `1.0.0` remains an explicit compatibility mode for the currently
bundled bridge pin. It does not acquire capabilities that it did not advertise.
The SDK rejects unknown major versions.

## Checked bound outcomes

For `check_bound`, the typed response must agree with its retained 1.x legacy
fields. The client rejects:

- a `verified` Boolean that contradicts `status`;
- typed and legacy enclosures that differ;
- inverted intervals or nonpositive rational denominators;
- a response direction different from the request;
- certificates on non-verified outcomes;
- verified outcomes without a certificate;
- malformed checker, verifier, schema, or verification-route identities.

This validation does not independently prove the bound. It prevents the Python
SDK from misrepresenting what the bridge said it checked.

## Next server increment

Before changing the Python package pin, `leancert-bridge` should tag the typed
contract commit and add immutable build/source/environment digests. Additional
operations should advertise a typed result schema only after they return a
checked certificate descriptor and the complete retained evidence required by
that schema.

Golden fixtures live in `leancert/tests/fixtures/bridge-contract-1.1` and are
intended to be copied into the bridge repository's contract test suite.
