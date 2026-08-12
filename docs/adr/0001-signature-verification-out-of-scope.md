# ADR-0001: Server-side signature verification is out of scope

**Status:** Accepted (2026-08-12)

## Context

A complete OAuth 1.0a implementation has two halves: a client that signs outbound requests, and a provider that verifies inbound ones. LeanOAuth v1 implements only the client half. The v2 redesign raised the question of adding the provider half.

Verification is a different product with a different threat model. It requires a persistent nonce store scoped to the client and timestamp window, a replay window and clock-skew policy, constant-time signature comparison, and a decision about what to do with credentials that fail to resolve. None of these concerns exist on the signing side.

The demand is also close to zero: OAuth 1.0a is a legacy protocol, and nobody is standing up new OAuth 1.0a providers in 2026. The people who need this library need it to talk *to* a legacy provider.

## Decision

LeanOAuth signs. It does not verify.

## Consequences

- Credential types are one-directional. They carry what is needed to sign, not what is needed to look up and check.
- No nonce store, no replay window, no clock-skew policy, no constant-time comparison anywhere in the library.
- A future verification package would not be a small addition. Reopening this means designing a second library, not extending this one.
- The library cannot be used to build an OAuth 1.0a provider. That is stated in the README rather than discovered.
