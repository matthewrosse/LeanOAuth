# ADR-0002: The signature method is determined by the credential type

**Status:** Accepted (2026-08-12)

## Context

RFC 5849 defines three signature methods, and the signing key is built differently for each. HMAC-SHA1 concatenates the percent-encoded client secret and token secret. PLAINTEXT does the same and sends it as the signature. RSA-SHA1 signs with an RSA private key and ignores both secrets entirely.

LeanOAuth v1 modelled these as independent choices: `IOAuthOptions` requires a non-empty `ConsumerSecret`, and the signature method is a separately injected `OAuthSignatureCalculator`. Jira Server cannot be expressed in that model at all — it signs RSA-SHA1 with a private key and has no consumer secret. Worse, the model permits combinations that cannot work, such as HMAC-SHA1 pointed at a provider expecting RSA-SHA1, and the resulting failure is a bare `401` with no diagnostic.

## Decision

There is no signature-method setting. The client credential type carries the method:

- `HmacClientCredentials` — consumer key and shared secret. Signs HMAC-SHA1.
- `RsaClientCredentials` — consumer key and an `RSA` instance. Signs RSA-SHA1.
- `PlainTextClientCredentials` — consumer key and shared secret. Signs PLAINTEXT.

The hierarchy is closed: an abstract base with a private constructor and sealed subtypes, so no fourth case can be introduced from outside.

## Consequences

- Mismatched method and key material become unrepresentable rather than diagnosed at runtime.
- Configuration shrinks: a Jira client is constructed by handing over a consumer key and an `RSA`, and the method follows.
- Adding a signature method means adding a credential type and touching the closed hierarchy. Custom signature methods are deliberately second-class; a provider demanding a non-RFC method such as HMAC-SHA256 forces this ADR to be reopened.
- Serialization of credentials is per-type rather than one flat shape.
