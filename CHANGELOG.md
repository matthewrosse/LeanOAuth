# Changelog

## 2.0.0

LeanOAuth 2.0 is a rebuild of the library as three layers — `LeanOAuth.Core`,
`LeanOAuth.Http`, `LeanOAuth.AspNetCore` — with the protocol core at the bottom and every
framework as an adapter above it. Every breaking change below is intentional.

### Read this first: the most dangerous change is silent

**v2 signs query-string and form-body parameters; v1 did not.** RFC 5849 §3.4.1.3.1 requires the
signature base string to include the OAuth protocol parameters, the query component of the
request URI, and the entity body when it is `application/x-www-form-urlencoded`. v1 included only
the first, so any request carrying a query string was signed incorrectly.

This means: **any request your application sends that carries a query string will now produce a
different signature than it did under v1.** There is no error, no warning, and no compile break.
A request that previously failed against a conformant provider will now succeed — v2's signature
is correct where v1's was wrong. But if you built a workaround around v1's broken behaviour (for
example, moving parameters out of the query string to avoid a mismatched signature, or
special-casing a provider that happened to tolerate v1's incorrect signature), that workaround
will now break, because v2's signature no longer matches what the workaround expected the
provider to see.

There is nothing to configure to opt out of this: it is a correctness fix, not a setting.
Re-verify every request your application signs that carries a query string or a form-encoded body
against a real provider before deploying v2.

### Breaking changes

| Change | Consequence |
|---|---|
| **Query-string and form-body parameters now signed** | Silent behavioural change, above. ADR-0004. |
| **Signature method follows the credential type** | `IOAuthOptions` and the injected `OAuthSignatureCalculator` are gone. The method is now determined by which `ClientCredentials` subtype you construct: `HmacSha1ClientCredentials`, `RsaSha1ClientCredentials`, or `PlainTextClientCredentials`. RSA-SHA1 is expressible for the first time. ADR-0002. |
| **`IOAuthAuthorizationParametersFactory` deleted** | Its six methods collapse to one: `OAuthSigner.Sign`. This also removes the overload resolution that caused the five-argument protected-resource overload to silently drop caller-supplied parameters. |
| **RFC 5849 vocabulary** | `UnauthorizedRequestTokenResponse` → `TemporaryCredentials`; `AccessTokenResponse` → `TokenCredentials`. See [README § Vocabulary](README.md#vocabulary). |
| **`OAuthTools` → `OAuthEncoding`** | Renderers move behind the signer; only `PercentEncode` stays public, as `LeanOAuth.Core.PercentEncoding.PercentEncoder.Encode`. |
| **`OAuthRequestHelpers` deleted** | Its three static pass-throughs are absorbed into `LeanOAuth.Http`. |
| **`OAuthConstants.Responses` deleted** | Duplicated `ParameterNames` with identical values. |
| **PLAINTEXT encoding fixed** | v1 percent-encoded PLAINTEXT signatures with RFC 2396 (`Uri.EscapeDataString`) while HMAC-SHA1 used RFC 3986. v2 uses RFC 3986 everywhere. Signatures now differ for secrets containing `! * ' ( )`. |
| **Nonce format changed** | 88-character Base64 → 32-character lowercase hex. |
| **`Realm` and `ScopeParameterName` no longer required** | v1's options `Validate()` threw without them; both are optional per the RFC and now behave that way. |
| **Target frameworks** | `net8.0` → `net8.0` and `net10.0`. |

### Also new

- RSA-SHA1 client credentials (`RsaSha1ClientCredentials`), taking an `RSA` instance whose
  lifetime the caller owns.
- The signature base string is returned alongside every signature (`OAuthSignature.SignatureBaseString`), so a `401` has something concrete to compare against a provider's documented example.
- `OAuthFlow`: the three-legged flow as plain async methods on a type that takes an `HttpClient`, with no web framework or test host required to exercise it.
- `OAuthSigningHandler`: a `DelegatingHandler` that signs automatically, for the standard `IHttpClientFactory` (`AddHttpMessageHandler`) registration pattern.
- A parameter hook (`OAuthSigningOptions.ParameterHook`) for adjusting the parameter set before signing, for non-conformant providers.

### Not proven by this release

This repository is provider-neutral by decision: no provider-specific code, configuration, or
tests live here. **Nothing in this repository proves interoperability with a real provider** —
only conformance to RFC 5849, established by the test suite. Verify against your actual provider
before depending on this release in production.
