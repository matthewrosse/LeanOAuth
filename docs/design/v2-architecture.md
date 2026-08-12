# LeanOAuth v2 — Architecture Proposal

**Status:** Proposed, awaiting approval. Nothing is implemented.
**Date:** 2026-08-12
**Supersedes:** LeanOAuth 1.x in its entirety. This is a redesign, not a port.

Vocabulary follows `CONTEXT.md`. Decisions already recorded as ADRs are cited rather than re-argued.

---

## 1. Overall architecture

Three layers, each with one job, stacked so that the layer below never knows the layer above exists.

```
LeanOAuth.AspNetCore     sign-in handler — an adapter, not the centre
        │
LeanOAuth.Http           HttpRequestMessage signing, DelegatingHandler, the three-legged flow
        │
LeanOAuth.Core           credentials, normalization, signature base string, signing — no HTTP
```

The load-bearing property: **`Core` is synchronous, deterministic given its injected clock and nonce source, and reachable from a test with no HTTP at all.** Everything that touches a network lives above it.

This inverts v1, where the protocol flow lived inside an ASP.NET Core `RemoteAuthenticationHandler` and the only seam beneath it was a parameter-list factory — so nothing could exercise the flow without a full test host. See ADR-0003.

**Rejected:** ASP.NET Core as the design centre with headless usage underneath. The first real consumer is a headless client; letting framework constraints leak downward would penalise it, and would rebuild v1's untestability.

---

## 2. Package structure

| Package | Depends on | Contents |
|---|---|---|
| `LeanOAuth.Core` | nothing | Credentials, `OAuthSigner`, encoding, normalization, nonce, exceptions |
| `LeanOAuth.Http` | `Core` | `OAuthFlow`, `OAuthSigningHandler`, `HttpRequestMessage` signing |
| `LeanOAuth.AspNetCore` | `Http` | Authentication handler, options, events, DI extensions |

Three packages, not four. v1's separate `LeanOAuth.AspNetCore.DependencyInjection` is **merged into `LeanOAuth.AspNetCore`** — nobody references an ASP.NET Core authentication handler without wanting to register it, and the split doubled packaging and versioning work for no gain.

`Core` referencing `System.Net.Http` for `HttpMethod` is deliberate. It is in the BCL on both target frameworks, and inventing a parallel method type to preserve notional purity would be purity for its own sake.

**Rejected:** `LeanOAuth.Client` as the middle package name. `Http` says what the layer is about.

---

## 3. Credential model

The centre of the design, and the biggest single "hard to use incorrectly" win. **There is no signature-method setting.** The credential type carries the method. See ADR-0002.

```csharp
namespace LeanOAuth.Core;

/// <summary>Client credentials. Called a "consumer key/secret" in most provider documentation.</summary>
public abstract record ClientCredentials
{
    private protected ClientCredentials(string consumerKey);
    public string ConsumerKey { get; }

    internal abstract string SignatureMethod { get; }
    internal abstract string Sign(string signatureBaseString, string? tokenSecret);
}

public sealed record HmacSha1ClientCredentials(string ConsumerKey, string ConsumerSecret)
    : ClientCredentials;

public sealed record RsaSha1ClientCredentials(string ConsumerKey, RSA PrivateKey)
    : ClientCredentials;

public sealed record PlainTextClientCredentials(string ConsumerKey, string ConsumerSecret)
    : ClientCredentials;
```

The hierarchy is closed — a `private protected` constructor means no fourth case can be added from outside.

Token pairs share a base so the signer takes one parameter rather than an overload per leg:

```csharp
/// <summary>An oauth_token / oauth_token_secret pair.</summary>
public abstract record OAuthToken(string Token, string TokenSecret);

/// <summary>Temporary credentials. Called a "request token" in most provider documentation.</summary>
public sealed record TemporaryCredentials(string Token, string TokenSecret, bool CallbackConfirmed)
    : OAuthToken(Token, TokenSecret);

/// <summary>Token credentials. Called an "access token" in most provider documentation.</summary>
public sealed record TokenCredentials(string Token, string TokenSecret)
    : OAuthToken(Token, TokenSecret);
```

**Why this matters concretely:** v1's `IOAuthOptions` requires a non-empty `ConsumerSecret` and `Validate()` throws without one. An RSA-SHA1 provider has no consumer secret — the private key *is* the credential. v1 cannot express such a provider at all. Under this model it is a constructor call, and pointing HMAC-SHA1 at an RSA provider becomes unrepresentable rather than a `401` you debug for a day.

**Rejected:** one flat credential type with nullable secret and nullable key, which makes every invalid combination representable. Rejected: a flat type with a validating factory, which moves the failure to runtime instead of removing it.

**Accepted cost:** custom signature methods are second-class. A provider demanding a non-RFC method such as HMAC-SHA256 reopens ADR-0002.

**RSA key input** is an `RSA` instance only — no PEM strings, no file paths. `RSA.ImportFromPem(File.ReadAllText(path))` is one line for the caller, and it keeps file IO and key parsing out of a protocol library. It also puts disposal where it belongs: the library never owns a key it did not create.

---

## 4. Signing — the core public API

**One method. No knowledge of which leg of the flow it is signing.**

```csharp
public sealed class OAuthSigner
{
    public OAuthSigner(OAuthSignerOptions? options = null);

    public OAuthSignature Sign(
        HttpMethod method,
        Uri uri,
        ClientCredentials client,
        OAuthToken? token = null,
        IReadOnlyList<OAuthParameter>? additionalParameters = null,
        string? realm = null);
}

public sealed record OAuthSignature(
    string HeaderValue,
    string SignatureBaseString,
    IReadOnlyList<OAuthParameter> SignedParameters);

public sealed class OAuthSignerOptions
{
    public INonceGenerator NonceGenerator { get; init; } = LeanOAuth.Core.NonceGenerator.Default;
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;
    public Func<IReadOnlyList<OAuthParameter>, IReadOnlyList<OAuthParameter>>? ParameterHook { get; init; }
}

public readonly record struct OAuthParameter(string Key, string Value);
```

The three legs of the flow differ only in which protocol parameters they carry — `oauth_callback`, `oauth_verifier`, `oauth_token`. Those arrive as `additionalParameters` from the flow layer. The signer stays one method with one body.

**This is the direct fix for v1's worst structural defect.** `IOAuthAuthorizationParametersFactory` has six methods delegating to one private body, three of them pure overload sugar — and the five-argument `CreateProtectedResourceRequestParameters` silently drops its `parameters` argument because it resolves to the four-argument private overload. Collapsing to one method makes that entire bug class unrepresentable.

**Returning `OAuthSignature` rather than a bare string** exposes the signature base string. It contains no secret material — secrets live in the signing *key*, never the base string — and it is the single most useful thing to look at when a provider returns `401`. It also lets golden tests assert on the base string directly rather than inferring it from the signature.

**Nonce and clock are injected, not parameters.** A pure function taking nonce and timestamp tests more prettily, but it invites callers to pass `Guid.NewGuid()` or a counter, and a predictable nonce is a real protocol failure. Defaults are `RandomNumberGenerator` and `TimeProvider.System`; tests substitute.

---

## 5. Parameter normalization and encoding

RFC 5849 §3.4.1.3.1 defines three parameter sources. **v1 includes only the first.** See ADR-0004.

| Source | Who collects it |
|---|---|
| OAuth protocol parameters | `OAuthSigner` |
| Query component of the request URI | `OAuthSigner`, parsed from the `Uri` it already normalizes |
| `application/x-www-form-urlencoded` body | `LeanOAuth.Http`, passed down as `additionalParameters` |

A non-form body — JSON, multipart, binary — does not participate, per the RFC.

Query parameters are extracted from the URI the caller already passes, so they cannot be omitted. Making it a separate argument is precisely how v1's parameter-dropping bug happened.

### URI normalization (§3.4.1.2)

| Case | Behaviour |
|---|---|
| Scheme, host | Lowercased |
| Default port (80/http, 443/https) | Removed |
| Explicit non-default port | Retained |
| Fragment | Stripped silently — never transmitted, so this matches reality |
| Query | Removed from the base URI, parsed into signed parameters |
| Userinfo (`https://u:p@host/`) | **Throws** |
| Non-HTTP scheme | **Throws** |

The governing principle: **silently normalize what the wire does anyway; throw on anything where silence would hide a security-relevant difference.** Userinfo is credential material that would be dropped from the signature while remaining in the request — a leak that looks like it worked.

### Percent-encoding

RFC 5849 §3.6 requires RFC 3986: unreserved characters are `ALPHA / DIGIT / "-" / "." / "_" / "~"`, everything else is `%XX` with uppercase hex, over UTF-8 bytes.

.NET's `Uri.EscapeDataString` implements RFC 2396 and leaves `!` `*` `'` `(` `)` unescaped. **One encoder, used everywhere.** v1 has two: `OAuthTools.UrlEncodeRelaxed` in the HMAC path and a raw `Uri.EscapeDataString` in the PLAINTEXT path, so a secret containing those five characters signs differently under the two methods.

```csharp
public static class OAuthEncoding
{
    public static string PercentEncode(string value);
}
```

Public because the parameter hook may need it.

### Parameter sorting (§3.4.1.3.2)

Encode first, then sort by encoded key, then by encoded value. Duplicate keys are legal and both survive. **Encode-before-sort is not interchangeable with sort-before-encode** — they produce different orderings for keys that differ only in characters whose encoded forms sort differently.

### Nonce

16 random bytes rendered as 32 lowercase hex characters. 128 bits of entropy, alphanumeric only, so percent-encoding is a no-op and the base string stays readable while debugging.

v1 uses 64 random bytes Base64-encoded — 88 characters containing `+`, `/`, and `=`, all of which then need encoding, and some providers mishandle encoded nonces.

---

## 6. Authentication flow

```csharp
namespace LeanOAuth.Http;

public sealed record OAuthProviderEndpoints(
    Uri TemporaryCredentialRequest,
    Uri ResourceOwnerAuthorization,
    Uri TokenRequest);

public abstract record OAuthCallback
{
    public static OAuthCallback OutOfBand { get; }
    public static OAuthCallback For(Uri uri);
}

public sealed class OAuthFlow
{
    public OAuthFlow(
        HttpClient httpClient,
        OAuthProviderEndpoints endpoints,
        ClientCredentials client,
        OAuthSigner? signer = null,
        OAuthFlowOptions? options = null);

    public Task<TemporaryCredentials> RequestTemporaryCredentialsAsync(
        OAuthCallback callback, CancellationToken ct = default);

    public Uri BuildAuthorizationUri(TemporaryCredentials temporary);

    public Task<TokenCredentials> ExchangeAsync(
        TemporaryCredentials temporary, string verifier, CancellationToken ct = default);
}

public sealed class OAuthFlowOptions
{
    /// <summary>
    /// Permits a provider that does not return oauth_callback_confirmed=true.
    /// This downgrades to the OAuth 1.0 flow, which has a known session-fixation
    /// vulnerability. Leave false unless a specific provider requires it.
    /// </summary>
    public bool AllowUnconfirmedCallback { get; init; }
}
```

**Multi-tenancy splits cleanly.** Endpoints and client credentials are per *provider instance* and go in the constructor. Temporary credentials, verifier, and token credentials are per *resource owner* and go per call. One `OAuthFlow` serves every user of one provider; a second provider instance means a second flow.

`OAuthCallback` is a closed type rather than a `string?`. RFC 5849 §2.1 requires the literal `"oob"` when there is no callback — a nullable string invites both a typo and a forgotten parameter.

**`oauth_callback_confirmed` is required by default.** That parameter is the "a" in OAuth 1.0a: it is the marker added in 2009 to fix the session-fixation attack. Accepting its absence silently runs the vulnerable OAuth 1.0 flow. The opt-out exists and is named to be alarming.

**Response parsing does not gate on `Content-Type`.** The RFC says these responses are form-encoded; real providers send `text/plain` and worse. Parse leniently; validate the parameters that matter.

**No `IOptions` in `Core` or `Http`** — plain records. `AspNetCore` bridges to `IOptions` where the framework expects it.

**Token storage is the application's job.** No `ICredentialStore`. The library takes credentials in and hands credentials out. A library that appears to handle secret storage but does not encrypt is worse than one that never claimed to — encryption at rest is platform- and policy-specific.

---

## 7. HTTP integration

```csharp
public sealed class OAuthSigningHandler : DelegatingHandler
{
    public OAuthSigningHandler(
        ClientCredentials client,
        TokenCredentials? defaultToken = null,
        OAuthSigner? signer = null);

    public static HttpRequestOptionsKey<TokenCredentials> TokenCredentialsKey { get; }
}

public static class HttpRequestMessageExtensions
{
    public static HttpRequestMessage WithOAuthToken(this HttpRequestMessage request, TokenCredentials token);

    public static Task SignAsync(this HttpRequestMessage request,
        ClientCredentials client, TokenCredentials? token,
        OAuthSigner signer, CancellationToken ct = default);
}
```

Per-request credential resolution via `HttpRequestOptions` is what makes multi-tenancy work: a server with one token per user cannot mint an `HttpClient` per user without leaking handlers. A default credential on the handler covers the single-tenant case. Retrofitting per-request resolution later would be a breaking change; supporting both now costs one options key.

Manual signing stays public — some callers need to sign a request they will not send through this pipeline.

### Pipeline hazards, handled explicitly

These are the places a signing library meets real .NET HTTP and loses.

| Hazard | Behaviour |
|---|---|
| **Form-encoded body** | Buffered via `LoadIntoBufferAsync()` before parsing, so the content stays sendable. This is why signing is async at the HTTP layer despite a synchronous core. |
| **Automatic redirects** | A redirect re-sends to a different URI without re-signing; the signature is bound to the URI, so it always fails. The handler **throws** if it observes a redirect status it did not expect, and the docs state `AllowAutoRedirect = false`. |
| **Retries** | Each attempt needs a fresh nonce and timestamp. `OAuthSigningHandler` must sit **inside** any retry handler. Documented with a Polly example. |
| **Existing `Authorization` header** | **Throws.** Silently clobbering a caller's header is worse than failing. |
| **Non-form bodies** | Not read, not buffered, not signed. Streaming stays streaming. |

---

## 8. ASP.NET Core adapter

Deliberately sequenced second. The core is built and validated first; the handler is adapted onto whatever shape that produces, rather than dictating it.

Scope: `AddOAuth10A(scheme, configure)`, an options type deriving from `RemoteAuthenticationOptions`, events, and the ticket-creation context. DI extensions live here rather than in their own package.

It gets no privileged access — anything it needs is part of `Http`'s public surface. That constraint is what keeps the seam honest.

---

## 9. Security model

Three columns, kept strictly apart. Claiming more than the middle column is how libraries mislead.

**OAuth protocol requirements — the library implements these:**
- Cryptographically secure nonce, 128 bits, per request.
- Timestamp in seconds since the Unix epoch, UTC.
- `oauth_callback_confirmed` enforced by default.
- Correct signature base string construction, which is the protocol's entire integrity guarantee.

**Library responsibilities — the library guarantees these:**
- **No secret material in any exception message.** Not truncated, not hashed, not "for debugging".
- **No logging in `Core` or `Http`.** No `ILogger`, no logging dependency. A signing library handles consumer secrets, private keys, token secrets, and base strings; every log statement is a leak waiting for a log aggregator.
- Userinfo URIs rejected rather than silently stripped.
- `PLAINTEXT` available because the RFC defines it, documented as unsafe without TLS.
- No key parsing, no key storage, no key disposal — the library never owns key material.

**Application responsibilities — the library does not and cannot cover these:**
- Storing token credentials, including encryption at rest.
- TLS enforcement. `HttpClient` configuration is the caller's.
- Callback URL validation and open-redirect prevention.
- SSRF: the caller supplies the endpoints; the library will sign a request to whatever it is given.
- Credential rotation and revocation.
- Replay protection on the *serving* side — out of scope entirely per ADR-0001.

**Out of scope, stated so it is not assumed:** signature *verification*. No nonce store, no replay window, no clock-skew policy, no constant-time comparison anywhere in the library. This library signs; it does not verify. See ADR-0001.

---

## 10. Error model

```csharp
public abstract class OAuthException : Exception;

/// <summary>The provider's response was malformed or missing a required parameter.</summary>
public sealed class OAuthProtocolException : OAuthException;

/// <summary>An OAuth endpoint returned a non-success status.</summary>
public sealed class OAuthRequestFailedException : OAuthException
{
    public HttpStatusCode StatusCode { get; }
    public string? ResponseExcerpt { get; }   // provider-controlled, truncated
}
```

Programmer error uses the BCL types — `ArgumentException`, `ArgumentNullException`. No invented configuration exception.

**No `Result<T>`.** A result type in a library forces every consumer to adopt it or unwrap at the boundary — an ergonomic tax .NET consumers do not expect. Exceptions throughout, typed so they can be caught precisely.

`ResponseExcerpt` carries the provider's own output, truncated and documented as provider-controlled. Without it a `401` is undebuggable. The absolute rule is one-directional: nothing the *library* knows — no secret, no key, no signature — ever reaches an exception message.

**Fixed from v1:** `OAuthResponseHelpers` throws `ArgumentNullException` when a provider response is missing a field, turning a remote fault into what reads as a caller bug.

---

## 11. Extensibility

Two extension points. Both have a demonstrated need; nothing else is extensible.

**`INonceGenerator`** — substituted in tests, and occasionally by callers with a provider-specific format requirement.

**The parameter hook** — `Func<IReadOnlyList<OAuthParameter>, IReadOnlyList<OAuthParameter>>`, running **before** signing.

```csharp
new OAuthSignerOptions
{
    ParameterHook = p => p.Where(x => x.Key != "oauth_version").ToList()
}
```

Running before signing is the only version that handles the deviations that actually occur — dropping `oauth_version` for providers that reject it, or adding a body-hash parameter. Running after signing could only rewrite a header already committed. It is a sharp tool and its XML doc says so.

**Rejected:** per-provider quirk profiles (`.ForJira()`, `.ForTwitter()`) — a maintenance treadmill for a one-maintainer library that rots the moment a provider changes. Rejected: `ICredentialStore`, `IHttpAbstraction`, pluggable flow implementations, custom signature method registration — speculative extension points with no demonstrated use case.

`TimeProvider` is BCL, not an invented abstraction.

---

## 12. Thread safety

**Guarantee: all public types are safe for concurrent use.** An `RSA` instance you supply must not be mutated after construction.

`OAuthSigner` is stateless. Credentials, tokens, and parameters are immutable records. `HttpClient` and `TimeProvider` are thread-safe. `RandomNumberGenerator` static methods are thread-safe.

**The one real hazard is RSA.** .NET's `RSA` implementations are not contractually thread-safe for concurrent signing, and a multi-tenant server shares one instance across threads. **`RsaSha1ClientCredentials` locks around its signing call, on the instance rather than a static** — so two tenants with different keys never contend, and only concurrent signing with the same key serializes.

A concurrency test covers this. Q27's benchmark measures what the ceiling actually costs; if it binds, pooling is the next move, not a wider lock.

---

## 13. Performance

Correctness first. Optimisation follows measurement, and no allocation budget is set before a number exists.

**Hot path** — executed once per signed request:

1. Percent-encoding — `SearchValues<char>` for the unreserved set, `stackalloc` for short values, `string.Create` for the result.
2. Parameter collection and sort — pooled buffers, a struct comparer, no LINQ.
3. Signature base string — single `string.Create` pass over known lengths rather than `StringBuilder` growth.
4. HMAC or RSA — `HMACSHA1.HashData` static, no instance allocation.

`OAuthParameter` is a `readonly record struct` to keep parameter lists off the heap.

`LeanOAuth.Benchmarks`, not in CI, covering exactly two things: end-to-end signing of a representative request, and the percent-encoder in isolation. Its first job is to answer the RSA-locking question.

---

## 14. Testing strategy

Four layers in CI. **The test suite's purpose is detecting subtle signing and encoding bugs**, which is a different bar from covering lines.

1. **Golden vectors** — RFC 5849 §1.2's worked example, carried over verbatim from v1's tests. Asserted against the signature base string as well as the signature, since `OAuthSignature` exposes it.
2. **Signature base string edge cases** — the layer that matters most, because this is where every real bug lives:
   - a URI that already has a query string
   - duplicate keys across protocol, query, and body sources
   - empty values, and keys with empty values
   - Unicode in keys and values
   - pre-percent-encoded input (double-encoding check)
   - default vs explicit ports; uppercase scheme and host
   - fragment stripping; userinfo rejection
   - the five characters `! * ' ( )` where RFC 2396 and RFC 3986 diverge, across **all three** signature methods
3. **Flow tests** — stub `HttpMessageHandler`, no network. Both `oauth_callback_confirmed` paths. Recorded response fixtures, checked in as generic form-encoded text, for the parsing paths.
4. **Property-based tests on the percent-encoder** — invariant: output contains only unreserved characters and uppercase `%XX` triplets, and round-trips. One test-only dependency (`CsCheck`). Worth it: a pure function with a crisp invariant, and the highest-risk code in the library.

Plus a concurrency test for the RSA path.

**No live provider tests.** This library is provider-neutral, so it has no provider to test against. **Stated plainly in the README: nothing in this repository proves the library works against a real provider.** That proof belongs to whatever consumes it. This is an honest consequence of provider-neutrality, not a hole to paper over.

---

## 15. Target frameworks

**`net10.0` and `net8.0`.**

Both have `TimeProvider`, `HMACSHA1.HashData`, `RSA.ImportFromPem`, `SearchValues`, and `CryptographicOperations`. Zero shims, zero `#if`, and multitargeting across them costs essentially nothing.

**`netstandard2.0` deliberately deferred.** It would reach .NET Framework 4.6.2+, where a lot of legacy integration code genuinely lives — a real argument, since this library's users skew legacy. But the cost is not free: no `TimeProvider`, no `ImportFromPem`, no static `HMACSHA1.HashData`, no `SearchValues`. That means conditional compilation in the crypto and encoding paths — the exact code where `#if` is most dangerous. Add the leg when a .NET Framework user asks, and pay that cost knowingly.

`IsAotCompatible` on `Core` and `Http` — free, since neither uses reflection, serialization, or dynamic code. Not on `AspNetCore`, whose framework machinery is not cleanly trimmable and chasing it would distort the design.

---

## 16. NuGet packaging

Same package IDs, major bump to **2.0.0**. Package identity carries whatever discovery exists, and 1.x has little adoption to protect. New IDs earn their keep only when both versions must coexist in one app, which nobody wants for a signing library.

Carried over from v1 and kept: `DotNet.ReproducibleBuilds`, deterministic builds, `GenerateDocumentationFile`, `EnablePackageValidation`, MIT license expression, per-package README.

Added: **`Microsoft.CodeAnalysis.PublicApiAnalyzers`**. The public surface lives in checked-in text files, so any accidental API change fails the build and appears as a reviewable diff. This is the cheap half of long-term maintainability, and it matters most right after a 2.0 while the surface is still setting.

---

## 17. Documentation

Root `README` covering all three packages, plus XML docs on every public member. No docs site — for a library this size it is maintenance that gets abandoned, and IntelliSense is where people actually read.

**Every public type names its OAuth 1.0 Core synonym in its XML doc.** The type names follow RFC 5849 because a credential is a key/secret *pair* and the RFC's names say so; but provider documentation universally uses the older vocabulary, so a reader arriving from provider docs must be able to find the right type.

```csharp
/// <summary>
/// Temporary credentials, called a "request token" in most provider documentation.
/// </summary>
```

Samples: a console client running the out-of-band flow, taking endpoints and credentials from arguments so it runs against any provider without naming one; and an ASP.NET Core sign-in app.

---

## 18. Migration

**Branch `v2`. Rewrite `src/` and `test/` in place. `main` stays at 1.x until release.**

Keeping both trees in one repository would make `AGENTS.md`, `CONTEXT.md`, and the ADRs describe two different libraries, and every agent working here would have to disambiguate on every task — the exact cost those documents exist to remove.

Carried over: the RFC 5849 §1.2 test vectors, verbatim. Everything else in `test/` is replaced. `LeanOAuth.AspNetCore.Examples` is replaced by the two samples above.

Long-lived branch means v1 fixes need deliberate porting. Given v1's release cadence, that is a small cost.

### Breaking changes from v1

Every one of these is intentional.

| Change | Consequence |
|---|---|
| **Query-string and form-body parameters now signed** | *Silent* behavioural change. A request carrying a query string produces a different signature. v2's is correct; v1's was wrong. ADR-0004. |
| **Signature method follows the credential type** | `IOAuthOptions` and injected `OAuthSignatureCalculator` are gone. RSA-SHA1 becomes expressible for the first time. ADR-0002. |
| **`IOAuthAuthorizationParametersFactory` deleted** | Six methods collapse to one `OAuthSigner.Sign`. Takes the silent parameter-dropping bug with it. |
| **RFC 5849 vocabulary** | `UnauthorizedRequestTokenResponse` → `TemporaryCredentials`; `AccessTokenResponse` → `TokenCredentials`. |
| **`OAuthTools` → `OAuthEncoding`** | Renderers move behind the signer; only `PercentEncode` stays public. |
| **`OAuthRequestHelpers` deleted** | Three static pass-throughs the `Http` layer absorbs. |
| **`OAuthConstants.Responses` deleted** | Duplicated `ParameterNames` with identical values. |
| **PLAINTEXT encoding fixed** | Was RFC 2396 via `Uri.EscapeDataString`; now RFC 3986 like the other methods. Signatures change for secrets containing `! * ' ( )`. |
| **Nonce format changed** | 88-character Base64 → 32-character hex. |
| **`Realm` and `ScopeParameterName` no longer required** | v1's `Validate()` throws without them; both are optional in the spec. |
| **Target frameworks** | `net8.0` → `net8.0` + `net10.0`. |

---

## 19. Open items

Deliberately unresolved, listed so they are not mistaken for oversights.

- **RSA locking cost** — measured by the benchmark before considering pooling.
- **`netstandard2.0`** — added on demand, not speculatively.
- **HMAC-SHA256** — out of scope; reopens ADR-0002 if a provider forces it.
- **OAuth Body Hash extension** — reachable today through the parameter hook. Promote to first-class only on demand.

---

## 20. Sequencing

1. `LeanOAuth.Core` — credentials, encoding, normalization, signer. Golden vectors and edge cases green.
2. `LeanOAuth.Http` — flow, signing handler, pipeline hazards.
3. Benchmarks — answer the RSA-locking question.
4. `LeanOAuth.AspNetCore` — adapted onto the shape the first two produced.
5. Samples, README, public API baselines.

Steps 1 and 2 are the library. Step 4 is a consumer of it, and building it last is what keeps ADR-0003 true.
