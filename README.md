# LeanOAuth

OAuth 1.0a ([RFC 5849](https://datatracker.ietf.org/doc/html/rfc5849)) for .NET, as three layers:

- **`LeanOAuth.Core`** — credentials, percent-encoding, normalization, and the signer. No HTTP, no framework dependency.
- **`LeanOAuth.Http`** — signs an `HttpRequestMessage`, a `DelegatingHandler` that signs automatically, and the three-legged flow (temporary credentials → authorization → token credentials).
- **`LeanOAuth.AspNetCore`** — an ASP.NET Core authentication handler for "sign in with OAuth 1.0a", built on `LeanOAuth.Http` with no privileged access to its internals.

The protocol core has no knowledge of any particular provider. **This repository is
provider-neutral by decision: no provider-specific code, configuration, or tests live here, and
nothing in it proves interoperability with a real provider.** Conformance to RFC 5849 is
established by the test suite; interoperability with any given provider is the consuming
project's responsibility to verify.

Upgrading from 1.x? See [Release notes](#release-notes) first — the query-string and form-body
signing change is silent and will change signatures your application already produces.

## Table of contents

- [Vocabulary](#vocabulary)
- [Installation](#installation)
- [LeanOAuth.Core](#leanoauthcore)
- [LeanOAuth.Http](#leanoauthhttp)
- [LeanOAuth.AspNetCore](#leanoauthaspnetcore)
- [Samples](#samples)
- [Security responsibilities this library does not carry](#security-responsibilities-this-library-does-not-carry)
- [Release notes](#release-notes)
- [Contributing](#contributing)
- [License](#license)

## Vocabulary

Type names follow RFC 5849, because a credential in this protocol is always a key/secret *pair*
and the RFC's names say so. Most provider documentation uses the older OAuth 1.0 Core vocabulary
instead. Every public type whose name follows RFC 5849 names its OAuth 1.0 Core synonym in its
XML doc, so a reader arriving from provider docs can find the right type. The mapping:

| RFC 5849 | OAuth 1.0 Core |
|---|---|
| Client credentials (`ClientCredentials` and subtypes) | Consumer key / consumer secret |
| Temporary credentials (`TemporaryCredentials`) | Request token |
| Token credentials (`TokenCredentials`) | Access token |

## Installation

```sh
dotnet add package LeanOAuth.Core
dotnet add package LeanOAuth.Http
dotnet add package LeanOAuth.AspNetCore
```

Install `LeanOAuth.Core` alone for a console app, daemon, or MCP server that only needs to sign;
add `LeanOAuth.Http` for the three-legged flow and the `HttpClient` integration; add
`LeanOAuth.AspNetCore` only for browser sign-in.

## LeanOAuth.Core

One call signs a request and returns the `Authorization` header value together with the
signature base string that produced it — so when a provider returns a bare `401`, there is
something concrete to compare against the provider's own documented example.

The signature method is not a setting: it is carried by which `ClientCredentials` subtype you
construct. `HmacSha1ClientCredentials` and `PlainTextClientCredentials` hold a shared secret;
`RsaSha1ClientCredentials` holds an `RSA` private key instead. Pointing the wrong method at a
provider becomes a compile error rather than an undiagnosable `401`.

```csharp
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;

var clientCredentials = new HmacSha1ClientCredentials("consumer-key", "consumer-secret");
var tokenCredentials = new OAuthToken("token", "token-secret");

var signer = new OAuthSigner();
var signature = signer.Sign(
    HttpMethod.Get,
    new Uri("https://example.com/resource?page=2"),
    clientCredentials,
    tokenCredentials
);

Console.WriteLine(signature.AuthorizationHeaderValue);
Console.WriteLine(signature.SignatureBaseString); // compare this against the provider's docs on a 401
```

Query-string parameters on the request URI are collected and signed automatically, per RFC 5849
§3.4.1.3.1 — pass form-body parameters through the `additionalParameters` argument of `Sign` if
you are not using `LeanOAuth.Http` to build the request.

## LeanOAuth.Http

Signs an `HttpRequestMessage` directly, or automatically via a `DelegatingHandler` registered on
an `HttpClient`.

```csharp
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;

var clientCredentials = new HmacSha1ClientCredentials("consumer-key", "consumer-secret");
var tokenCredentials = new OAuthToken("token", "token-secret");

var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
using var httpClient = new HttpClient(
    new OAuthSigningHandler(clientCredentials, tokenCredentials) { InnerHandler = handler }
);

using var response = await httpClient.GetAsync("https://example.com/resource?page=2");
```

Two pipeline hazards `OAuthSigningHandler` cannot see from inside itself:

- **`OAuthSigningHandler` must sit inside any retry handler**, closer to the transport — each
  retry needs a fresh nonce and timestamp, and a signature computed once and replayed across
  retries is bound to a stale nonce on every attempt after the first. With Polly, register this
  handler with `AddHttpMessageHandler` *before* `AddPolicyHandler`, so Polly wraps it rather than
  the other way around.
- **Automatic redirects must be disabled** (`AllowAutoRedirect = false` above). The handler signs
  the request URI; a redirect the runtime follows automatically re-sends to a different URI the
  signature was never bound to, and the provider always rejects it. `OAuthSigningHandler` throws
  if it observes a redirect response, so this fails loudly rather than silently, but disabling
  auto-redirect and handling the redirect explicitly is what you want in practice.

### The three-legged flow

`OAuthFlow` runs RFC 5849 §2 against plain `HttpClient` calls — no browser, no web framework, no
test host — so it is reachable from a console app or a daemon:

```csharp
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;

var clientCredentials = new HmacSha1ClientCredentials("consumer-key", "consumer-secret");
var endpoints = new OAuthProviderEndpoints(
    new Uri("https://example.com/oauth/request_token"),
    new Uri("https://example.com/oauth/authorize"),
    new Uri("https://example.com/oauth/access_token")
);

using var httpClient = new HttpClient();
var flow = new OAuthFlow(httpClient, endpoints, clientCredentials);

var temporaryCredentials = await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand);
var authorizationUri = flow.BuildAuthorizationUri(temporaryCredentials);

// Send the resource owner to authorizationUri; they authorize and are given a verifier.
var verifier = /* obtained out-of-band, or from the callback URI's "oauth_verifier" query parameter */ "";

var tokenCredentials = await flow.ExchangeAsync(temporaryCredentials, verifier);
```

See `samples/LeanOAuth.Samples.Console` for the complete, runnable version of this flow.

## LeanOAuth.AspNetCore

One adapter over `LeanOAuth.Http`, for "sign in with OAuth 1.0a" in an ASP.NET Core application:

```csharp
using LeanOAuth.AspNetCore;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication.Cookies;

builder
    .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOAuth10A(
        "oauth1a",
        options =>
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.ClientCredentials = new HmacSha1ClientCredentials("consumer-key", "consumer-secret");
            options.Endpoints = new OAuthProviderEndpoints(
                new Uri("https://example.com/oauth/request_token"),
                new Uri("https://example.com/oauth/authorize"),
                new Uri("https://example.com/oauth/access_token")
            );
        }
    );

app.MapGet(
    "/signin",
    () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, ["oauth1a"])
);
```

RFC 5849 defines no standard profile endpoint, so the handler does not fetch or expose provider
profile data itself. To fetch one, use `OAuth10AEvents.OnCreatingTicket`: it hands you a
`OAuth10ACreatingTicketContext` carrying the backchannel `HttpClient`, the client credentials, and
the token credentials — the same public surface any headless caller uses to sign a request.

See `samples/LeanOAuth.Samples.AspNetCore` for the complete, runnable version.

## Samples

- **`samples/LeanOAuth.Samples.Console`** — completes the out-of-band flow against endpoints and
  credentials given on the command line. Names no provider.
- **`samples/LeanOAuth.Samples.AspNetCore`** — demonstrates sign-in. Endpoints and credentials
  come from configuration, not code.

Neither sample contains provider-specific code, configuration, or endpoints.

## Security responsibilities this library does not carry

LeanOAuth signs requests and runs the three-legged flow. It does not, and its use does not imply:

- **Token storage and encryption at rest.** Temporary and token credentials are plain strings;
  where and how you persist them is your application's responsibility.
- **Transport security.** The library signs over whatever `HttpClient`/`Uri` you give it; it does
  not enforce TLS. Send credentials only over HTTPS.
- **Callback URL validation.** The library builds the authorization URI and reads back whatever
  the provider sends to your callback endpoint; validating that your callback route is reachable
  only as intended is your application's responsibility.
- **Request forgery prevention.** `LeanOAuth.AspNetCore` correlates the challenge and callback
  through its own state cookie, matching the returned `oauth_token` against the one it requested.
  Beyond that, general CSRF and session-fixation hardening of your application is your
  responsibility.
- **Credential rotation.** The library has no opinion on how long a consumer key/secret or token
  pair lives; rotating them is between you and the provider.

## Release notes

See [`CHANGELOG.md`](CHANGELOG.md).

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any
improvements or bug fixes.

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).
