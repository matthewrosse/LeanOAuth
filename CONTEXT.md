# Context

Domain glossary for LeanOAuth. Terms are RFC 5849's, because a credential in OAuth 1.0a is always a key/secret *pair* and the RFC's names say so where OAuth 1.0 Core's do not.

Most provider documentation — Atlassian's included — uses the older OAuth 1.0 Core vocabulary. Every public type carries its Core synonym in its XML doc so that a reader arriving from provider docs finds the right type.

## Credentials

**Client credentials** — the consumer key, plus whatever secret material authenticates the client. Called *consumer key / consumer secret* in provider docs. What the secret material *is* depends on the signature method, which is why it is not one type: an HMAC client holds a shared secret, an RSA client holds a private key.

**Temporary credentials** — the short-lived pair obtained from the request-token endpoint and handed to the resource owner for authorization. Called a *request token* in provider docs. Short-lived — providers commonly expire them in minutes.

**Token credentials** — the long-lived pair obtained by exchanging authorized temporary credentials. Called an *access token* in provider docs. This is what a long-running client holds and signs with.

**Verifier** — the code the provider returns after the resource owner authorizes, proving the authorization happened. Delivered on the callback URL, or displayed for the user to paste when the client registered no callback (out-of-band).

## Protocol

**Signature base string** — the normalized string that gets signed: HTTP method, normalized URI, and normalized parameters, concatenated and percent-encoded per RFC 5849 §3.4.1. Getting this wrong is the failure mode of the entire protocol, and it fails as a bare `401`.

**Parameter normalization** — collecting the parameters that participate in signing (OAuth protocol parameters, query-string parameters, and form-encoded body parameters), encoding them, and sorting by encoded key then encoded value. A non-form-encoded body — JSON, for instance — does not participate.

**Signature method** — HMAC-SHA1, RSA-SHA1, or PLAINTEXT. Not a configuration setting in this library: it is determined by which client credential type you hold. See ADR-0002.

## Roles

**Client** — the application signing requests. Called a *consumer* in OAuth 1.0 Core; avoided here because "consumer" collides with .NET's producer/consumer sense.

**Provider** — the server issuing credentials and serving protected resources. This library is provider-neutral: no provider-specific code, configuration, samples, or tests live here. Provider quirks are handled by the caller through the parameter hook.

**Resource owner** — the human who authorizes the client.

## Consumers of this library

**Headless client** — a console app, daemon, or MCP server holding token credentials and signing outbound requests. The design centre. See ADR-0003.

**Sign-in adapter** — an ASP.NET Core authentication handler doing "sign in with X" in a browser. One adapter over the core, not the core's shape.
