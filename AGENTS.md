# LeanOAuth

OAuth 1.0a (RFC 5849) for .NET. `LeanOAuth.Core` implements the protocol; `LeanOAuth.AspNetCore` binds it to the ASP.NET Core authentication middleware.

## Signing

A wrong signature surfaces only as a bare `401` from the provider — no detail, nothing failing locally. Any change to parameter building, percent-encoding, or the signature base string is a change to signing. Three rules keep it intact:

- **Percent-encode through `OAuthTools`.** RFC 5849 §3.6 requires RFC 3986 encoding; .NET's `Uri.EscapeDataString` implements RFC 2396 and leaves `!` `*` `'` `(` `)` unescaped. Use `UrlEncodeStrict` for parameter keys and `UrlEncodeRelaxed` for values.
- **Encode before sorting.** The signature base string sorts on the encoded key, then the encoded value.
- **Sign what you send.** The parameters folded into the signature base string and the parameters placed on the wire must match, including any a caller supplies.

## Tests

Signing tests are pinned to the worked example in RFC 5849 §1.2 — consumer key `dpf43f3p2l4k3l03`, nonce `kllo9940pd9333jh`, timestamp `1191242090`. Extend them with vectors from the spec, so an expected signature is verifiable against the RFC rather than against the implementation that produced it.

`OAuthSignatureCalculator`, `INonceGenerator` and `TimeProvider` are the substitution points; a signing test fixes nonce and timestamp through them.

## Core stays framework-free

`LeanOAuth.Core.csproj` carries no `FrameworkReference`, and that is load-bearing — the package is meant to work from a console or desktop app. ASP.NET Core types belong in `LeanOAuth.AspNetCore`.

## Before committing

Run `dotnet csharpier .`. The repo is CSharpier-formatted and CI does not check formatting.

## Agent skills

### Issue tracker

Issues live as GitHub issues on `matthewrosse/LeanOAuth`, managed with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use their default label strings. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and one `docs/adr/` at the repo root. See `docs/agents/domain.md`.
