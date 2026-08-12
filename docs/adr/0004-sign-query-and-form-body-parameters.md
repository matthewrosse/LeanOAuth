# ADR-0004: The signature base string includes query-string and form-body parameters

**Status:** Accepted (2026-08-12)

## Context

RFC 5849 §3.4.1.3.1 defines the parameters that participate in the signature base string as three sources combined: the OAuth protocol parameters, the query component of the request URI, and the entity body when its content type is `application/x-www-form-urlencoded`.

LeanOAuth v1 includes only the first. `OAuthAuthorizationParametersFactory` builds the protocol parameters and signs those alone; the request URI's query component is never parsed, and no body is ever read. Any request to a provider that carries a query string is therefore signed incorrectly, and the failure surfaces as a bare `401` with no diagnostic. The handler compounds this by appending a scope query string to the request-token endpoint by hand after the signature has already been computed.

## Decision

The signature base string is built from all three sources.

`LeanOAuth.Core` parses the query component out of the request URI itself, since it must parse the URI to normalize it. `LeanOAuth.Http` reads form-encoded request bodies and supplies those parameters to the signer. A body of any other content type — JSON, for instance — does not participate, per the RFC.

## Consequences

- This is a silent behavioural break against v1 for any request carrying a query string. A caller who upgrades gets a different signature for the same request. That is the correct signature; v1's was wrong.
- Callers cannot opt out or forget. Query parameters are extracted from the URI they already pass, rather than being a separate argument they might omit — which is how v1's own parameter-dropping bug happened.
- Reading a form-encoded body forces the HTTP layer to buffer content that would otherwise stream, and to re-attach it so the request remains sendable. Signing is therefore async at the HTTP layer even though the protocol core is synchronous.
- The test suite needs signature base string cases covering existing query strings, duplicate keys across sources, and empty values, because these paths did not exist before.
