# ADR-0003: The headless client is the design centre; ASP.NET Core is an adapter

**Status:** Accepted (2026-08-12)

## Context

LeanOAuth v1 grew around `OAuth10AHandler`, an ASP.NET Core `RemoteAuthenticationHandler`. The protocol flow — request temporary credentials, redirect, exchange for token credentials, parse responses — lives inside that handler, and the only seam beneath it is a parameter-list factory. Nothing can exercise the flow without a full ASP.NET Core test host, and at 336 lines it is the largest and least tested file in the repository.

The first concrete consumer of v2 is an MCP server talking to Jira 8. It runs as a local process, holds one long-lived access token, and signs outbound REST calls. It has no browser session, no authentication cookie, no `ClaimsPrincipal`, and no DataProtection state. Designing around the ASP.NET Core handler again would shape the core API around constraints that consumer does not have.

## Decision

The protocol core and the flow orchestration are plain types with no web framework dependency. ASP.NET Core sign-in ships as a separate package that adapts them.

## Consequences

- The flow is reachable from a test with a stubbed `HttpMessageHandler` and no test host.
- Two adapters — a headless client and a sign-in handler — sit over one core, which is what makes the seam real rather than hypothetical.
- The ASP.NET Core package can no longer take shortcuts through internals; anything it needs must be part of the core's public interface.
- Sequencing follows: core and headless client are built and validated against Jira first, and the ASP.NET Core package is adapted onto whatever shape that produces.
