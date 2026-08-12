using LeanOAuth.Core.Nonce;

namespace LeanOAuth.Core;

/// <summary>Options for <see cref="OAuthSigner"/>: the nonce generator, clock, and parameter hook.</summary>
public sealed record OAuthSigningOptions
{
    /// <summary>The nonce generator. Defaults to a cryptographically secure generator.</summary>
    public INonceGenerator NonceGenerator { get; init; } = new SecureNonceGenerator();

    /// <summary>The clock used for "oauth_timestamp". Defaults to the system clock.</summary>
    public IClock Clock { get; init; } = new SystemClock();

    /// <summary>Runs against the parameter set before the signature is computed. No-op by default.</summary>
    public ParameterHook? ParameterHook { get; init; }
}
