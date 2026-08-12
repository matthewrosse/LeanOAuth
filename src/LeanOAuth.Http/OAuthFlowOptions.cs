namespace LeanOAuth.Http;

/// <summary>Options for <see cref="OAuthFlow"/>.</summary>
public sealed record OAuthFlowOptions
{
    /// <summary>
    /// Permits a provider that does not return "oauth_callback_confirmed=true" on its temporary
    /// credentials response. Leaving this false (the default) is what keeps OAuth 1.0a's fix for
    /// the session-fixation vulnerability enforced; setting it true re-exposes that vulnerability
    /// for the sake of a non-conformant provider. Set it only when a specific provider requires it,
    /// and only once you have confirmed that provider is not vulnerable in some other way.
    /// </summary>
    public bool AllowUnconfirmedCallback { get; init; }
}
