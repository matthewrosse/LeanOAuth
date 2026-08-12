namespace LeanOAuth.Http;

/// <summary>
/// The short-lived pair obtained from the temporary credential request endpoint and handed to
/// the resource owner for authorization. Called a "request token" in most provider documentation.
/// </summary>
/// <param name="Token">The identifier, called "oauth_token" on the wire.</param>
/// <param name="TokenSecret">The shared secret, called "oauth_token_secret" on the wire.</param>
/// <param name="CallbackConfirmed">
/// Whether the provider confirmed it received and will honour the callback — the "a" in
/// OAuth 1.0a. False only when <see cref="OAuthFlowOptions.AllowUnconfirmedCallback"/> was set;
/// otherwise a provider that did not confirm causes <see cref="OAuthFlow.RequestTemporaryCredentialsAsync"/>
/// to throw rather than produce an instance with this set to false.
/// </param>
public sealed record TemporaryCredentials(string Token, string TokenSecret, bool CallbackConfirmed);
