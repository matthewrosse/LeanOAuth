namespace LeanOAuth.Http;

/// <summary>
/// The long-lived pair obtained by exchanging authorized temporary credentials for a verifier.
/// Called an "access token" in most provider documentation. What a long-running client holds and
/// signs with.
/// </summary>
/// <param name="Token">The identifier, called "oauth_token" on the wire.</param>
/// <param name="TokenSecret">The shared secret, called "oauth_token_secret" on the wire.</param>
public sealed record TokenCredentials(string Token, string TokenSecret);
