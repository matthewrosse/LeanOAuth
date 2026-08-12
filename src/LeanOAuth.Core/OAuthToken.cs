namespace LeanOAuth.Core;

/// <summary>
/// A token/secret pair. The base representation shared by temporary credentials (the "request
/// token" in OAuth 1.0 Core) and token credentials (the "access token" in OAuth 1.0 Core).
/// </summary>
/// <param name="Token">The identifier, called "oauth_token" on the wire.</param>
/// <param name="TokenSecret">The shared secret, called "oauth_token_secret" on the wire.</param>
public readonly record struct OAuthToken(string Token, string TokenSecret);
