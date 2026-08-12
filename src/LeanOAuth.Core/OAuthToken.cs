namespace LeanOAuth.Core;

/// <summary>
/// A token/secret pair. The base representation shared by temporary credentials (the "request
/// token" in OAuth 1.0 Core) and token credentials (the "access token" in OAuth 1.0 Core).
/// </summary>
public readonly record struct OAuthToken(string Token, string TokenSecret);
