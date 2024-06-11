namespace LeanOAuth.Core.Common;

/// <summary>
/// Contains information about OAuth1.0A parameter, e.g. oauth_consumer_key=something
/// </summary>
/// <param name="Key">The key.</param>
/// <param name="Value">The value.</param>
public sealed record OAuthParameter(string Key, string Value);
