namespace LeanOAuth.Core;

/// <summary>A single protocol, query-string, or body parameter that participates in signing.</summary>
public readonly record struct OAuthParameter(string Key, string Value);
