namespace LeanOAuth.Core;

/// <summary>A single protocol, query-string, or body parameter that participates in signing.</summary>
/// <param name="Key">The parameter name.</param>
/// <param name="Value">The parameter value.</param>
public readonly record struct OAuthParameter(string Key, string Value);
