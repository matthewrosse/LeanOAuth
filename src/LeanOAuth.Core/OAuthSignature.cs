namespace LeanOAuth.Core;

/// <summary>The result of signing a request: the header value, the base string that produced it, and the signed parameters.</summary>
public sealed record OAuthSignature(
    string AuthorizationHeaderValue,
    string SignatureBaseString,
    IReadOnlyList<OAuthParameter> Parameters
);
