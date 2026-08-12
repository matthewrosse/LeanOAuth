namespace LeanOAuth.Core;

/// <summary>The result of signing a request: the header value, the base string that produced it, and the signed parameters.</summary>
/// <param name="AuthorizationHeaderValue">The value for the "Authorization" header.</param>
/// <param name="SignatureBaseString">The signature base string that was signed, per RFC 5849 §3.4.1.</param>
/// <param name="Parameters">The parameters that were folded into the signature, encoded and sorted.</param>
public sealed record OAuthSignature(
    string AuthorizationHeaderValue,
    string SignatureBaseString,
    IReadOnlyList<OAuthParameter> Parameters
);
