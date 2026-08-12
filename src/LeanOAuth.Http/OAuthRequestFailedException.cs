using System.Net;

namespace LeanOAuth.Http;

/// <summary>An OAuth endpoint returned a non-success HTTP status.</summary>
public sealed class OAuthRequestFailedException : OAuthException
{
    public OAuthRequestFailedException(HttpStatusCode statusCode, string? responseExcerpt)
        : base($"The OAuth endpoint returned {(int)statusCode} {statusCode}.")
    {
        StatusCode = statusCode;
        ResponseExcerpt = responseExcerpt;
    }

    /// <summary>The non-success status code the provider returned.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>
    /// A truncated excerpt of the provider's response body, for diagnosing the failure.
    /// Provider-controlled: treat it as untrusted text, never as safe-to-render markup.
    /// </summary>
    public string? ResponseExcerpt { get; }
}
