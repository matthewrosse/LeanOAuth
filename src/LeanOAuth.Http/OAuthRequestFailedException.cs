using System.Net;

namespace LeanOAuth.Http;

/// <summary>An OAuth endpoint returned a non-success HTTP status.</summary>
public sealed class OAuthRequestFailedException : OAuthException
{
    /// <summary>Creates the exception from the provider's non-success status and response excerpt.</summary>
    public OAuthRequestFailedException(HttpStatusCode statusCode, string? responseExcerpt)
        : base(BuildMessage(statusCode))
    {
        StatusCode = statusCode;
        ResponseExcerpt = responseExcerpt;
    }

    private static readonly HttpStatusCode[] RedirectStatusCodes =
    [
        HttpStatusCode.MovedPermanently,
        HttpStatusCode.Found,
        HttpStatusCode.SeeOther,
        HttpStatusCode.TemporaryRedirect,
        HttpStatusCode.PermanentRedirect,
    ];

    private static string BuildMessage(HttpStatusCode statusCode) =>
        Array.IndexOf(RedirectStatusCodes, statusCode) >= 0
            ? $"The OAuth endpoint returned a redirect ({(int)statusCode} {statusCode}) instead of "
                + "a signed response. An OAuth 1.0a signature is bound to the request URI; a "
                + "redirect the runtime follows automatically re-sends to a URI the signature was "
                + "never bound to, which the provider then rejects. Fix the endpoint URI or "
                + "resolve the redirect before signing."
            : $"The OAuth endpoint returned {(int)statusCode} {statusCode}.";

    /// <summary>The non-success status code the provider returned.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>
    /// A truncated excerpt of the provider's response body, for diagnosing the failure.
    /// Provider-controlled: treat it as untrusted text, never as safe-to-render markup.
    /// </summary>
    public string? ResponseExcerpt { get; }
}
