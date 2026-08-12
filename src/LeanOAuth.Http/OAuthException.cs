namespace LeanOAuth.Http;

/// <summary>
/// Base type for exceptions <see cref="OAuthFlow"/> itself raises. Catch this to handle a
/// malformed provider response and a rejected request together, or catch
/// <see cref="OAuthProtocolException"/> and <see cref="OAuthRequestFailedException"/>
/// individually to distinguish them. Transport failures from the underlying
/// <see cref="HttpClient"/> (for example <see cref="HttpRequestException"/>) are not wrapped and
/// propagate separately.
/// </summary>
public abstract class OAuthException : Exception
{
    private protected OAuthException(string message)
        : base(message) { }

    private protected OAuthException(string message, Exception innerException)
        : base(message, innerException) { }
}
