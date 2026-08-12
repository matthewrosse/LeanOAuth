namespace LeanOAuth.Http;

/// <summary>
/// The provider's response was malformed or missing a required parameter. Never thrown for a
/// mistake in the caller's own arguments.
/// </summary>
public sealed class OAuthProtocolException : OAuthException
{
    /// <summary>Creates the exception with the given message.</summary>
    public OAuthProtocolException(string message)
        : base(message) { }

    /// <summary>Creates the exception with the given message and inner exception.</summary>
    public OAuthProtocolException(string message, Exception innerException)
        : base(message, innerException) { }
}
