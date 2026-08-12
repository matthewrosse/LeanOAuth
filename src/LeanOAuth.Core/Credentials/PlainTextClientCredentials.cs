namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials that sign PLAINTEXT. Holds a shared secret, called the "consumer secret"
/// in OAuth 1.0 Core. Signing with this credential type is not yet implemented; it exists so
/// the credential hierarchy is closed in its full shape.
/// </summary>
public sealed record PlainTextClientCredentials : ClientCredentials
{
    public PlainTextClientCredentials(string consumerKey, string consumerSecret)
        : base(consumerKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(consumerSecret);
        ConsumerSecret = consumerSecret;
    }

    /// <summary>The shared secret, called "consumer secret" in OAuth 1.0 Core.</summary>
    public string ConsumerSecret { get; }
}
