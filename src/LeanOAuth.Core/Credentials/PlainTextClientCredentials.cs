namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials that sign PLAINTEXT. Holds a shared secret, called the "consumer secret"
/// in OAuth 1.0 Core. The signature is the shared secret itself, so this method transmits the
/// secret in every request; it is unsafe without transport security (e.g. TLS).
/// </summary>
public sealed record PlainTextClientCredentials : ClientCredentials
{
    /// <summary>Creates PLAINTEXT client credentials from the consumer key and shared secret.</summary>
    /// <param name="consumerKey">The client identifier, called "consumer key" in OAuth 1.0 Core.</param>
    /// <param name="consumerSecret">The shared secret, called "consumer secret" in OAuth 1.0 Core.</param>
    public PlainTextClientCredentials(string consumerKey, string consumerSecret)
        : base(consumerKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(consumerSecret);
        ConsumerSecret = consumerSecret;
    }

    /// <summary>The shared secret, called "consumer secret" in OAuth 1.0 Core.</summary>
    public string ConsumerSecret { get; }
}
