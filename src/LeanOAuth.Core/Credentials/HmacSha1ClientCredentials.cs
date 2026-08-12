namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials that sign HMAC-SHA1. Holds a shared secret, called the "consumer secret"
/// in OAuth 1.0 Core.
/// </summary>
public sealed record HmacSha1ClientCredentials : ClientCredentials
{
    /// <summary>Creates HMAC-SHA1 client credentials from the consumer key and shared secret.</summary>
    /// <param name="consumerKey">The client identifier, called "consumer key" in OAuth 1.0 Core.</param>
    /// <param name="consumerSecret">The shared secret, called "consumer secret" in OAuth 1.0 Core.</param>
    public HmacSha1ClientCredentials(string consumerKey, string consumerSecret)
        : base(consumerKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(consumerSecret);
        ConsumerSecret = consumerSecret;
    }

    /// <summary>The shared secret, called "consumer secret" in OAuth 1.0 Core.</summary>
    public string ConsumerSecret { get; }
}
