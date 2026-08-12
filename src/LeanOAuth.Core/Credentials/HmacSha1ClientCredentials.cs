namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials that sign HMAC-SHA1. Holds a shared secret, called the "consumer secret"
/// in OAuth 1.0 Core.
/// </summary>
public sealed record HmacSha1ClientCredentials : ClientCredentials
{
    public HmacSha1ClientCredentials(string consumerKey, string consumerSecret)
        : base(consumerKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(consumerSecret);
        ConsumerSecret = consumerSecret;
    }

    /// <summary>The shared secret, called "consumer secret" in OAuth 1.0 Core.</summary>
    public string ConsumerSecret { get; }
}
