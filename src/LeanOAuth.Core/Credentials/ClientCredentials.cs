namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials, called the "consumer key" and "consumer secret" in OAuth 1.0 Core.
/// The signature method is carried by the concrete type; see ADR-0002. This hierarchy is
/// closed and cannot be extended from outside the package.
/// </summary>
public abstract record ClientCredentials
{
    private protected ClientCredentials(string consumerKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(consumerKey);
        ConsumerKey = consumerKey;
    }

    /// <summary>The client identifier, called "consumer key" in OAuth 1.0 Core.</summary>
    public string ConsumerKey { get; }
}
