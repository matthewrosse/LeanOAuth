using System.Security.Cryptography;

namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials that sign RSA-SHA1. Holds an RSA private key instead of a shared secret.
/// Signing with this credential type is not yet implemented; it exists so the credential
/// hierarchy is closed in its full shape.
/// </summary>
public sealed record RsaSha1ClientCredentials : ClientCredentials
{
    public RsaSha1ClientCredentials(string consumerKey, RSA privateKey)
        : base(consumerKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        PrivateKey = privateKey;
    }

    /// <summary>The RSA private key used to sign requests.</summary>
    public RSA PrivateKey { get; }
}
