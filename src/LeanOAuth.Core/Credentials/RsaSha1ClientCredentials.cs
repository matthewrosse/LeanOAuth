using System.Security.Cryptography;

namespace LeanOAuth.Core.Credentials;

/// <summary>
/// Client credentials that sign RSA-SHA1. Holds an RSA private key instead of a shared secret
/// ("consumer secret" in OAuth 1.0 Core), the configuration RSA-SHA1 providers commonly require.
/// The library never parses, loads, or disposes the key; the caller owns its lifetime.
/// </summary>
public sealed record RsaSha1ClientCredentials : ClientCredentials
{
    /// <summary>Creates RSA-SHA1 client credentials from the consumer key and private key.</summary>
    /// <param name="consumerKey">The client identifier, called "consumer key" in OAuth 1.0 Core.</param>
    /// <param name="privateKey">The RSA private key used to sign requests. Ownership stays with the caller.</param>
    public RsaSha1ClientCredentials(string consumerKey, RSA privateKey)
        : base(consumerKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        PrivateKey = privateKey;
    }

    /// <summary>The RSA private key used to sign requests.</summary>
    public RSA PrivateKey { get; }

    /// <summary>
    /// Signs <paramref name="data"/> with <see cref="PrivateKey"/> using SHA1 and PKCS#1 v1.5
    /// padding, per RFC 5849 §3.4.3. Locked on <see cref="PrivateKey"/> itself, not a static,
    /// because the runtime's <see cref="RSA"/> implementations are not contractually
    /// thread-safe for concurrent signing: two credentials holding different keys never
    /// contend, and only concurrent signing through the same key serializes -- even if that
    /// key is wrapped by more than one credential instance.
    /// </summary>
    internal byte[] Sign(byte[] data)
    {
        lock (PrivateKey)
        {
            return PrivateKey.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }
    }
}
