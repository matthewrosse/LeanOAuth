using System.Security.Cryptography;

namespace LeanOAuth.Core.Nonce;

/// <summary>Generates a nonce as 16 random bytes from a cryptographically secure source, rendered as 32 lowercase hex characters.</summary>
public sealed class SecureNonceGenerator : INonceGenerator
{
    /// <inheritdoc />
    public string GenerateNonce()
    {
        Span<byte> bytes = stackalloc byte[16];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
