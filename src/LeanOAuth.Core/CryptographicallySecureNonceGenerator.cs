using System.Security.Cryptography;
using LeanOAuth.Core.Abstractions;

namespace LeanOAuth.Core;

public sealed class CryptographicallySecureNonceGenerator : INonceGenerator
{
    private const int NonceLength = 1 << 6;

    public string Generate() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(NonceLength));
}
