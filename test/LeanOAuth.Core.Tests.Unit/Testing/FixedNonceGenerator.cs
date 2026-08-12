using LeanOAuth.Core.Nonce;

namespace LeanOAuth.Core.Tests.Unit.Testing;

internal sealed class FixedNonceGenerator(string nonce) : INonceGenerator
{
    public string GenerateNonce() => nonce;
}
