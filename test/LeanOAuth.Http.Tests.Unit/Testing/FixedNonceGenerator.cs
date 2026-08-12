using LeanOAuth.Core.Nonce;

namespace LeanOAuth.Http.Tests.Unit.Testing;

internal sealed class FixedNonceGenerator(string nonce) : INonceGenerator
{
    public string GenerateNonce() => nonce;
}
