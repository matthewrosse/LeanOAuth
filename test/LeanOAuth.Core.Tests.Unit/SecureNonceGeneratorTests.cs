using System.Text.RegularExpressions;
using LeanOAuth.Core.Nonce;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public partial class SecureNonceGeneratorTests
{
    [Fact]
    public void GenerateNonce_Returns32LowercaseHexCharacters()
    {
        var nonce = new SecureNonceGenerator().GenerateNonce();

        nonce.Length.ShouldBe(32);
        LowercaseHexPattern().IsMatch(nonce).ShouldBeTrue();
    }

    [Fact]
    public void GenerateNonce_ProducesDifferentValuesAcrossCalls()
    {
        var generator = new SecureNonceGenerator();

        var nonces = Enumerable.Range(0, 100).Select(_ => generator.GenerateNonce()).ToHashSet();

        nonces.Count.ShouldBe(100);
    }

    [GeneratedRegex("^[0-9a-f]{32}$")]
    private static partial Regex LowercaseHexPattern();
}
