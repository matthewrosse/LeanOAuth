using System.Globalization;
using System.Security.Cryptography;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.Tests.Unit.Fixtures;
using LeanOAuth.Core.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class OAuthSignerRsaSha1Tests
{
    private static OAuthSigner CreateSigner() =>
        new(
            new OAuthSigningOptions
            {
                Clock = new FixedClock(
                    DateTimeOffset.FromUnixTimeSeconds(
                        long.Parse(RsaSha1GoldenVectorFixture.Timestamp, CultureInfo.InvariantCulture)
                    )
                ),
                NonceGenerator = new FixedNonceGenerator(RsaSha1GoldenVectorFixture.Nonce),
            }
        );

    private static RSA CreateGoldenVectorKey()
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(RsaSha1GoldenVectorFixture.PrivateKeyPem);
        return rsa;
    }

    [Fact]
    public void Sign_WithRsaCredentials_ProducesTheExpectedSignatureBaseString()
    {
        using var key = CreateGoldenVectorKey();
        var credentials = new RsaSha1ClientCredentials(RsaSha1GoldenVectorFixture.ConsumerKey, key);

        var result = CreateSigner()
            .Sign(
                RsaSha1GoldenVectorFixture.HttpMethod,
                RsaSha1GoldenVectorFixture.RequestUri,
                credentials
            );

        result.SignatureBaseString.ShouldBe(RsaSha1GoldenVectorFixture.ExpectedSignatureBaseString);
    }

    [Fact]
    public void Sign_WithRsaCredentials_ProducesTheExpectedSignatureAgainstAKnownKey()
    {
        using var key = CreateGoldenVectorKey();
        var credentials = new RsaSha1ClientCredentials(RsaSha1GoldenVectorFixture.ConsumerKey, key);

        var result = CreateSigner()
            .Sign(
                RsaSha1GoldenVectorFixture.HttpMethod,
                RsaSha1GoldenVectorFixture.RequestUri,
                credentials
            );

        var expectedHeaderSignature = Uri.EscapeDataString(
            RsaSha1GoldenVectorFixture.ExpectedSignature
        );
        result.AuthorizationHeaderValue.ShouldContain($"oauth_signature=\"{expectedHeaderSignature}\"");
    }

    [Fact]
    public void Sign_WithRsaCredentials_DoesNotDisposeTheSuppliedKey()
    {
        using var key = CreateGoldenVectorKey();
        var credentials = new RsaSha1ClientCredentials(RsaSha1GoldenVectorFixture.ConsumerKey, key);

        CreateSigner()
            .Sign(
                RsaSha1GoldenVectorFixture.HttpMethod,
                RsaSha1GoldenVectorFixture.RequestUri,
                credentials
            );

        Should.NotThrow(() => key.SignData([1, 2, 3], HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void Sign_ConcurrentSigningThroughOneSharedRsaCredential_ProducesNoCorruption()
    {
        using var key = CreateGoldenVectorKey();
        var credentials = new RsaSha1ClientCredentials(RsaSha1GoldenVectorFixture.ConsumerKey, key);
        var signer = CreateSigner();

        var results = Enumerable
            .Range(0, 64)
            .AsParallel()
            .Select(_ =>
                signer.Sign(
                    RsaSha1GoldenVectorFixture.HttpMethod,
                    RsaSha1GoldenVectorFixture.RequestUri,
                    credentials
                )
            )
            .ToList();

        results.ShouldAllBe(r =>
            r.AuthorizationHeaderValue.Contains(Uri.EscapeDataString(RsaSha1GoldenVectorFixture.ExpectedSignature))
        );
    }

    [Fact]
    public void Sign_ConcurrentSigningThroughTwoCredentialsWithDifferentKeys_DoNotContend()
    {
        using var keyA = RSA.Create(2048);
        using var keyB = RSA.Create(2048);
        var credentialsA = new RsaSha1ClientCredentials("consumer-a", keyA);
        var credentialsB = new RsaSha1ClientCredentials("consumer-b", keyB);
        var signer = new OAuthSigner();
        var uri = new Uri("http://example.com/resource");

        var results = Enumerable
            .Range(0, 64)
            .AsParallel()
            .Select(i =>
                signer.Sign(
                    HttpMethod.Get,
                    uri,
                    i % 2 == 0 ? credentialsA : credentialsB
                )
            )
            .ToList();

        results.ShouldAllBe(r => !string.IsNullOrEmpty(r.AuthorizationHeaderValue));
    }
}
