using System.Globalization;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.Tests.Unit.Fixtures;
using LeanOAuth.Core.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class OAuthSignerRfc5849GoldenVectorTests
{
    private static OAuthSigner CreateSigner() =>
        new(
            new OAuthSigningOptions
            {
                Clock = new FixedClock(
                    DateTimeOffset.FromUnixTimeSeconds(
                        long.Parse(
                            Rfc5849WorkedExampleFixture.Timestamp,
                            CultureInfo.InvariantCulture
                        )
                    )
                ),
                NonceGenerator = new FixedNonceGenerator(Rfc5849WorkedExampleFixture.Nonce),
            }
        );

    private static OAuthSignature SignGoldenVector() =>
        CreateSigner()
            .Sign(
                Rfc5849WorkedExampleFixture.HttpMethod,
                Rfc5849WorkedExampleFixture.RequestUri,
                new HmacSha1ClientCredentials(
                    Rfc5849WorkedExampleFixture.ConsumerKey,
                    Rfc5849WorkedExampleFixture.ConsumerSecret
                ),
                new OAuthToken(
                    Rfc5849WorkedExampleFixture.Token,
                    Rfc5849WorkedExampleFixture.TokenSecret
                ),
                Rfc5849WorkedExampleFixture
                    .RequestParameters.Select(p => new OAuthParameter(p.Key, p.Value))
                    .ToList()
            );

    [Fact]
    public void Sign_ProducesTheExactAuthorizationHeaderFromTheRfc()
    {
        var result = SignGoldenVector();

        result.AuthorizationHeaderValue.ShouldBe(
            Rfc5849WorkedExampleFixture.ExpectedAuthorizationHeaderValue
        );
    }

    [Fact]
    public void Sign_ProducesTheExactSignatureBaseStringFromTheRfc()
    {
        var result = SignGoldenVector();

        result.SignatureBaseString.ShouldBe(
            Rfc5849WorkedExampleFixture.ExpectedSignatureBaseString
        );
    }

    [Fact]
    public void Sign_ResultCarriesHeaderBaseStringAndSignedParameters()
    {
        var result = SignGoldenVector();

        result.AuthorizationHeaderValue.ShouldNotBeNullOrEmpty();
        result.SignatureBaseString.ShouldNotBeNullOrEmpty();
        result.Parameters.ShouldContain(p => p.Key == "file" && p.Value == "vacation.jpg");
        result.Parameters.ShouldContain(p => p.Key == "size" && p.Value == "original");
        result.Parameters.ShouldContain(p =>
            p.Key == "oauth_consumer_key" && p.Value == Rfc5849WorkedExampleFixture.ConsumerKey
        );
    }
}
