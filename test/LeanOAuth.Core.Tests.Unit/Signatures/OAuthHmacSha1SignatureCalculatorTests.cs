using FluentAssertions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures;

namespace LeanOAuth.Core.Tests.Unit.Signatures;

public class OAuthHmacSha1SignatureCalculatorTests
{
    [Theory]
    [MemberData(nameof(CalculateData))]
    public void Generate_ShouldReturnValidSignature(
        HttpMethod httpMethod,
        Uri requestBaseUrl,
        IList<OAuthParameter> parameters,
        string consumerSecret,
        string tokenSecret,
        string expected
    )
    {
        var sut = new OAuthHmacSha1SignatureCalculator();

        // Arrange
        var context = new OAuthSignatureCreationContext(
            httpMethod,
            requestBaseUrl,
            parameters,
            consumerSecret,
            tokenSecret
        );

        // Act

        var result = sut.Calculate(context);

        // Assert

        result.Should().Be(expected);
    }

    public static IEnumerable<object[]> CalculateData =>
        new[]
        {
            new object[]
            {
                HttpMethod.Get,
                new Uri("http://photos.example.net/photos"),
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "dpf43f3p2l4k3l03"),
                    new(OAuthConstants.ParameterNames.Token, "nnch734d00sl2jdk"),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1191242096"),
                    new(OAuthConstants.ParameterNames.Nonce, "kllo9940pd9333jh"),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new("file", "vacation.jpg"),
                    new("size", "original")
                },
                "kd94hf93k423kf44",
                "pfkkdhi9sl3r4s00",
                "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
            },
            new object[]
            {
                HttpMethod.Post,
                new Uri("https://api.twitter.com/1.1/statuses/update.json"),
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "xvz1evFS4wEEPTGEFPHBog"),
                    new(
                        OAuthConstants.ParameterNames.Token,
                        "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
                    ),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1318622958"),
                    new(
                        OAuthConstants.ParameterNames.Nonce,
                        "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
                    ),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new("status", "Hello Ladies + Gentlemen, a signed OAuth request!"),
                    new("include_entities", "true")
                },
                "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
                "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
                "hCtSmYh+iHYCEqBWrE7C7hYmtUk="
            },
            new object[]
            {
                HttpMethod.Post,
                new Uri("http://host.net/resource"),
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "abcd"),
                    new(OAuthConstants.ParameterNames.Token, "ijkl"),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1462028665"),
                    new(OAuthConstants.ParameterNames.Nonce, "FDRMnsTvyF1"),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new("name", "value"),
                    new("scopes", "email|photo")
                },
                "efgh",
                "mnop",
                "Yg/QoU08gHjHquNXwcn3sAg+jAk="
            },
            new object[]
            {
                HttpMethod.Post,
                new Uri("https://usosapps.umk.pl/services/oauth/access_token"),
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "daDdqSStndmyYcKSAfKM"),
                    new(OAuthConstants.ParameterNames.Token, "9qG3rByqDzDjkfFT7SxF"),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1718116861"),
                    new(OAuthConstants.ParameterNames.Nonce, "DEKxPdg6I0M"),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new(OAuthConstants.ParameterNames.Verifier, "40156935"),
                },
                "JPD3VjzpsU3tznfr75qXmxEQbb4U2A8dwtHGjYDf",
                "XeGjTC7dYtJAJJqb2XR2yKq9VaE9eJZ3eHz4fTSn",
                "WW7NgwzwO8KAxYWA1EYPX2OHl4Y="
            }
        };
}
