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
        Dictionary<string, string> additionalParameters,
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
            additionalParameters,
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
                new Dictionary<string, string>
                {
                    { OAuthConstants.ParameterNames.ConsumerKey, "dpf43f3p2l4k3l03" },
                    { OAuthConstants.ParameterNames.Token, "nnch734d00sl2jdk" },
                    { OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1" },
                    { OAuthConstants.ParameterNames.Timestamp, "1191242096" },
                    { OAuthConstants.ParameterNames.Nonce, "kllo9940pd9333jh" },
                    { OAuthConstants.ParameterNames.Version, "1.0" },
                    { "file", "vacation.jpg" },
                    { "size", "original" },
                },
                "kd94hf93k423kf44",
                "pfkkdhi9sl3r4s00",
                "tR3+Ty81lMeYAr/Fid0kMTYa/WM="
            }
        };
}
