using FluentAssertions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures;
using NSubstitute;

namespace LeanOAuth.Core.Tests.Unit.Signatures;

public class OAuthPlainTextSignatureCalculatorTests
{
    private readonly OAuthPlainTextSignatureCalculator _sut = new();

    [Theory]
    [MemberData(nameof(CalculateData))]
    public void Calculate_ShouldReturnValidSignature(
        string consumerSecret,
        string tokenSecret,
        string expected
    )
    {
        // Arrange

        var context = new OAuthSignatureCreationContext(
            Arg.Any<HttpMethod>(),
            Arg.Any<Uri>(),
            Arg.Any<IList<OAuthParameter>>(),
            consumerSecret,
            tokenSecret
        );

        // Act
        var result = _sut.Calculate(context);

        // Assert

        result.Should().Be(expected);
    }

    public static IEnumerable<object[]> CalculateData =>
        new[]
        {
            new[] { "kd94hf93k423kf44", "pfkkdhi9sl3r4s00", "kd94hf93k423kf44&pfkkdhi9sl3r4s00" },
            new[]
            {
                "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
                "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
                "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
            },
            new[] { "abcd", "1234", "abcd&1234" }
        };
}
