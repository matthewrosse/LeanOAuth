using LeanOAuth.Core.PercentEncoding;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class PercentEncoderTests
{
    [Theory]
    [InlineData("abcABC123", "abcABC123")]
    [InlineData("-._~", "-._~")]
    [InlineData(" ", "%20")]
    [InlineData("!*'()", "%21%2A%27%28%29")]
    [InlineData("a b", "a%20b")]
    [InlineData("100%", "100%25")]
    [InlineData("", "")]
    public void Encode_MatchesRfc3986(string input, string expected)
    {
        PercentEncoder.Encode(input).ShouldBe(expected);
    }

    [Fact]
    public void Encode_EncodesUnicodeAsUppercaseUtf8PercentTriplets()
    {
        PercentEncoder.Encode("é").ShouldBe("%C3%A9");
    }

    [Fact]
    public void Encode_DoesNotDoubleEncodeAlreadyEncodedInput()
    {
        PercentEncoder.Encode("%20").ShouldBe("%2520");
    }

    [Theory]
    [InlineData("hello world! this is a test 100% (of) 'encoding' *properly*")]
    [InlineData("unicode: héllo wörld 日本語")]
    [InlineData("")]
    [InlineData("unreserved-only_1.2~3")]
    public void Encode_OnlyProducesUnreservedCharactersOrUppercasePercentTriplets(string input)
    {
        PercentEncoder
            .Encode(input)
            .ShouldContainOnlyUnreservedCharactersOrUppercasePercentTriplets();
    }

    [Theory]
    [InlineData("hello world!")]
    [InlineData("unicode: héllo wörld 日本語")]
    [InlineData("")]
    public void Encode_RoundTrips(string input)
    {
        var encoded = PercentEncoder.Encode(input);
        var roundTripped = Uri.UnescapeDataString(encoded);

        roundTripped.ShouldBe(input);
    }
}
