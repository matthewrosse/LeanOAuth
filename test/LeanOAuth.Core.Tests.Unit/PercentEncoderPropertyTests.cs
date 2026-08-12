using CsCheck;
using LeanOAuth.Core.PercentEncoding;
using Shouldly;
using static LeanOAuth.Core.Tests.Unit.PercentEncodingAssertions;

namespace LeanOAuth.Core.Tests.Unit;

public class PercentEncoderPropertyTests
{
    // Covers ASCII, RFC 2396/3986 divergence marks ("!*'()"), reserved punctuation, control
    // characters, and the BMP outside surrogate pairs. Lone surrogates are excluded because they
    // are not valid Unicode scalar values and cannot round-trip through UTF-8.
    private static readonly Gen<char> ArbitraryChar = Gen.Char[
        (char)0x00000,
        (char)0x0FFFF
    ].Where(c => !char.IsSurrogate(c));

    private static readonly Gen<string> ArbitraryString = Gen.String[ArbitraryChar, 0, 64];

    private static readonly Gen<string> UnreservedOnlyString = Gen.String[
        Gen.Char[(char)0x00, (char)0x7F].Where(IsUnreserved),
        0,
        64
    ];

    [Fact]
    public void Encode_OnlyProducesUnreservedCharactersOrUppercasePercentTriplets()
    {
        ArbitraryString.Sample(input =>
            PercentEncoder
                .Encode(input)
                .ShouldContainOnlyUnreservedCharactersOrUppercasePercentTriplets()
        );
    }

    [Fact]
    public void Encode_RoundTrips()
    {
        ArbitraryString.Sample(input =>
        {
            var encoded = PercentEncoder.Encode(input);
            var decoded = Uri.UnescapeDataString(encoded);

            decoded.ShouldBe(input);
        });
    }

    [Fact]
    public void Encode_NeverEncodesUnreservedCharacters()
    {
        UnreservedOnlyString.Sample(input =>
        {
            PercentEncoder.Encode(input).ShouldBe(input);
        });
    }
}
