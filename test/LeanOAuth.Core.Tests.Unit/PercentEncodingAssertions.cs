using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

internal static class PercentEncodingAssertions
{
    public static void ShouldContainOnlyUnreservedCharactersOrUppercasePercentTriplets(
        this string encoded
    )
    {
        var i = 0;
        while (i < encoded.Length)
        {
            var c = encoded[i];
            if (c == '%')
            {
                (i + 3 <= encoded.Length).ShouldBeTrue($"truncated percent triplet in '{encoded}'");
                Uri.IsHexDigit(encoded[i + 1]).ShouldBeTrue($"non-hex digit after '%' in '{encoded}'");
                Uri.IsHexDigit(encoded[i + 2]).ShouldBeTrue($"non-hex digit after '%' in '{encoded}'");
                IsDigitOrUppercaseHexLetter(encoded[i + 1])
                    .ShouldBeTrue($"lowercase hex digit in percent triplet in '{encoded}'");
                IsDigitOrUppercaseHexLetter(encoded[i + 2])
                    .ShouldBeTrue($"lowercase hex digit in percent triplet in '{encoded}'");
                i += 3;
            }
            else
            {
                IsUnreserved(c).ShouldBeTrue(
                    $"unexpected non-unreserved character '{c}' at position {i} in '{encoded}'"
                );
                i++;
            }
        }
    }

    public static bool IsUnreserved(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~';

    private static bool IsDigitOrUppercaseHexLetter(char c) =>
        char.IsAsciiDigit(c) || char.IsAsciiHexDigitUpper(c);
}
