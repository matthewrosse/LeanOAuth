using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace LeanOAuth.Core.Common;

public static class OAuthTools
{
    private const string AlphaNumeric = Upper + Lower + Digit;
    private const string Digit = "1234567890";
    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Unreserved = AlphaNumeric + "-._~";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static readonly Encoding Encoding = Encoding.UTF8;

    /// <summary>
    /// The set of characters that are unreserved in RFC 2396 but are NOT unreserved in RFC 3986.
    /// </summary>
    private static readonly string[] UriRfc3986CharsToEscape = { "!", "*", "'", "(", ")" };

    private static readonly string[] UriRfc3968EscapedHex = { "%21", "%2A", "%27", "%28", "%29" };

    /// <summary>
    /// URL encodes a string based on section 5.1 of the OAuth spec.
    /// Namely, percent encoding with [RFC3986], avoiding unreserved characters,
    /// upper-casing hexadecimal characters, and UTF-8 encoding for text value pairs.
    /// </summary>
    /// <param name="value">The value to escape.</param>
    /// <returns>The escaped value.</returns>
    /// <remarks>
    /// The <see cref="Uri.EscapeDataString" /> method is <i>supposed</i> to take on
    /// RFC 3986 behavior if certain elements are present in a .config file.  Even if this
    /// actually worked (which in my experiments it <i>doesn't</i>), we can't rely on every
    /// host actually having this configuration element present.
    /// </remarks>
    [return: NotNullIfNotNull(nameof(value))]
    public static string? UrlEncodeRelaxed(string? value)
    {
        if (value is null)
            return null;

        // Do RFC 2396 escaping by calling the .NET method to do the work.
        var escaped = Uri.EscapeDataString(value);

        // Escape RFC 3986 chars first.
        var escapedRfc3986 = new StringBuilder(escaped);

        for (var i = 0; i < UriRfc3986CharsToEscape.Length; i++)
        {
            var t = UriRfc3986CharsToEscape[i];

            escapedRfc3986.Replace(t, UriRfc3968EscapedHex[i]);
        }

        // Return the fully-RFC3986-escaped string.
        return escapedRfc3986.ToString();
    }

    [return: NotNullIfNotNull(nameof(value))]
    public static string? UrlEncodeStrict(string? value) =>
        value is null
            ? null
            : string.Join(
                string.Empty,
                value.Select(x => Unreserved.Contains(x) ? x.ToString() : $"%{(byte)x:X2}")
            );
}
