using System.Globalization;
using System.Text;

namespace LeanOAuth.Core.PercentEncoding;

/// <summary>
/// RFC 3986 percent-encoding, used everywhere in this library including PLAINTEXT signing.
/// Public so the parameter hook can encode values consistently with the signer.
/// </summary>
public static class PercentEncoder
{
    /// <summary>Percent-encodes <paramref name="value"/> per RFC 3986 over its UTF-8 bytes.</summary>
    public static string Encode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var bytes = Encoding.UTF8.GetBytes(value);
        var builder = new StringBuilder(bytes.Length);

        foreach (var b in bytes)
        {
            if (IsUnreserved(b))
            {
                builder.Append((char)b);
            }
            else
            {
                builder.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    private static bool IsUnreserved(byte b) =>
        (b >= (byte)'A' && b <= (byte)'Z')
        || (b >= (byte)'a' && b <= (byte)'z')
        || (b >= (byte)'0' && b <= (byte)'9')
        || b is (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~';
}
