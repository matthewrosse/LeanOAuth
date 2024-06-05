using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Requests.Signatures;

public class OAuthSignatureMethod : Enumeration<OAuthSignatureMethod>
{
    public static readonly OAuthSignatureMethod PlainText = new(1, "PLAINTEXT");
    public static readonly OAuthSignatureMethod HmacSha1 = new(2, "HMAC-SHA1");
    public static readonly OAuthSignatureMethod RsaSha1 = new(3, "RSA-SHA1");

    private OAuthSignatureMethod(int value, string name)
        : base(value, name) { }
}
