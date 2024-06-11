using System.Security.Cryptography;
using System.Text;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures.Abstractions;

namespace LeanOAuth.Core.Signatures;

public sealed class OAuthHmacSha1SignatureCalculator : OAuthSignatureCalculator
{
    public override string SignatureMethod => OAuthConstants.SignatureMethods.HmacSha1;

    public override string Calculate(OAuthSignatureCreationContext context)
    {
        var escapedConsumerSecret = OAuthTools.UrlEncodeRelaxed(context.ConsumerSecret);
        var escapedTokenSecret = OAuthTools.UrlEncodeRelaxed(context.TokenSecret);

        var key = Encoding.UTF8.GetBytes(
            string.Join('&', escapedConsumerSecret, escapedTokenSecret)
        );

        var signatureBase = CalculateSignatureBase(
            context.HttpMethod,
            context.RequestBaseUrl,
            context
                .RequestParameters.Select(x => new OAuthParameter(
                    OAuthTools.UrlEncodeStrict(x.Key),
                    OAuthTools.UrlEncodeRelaxed(x.Value)
                ))
                .ToList()
        );

        var signatureBaseBytes = Encoding.UTF8.GetBytes(signatureBase);

        var digest = HMACSHA1.HashData(key, signatureBaseBytes);

        var signature = Convert.ToBase64String(digest);

        return signature;
    }
}
