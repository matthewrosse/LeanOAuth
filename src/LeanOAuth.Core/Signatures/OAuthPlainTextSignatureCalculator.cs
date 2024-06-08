using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures.Abstractions;

namespace LeanOAuth.Core.Signatures;

public sealed class OAuthPlainTextSignatureCalculator : OAuthSignatureCalculator
{
    public override string SignatureMethod => OAuthConstants.SignatureMethods.PlainText;

    public override string Calculate(OAuthSignatureCreationContext context)
    {
        var escapedConsumerSecret = Uri.EscapeDataString(context.ConsumerSecret);
        var escapedTokenSecret = Uri.EscapeDataString(context.TokenSecret);

        return string.Join('&', escapedConsumerSecret, escapedTokenSecret);
    }
}
