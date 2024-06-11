using System.Text;
using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Signatures.Abstractions;

public abstract class OAuthSignatureCalculator
{
    public abstract string SignatureMethod { get; }
    public abstract string Calculate(OAuthSignatureCreationContext context);
    private const int DefaultSignatureBaseStringBufferCapacity = 1 << 9;

    protected string CalculateSignatureBase(
        HttpMethod httpMethod,
        Uri requestBaseUrl,
        IDictionary<string, string> requestParameters
    )
    {
        var sb = new StringBuilder(DefaultSignatureBaseStringBufferCapacity);
        var methodUrlEncoded = OAuthTools.UrlEncodeRelaxed(httpMethod.Method.ToUpperInvariant());

        // Need to ensure that user provided the base url anyway...
        var baseUrlEncoded = OAuthTools.UrlEncodeRelaxed(
            requestBaseUrl.GetLeftPart(UriPartial.Path)
        );

        var sortedParameters = requestParameters
            .OrderBy(kvp => kvp.Key)
            .ThenBy(kvp => kvp.Value)
            .Select(kvp => $"{kvp.Key}={kvp.Value}")
            .ToArray();

        var concatenatedParametersEncoded = OAuthTools.UrlEncodeRelaxed(
            string.Join('&', sortedParameters)
        );

        var signature = sb.Append(methodUrlEncoded)
            .Append('&')
            .Append(baseUrlEncoded)
            .Append('&')
            .Append(concatenatedParametersEncoded)
            .ToString();

        return signature;
    }
}
