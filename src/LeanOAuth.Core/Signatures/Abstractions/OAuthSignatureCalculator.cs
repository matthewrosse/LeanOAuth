using System.Text;

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
        var methodUrlEncoded = Uri.EscapeDataString(httpMethod.Method.ToUpperInvariant());

        // Need to ensure that user provided the base url anyway...
        var baseUrlEncoded = Uri.EscapeDataString(requestBaseUrl.GetLeftPart(UriPartial.Path));

        var sortedParameters = requestParameters
            .ToDictionary(
                kvp => Uri.EscapeDataString(kvp.Key),
                kvp => Uri.EscapeDataString(kvp.Value)
            )
            .OrderBy(kvp => kvp.Key)
            .ThenBy(kvp => kvp.Value)
            .Select(kvp => $"{kvp.Key}={kvp.Value}")
            .ToArray();

        var encodedConcatenatedParameters = Uri.EscapeDataString(
            string.Join('&', sortedParameters)
        );

        var signature = sb.Append(methodUrlEncoded)
            .Append('&')
            .Append(baseUrlEncoded)
            .Append('&')
            .Append(encodedConcatenatedParameters)
            .ToString();

        return signature;
    }
}
