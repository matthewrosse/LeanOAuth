using System.Diagnostics.Contracts;
using System.Net;
using System.Text;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures;
using LeanOAuth.Core.Signatures.Abstractions;

namespace LeanOAuth.Core;

public sealed class OAuthHeaderFactory<TOAuthOptions>(
    TOAuthOptions options,
    OAuthSignatureCalculator signatureCalculator,
    TimeProvider timeProvider,
    INonceGenerator nonceGenerator
) : IOAuthHeaderFactory<TOAuthOptions>
    where TOAuthOptions : IOAuthOptions
{
    public string CreateRequestTokenHeader(HttpMethod httpMethod) =>
        CreateRequestTokenHeader(httpMethod, new Dictionary<string, string>());

    public string CreateRequestTokenHeader(
        HttpMethod httpMethod,
        IDictionary<string, string> additionalParameters
    )
    {
        var timestamp = timeProvider.GetLocalNow().ToUnixTimeSeconds();
        var nonce = nonceGenerator.Generate();

        var headerParameters = BuildRequestTokenHeaderParameters(
            options.CallbackEndpoint,
            timestamp,
            nonce,
            additionalParameters
        );

        var allParameters = MergeDictionaries(headerParameters, additionalParameters);

        var signature = signatureCalculator.Calculate(
            new OAuthSignatureCreationContext(
                httpMethod,
                options.RequestTokenEndpoint,
                allParameters,
                options.ConsumerSecret,
                string.Empty
            )
        );

        var finalParameters = MergeDictionaries(
            headerParameters,
            new Dictionary<string, string>
            {
                { OAuthConstants.ParameterNames.Signature, signature }
            }
        );

        var sb = new StringBuilder();

        var header = sb.Append(HttpRequestHeader.Authorization.ToString())
            .Append(':')
            .Append(' ')
            .Append($@"OAuth realm=""{options.Realm}""")
            .Append(',')
            .Append(
                string.Join(
                    ",",
                    finalParameters
                        .ToDictionary(
                            kvp => Uri.EscapeDataString(kvp.Key),
                            kvp => Uri.EscapeDataString(kvp.Value)
                        )
                        .Select(kvp => $@"{kvp.Key}=""{kvp.Value}""")
                )
            )
            .ToString();

        return header;
    }

    [Pure]
    private IDictionary<string, string> BuildHeaderParameters(
        long timestamp,
        string nonce,
        IDictionary<string, string> additionalParameters
    )
    {
        var defaultHeaderParameters = new Dictionary<string, string>()
        {
            { OAuthConstants.ParameterNames.ConsumerKey, options.ConsumerKey },
            { OAuthConstants.ParameterNames.Nonce, nonce },
            { OAuthConstants.ParameterNames.Timestamp, timestamp.ToString() },
            { OAuthConstants.ParameterNames.SignatureMethod, signatureCalculator.SignatureMethod },
            { OAuthConstants.ParameterNames.Version, OAuthConstants.Version },
        };

        var parameters = MergeDictionaries(defaultHeaderParameters, additionalParameters);

        return parameters;
    }

    [Pure]
    private IDictionary<string, string> BuildRequestTokenHeaderParameters(
        Uri callbackEndpoint,
        long timestamp,
        string nonce,
        IDictionary<string, string> additionalParameters
    )
    {
        var parametersToBeAdded = new Dictionary<string, string>
        {
            { OAuthConstants.ParameterNames.Callback, callbackEndpoint.ToString() }
        };

        var mergedParameters = MergeDictionaries(additionalParameters, parametersToBeAdded);

        return BuildHeaderParameters(timestamp, nonce, mergedParameters);
    }

    [Pure]
    private IDictionary<TKey, TValue> MergeDictionaries<TKey, TValue>(
        params IDictionary<TKey, TValue>[] dictionaries
    )
        where TKey : notnull =>
        dictionaries
            .SelectMany(dict => dict)
            .GroupBy(pair => pair.Key)
            .ToDictionary(group => group.Key, group => group.First().Value);
}
