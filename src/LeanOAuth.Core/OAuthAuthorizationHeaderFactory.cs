using System.Diagnostics.Contracts;
using System.Text;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures;
using LeanOAuth.Core.Signatures.Abstractions;

namespace LeanOAuth.Core;

public sealed class OAuthAuthorizationHeaderFactory<TOAuthOptions>(
    TOAuthOptions options,
    OAuthSignatureCalculator signatureCalculator,
    TimeProvider timeProvider,
    INonceGenerator nonceGenerator
) : IOAuthAuthorizationHeaderFactory<TOAuthOptions>
    where TOAuthOptions : IOAuthOptions
{
    public string CreateRequestTokenRequestHeader(HttpMethod httpMethod, Uri callbackUrl) =>
        CreateRequestHeader(
            options.RequestTokenEndpoint,
            httpMethod,
            string.Empty,
            () => BuildRequestTokenSpecificHeaderParameters(callbackUrl)
        );

    public string CreateRequestTokenRequestHeader(
        HttpMethod httpMethod,
        Uri callbackUrl,
        IDictionary<string, string> additionalParameters
    ) =>
        CreateRequestHeader(
            options.RequestTokenEndpoint,
            httpMethod,
            string.Empty,
            () => BuildRequestTokenSpecificHeaderParameters(callbackUrl),
            additionalParameters
        );

    public string CreateAccessTokenRequestHeader(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier
    ) =>
        CreateRequestHeader(
            options.AccessTokenEndpoint,
            httpMethod,
            tokenSecret,
            () => BuildAccessTokenSpecificHeaderParameters(token, verifier)
        );

    public string CreateAccessTokenRequestHeader(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier,
        IDictionary<string, string> additionalParameters
    ) =>
        CreateRequestHeader(
            options.AccessTokenEndpoint,
            httpMethod,
            tokenSecret,
            () => BuildAccessTokenSpecificHeaderParameters(token, verifier),
            additionalParameters
        );

    private string CreateRequestHeader(
        Uri endpoint,
        HttpMethod httpMethod,
        string tokenSecret,
        Func<IDictionary<string, string>> buildRequestSpecificHeaderParametersFactory
    ) =>
        CreateRequestHeader(
            endpoint,
            httpMethod,
            tokenSecret,
            buildRequestSpecificHeaderParametersFactory,
            new Dictionary<string, string>()
        );

    private string CreateRequestHeader(
        Uri endpoint,
        HttpMethod httpMethod,
        string tokenSecret,
        Func<IDictionary<string, string>> buildRequestSpecificHeaderParametersFactory,
        IDictionary<string, string> additionalParameters
    )
    {
        var timestamp = timeProvider.GetLocalNow().ToUnixTimeSeconds();
        var nonce = nonceGenerator.Generate();

        var basicHeaderParameters = BuildHeaderParameters(timestamp, nonce);

        var requestSpecificHeaderParameters = buildRequestSpecificHeaderParametersFactory();

        var headerParameters = MergeParameters(
            basicHeaderParameters,
            requestSpecificHeaderParameters
        );

        var parametersForSignature = MergeParameters(headerParameters, additionalParameters);

        var signature = signatureCalculator.Calculate(
            new OAuthSignatureCreationContext(
                httpMethod,
                endpoint,
                parametersForSignature,
                options.ConsumerSecret,
                tokenSecret
            )
        );

        var headerParametersWithSignature = MergeParameters(
            headerParameters,
            new Dictionary<string, string>
            {
                { OAuthConstants.ParameterNames.Signature, signature }
            }
        );

        var sb = new StringBuilder();

        var header = sb.Append($@"realm=""{options.Realm}""")
            .Append(',')
            .Append(
                string.Join(
                    ",",
                    headerParametersWithSignature
                        .ToDictionary(
                            kvp => OAuthTools.UrlEncodeStrict(kvp.Key),
                            kvp => OAuthTools.UrlEncodeRelaxed(kvp.Value)
                        )
                        .Select(kvp => $@"{kvp.Key}=""{kvp.Value}""")
                )
            )
            .ToString();

        return header;
    }

    [Pure]
    private IDictionary<string, string> BuildHeaderParameters(long timestamp, string nonce) =>
        new Dictionary<string, string>
        {
            { OAuthConstants.ParameterNames.ConsumerKey, options.ConsumerKey },
            { OAuthConstants.ParameterNames.Nonce, nonce },
            { OAuthConstants.ParameterNames.Timestamp, timestamp.ToString() },
            { OAuthConstants.ParameterNames.SignatureMethod, signatureCalculator.SignatureMethod },
            { OAuthConstants.ParameterNames.Version, OAuthConstants.Version },
        };

    [Pure]
    private IDictionary<string, string> BuildRequestTokenSpecificHeaderParameters(
        Uri callbackEndpoint
    )
    {
        var parametersToBeAdded = new Dictionary<string, string>
        {
            { OAuthConstants.ParameterNames.Callback, callbackEndpoint.ToString() },
        };

        return parametersToBeAdded;
    }

    private IDictionary<string, string> BuildAccessTokenSpecificHeaderParameters(
        string token,
        string verifier
    ) =>
        new Dictionary<string, string>
        {
            { OAuthConstants.ParameterNames.Token, token },
            { OAuthConstants.ParameterNames.Verifier, verifier },
        };

    [Pure]
    private IDictionary<TKey, TValue> MergeParameters<TKey, TValue>(
        params IDictionary<TKey, TValue>[] parameters
    )
        where TKey : notnull =>
        parameters
            .SelectMany(dict => dict)
            .GroupBy(pair => pair.Key)
            .ToDictionary(group => group.Key, group => group.First().Value);
}
