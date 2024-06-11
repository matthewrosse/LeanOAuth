using System.Diagnostics.Contracts;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures;
using LeanOAuth.Core.Signatures.Abstractions;

namespace LeanOAuth.Core;

public sealed class OAuthAuthorizationParametersFactory<TOAuthOptions>(
    TOAuthOptions options,
    OAuthSignatureCalculator signatureCalculator,
    TimeProvider timeProvider,
    INonceGenerator nonceGenerator
) : IOAuthAuthorizationParametersFactory
    where TOAuthOptions : IOAuthOptions
{
    public IList<OAuthParameter> CreateRequestTokenRequestParameters(
        HttpMethod httpMethod,
        Uri callbackUrl
    ) => CreateRequestTokenRequestParameters(httpMethod, callbackUrl, new List<OAuthParameter>());

    public IList<OAuthParameter> CreateRequestTokenRequestParameters(
        HttpMethod httpMethod,
        Uri callbackUrl,
        IList<OAuthParameter> parameters
    ) =>
        CreateRequestParameters(
            options.RequestTokenEndpoint,
            httpMethod,
            string.Empty,
            () => ConstructRequestTokenRequestSpecificParameters(callbackUrl),
            parameters
        );

    private IList<OAuthParameter> CreateRequestParameters(
        Uri endpoint,
        HttpMethod httpMethod,
        string tokenSecret,
        Func<IList<OAuthParameter>> requestSpecificParametersFactory
    ) =>
        CreateRequestParameters(
            endpoint,
            httpMethod,
            tokenSecret,
            requestSpecificParametersFactory,
            new List<OAuthParameter>()
        );

    public IList<OAuthParameter> CreateAccessTokenRequestParameters(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier
    ) =>
        CreateAccessTokenRequestParameters(
            httpMethod,
            token,
            tokenSecret,
            verifier,
            new List<OAuthParameter>()
        );

    public IList<OAuthParameter> CreateAccessTokenRequestParameters(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier,
        IList<OAuthParameter> parameters
    ) =>
        CreateRequestParameters(
            options.AccessTokenEndpoint,
            httpMethod,
            tokenSecret,
            () => ConstructAccessTokenRequestSpecificParameters(token, verifier),
            parameters
        );

    public IList<OAuthParameter> CreateProtectedResourceRequestParameters(
        Uri requestUri,
        HttpMethod httpMethod,
        string token,
        string tokenSecret
    ) =>
        CreateProtectedResourceRequestParameters(
            requestUri,
            httpMethod,
            token,
            tokenSecret,
            new List<OAuthParameter>()
        );

    public IList<OAuthParameter> CreateProtectedResourceRequestParameters(
        Uri requestUri,
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        IList<OAuthParameter> parameters
    ) =>
        CreateRequestParameters(
            requestUri,
            httpMethod,
            tokenSecret,
            () => ConstructProtectedResourceRequestSpecificParameters(token)
        );

    private IList<OAuthParameter> CreateRequestParameters(
        Uri endpoint,
        HttpMethod httpMethod,
        string tokenSecret,
        Func<IList<OAuthParameter>> requestSpecificParametersFactory,
        IList<OAuthParameter> parameters
    )
    {
        var timestamp = timeProvider.GetLocalNow().ToUnixTimeSeconds();
        var nonce = nonceGenerator.Generate();

        var defaultParameters = ConstructDefaultParameters(timestamp, nonce);

        var requestSpecificParameters = requestSpecificParametersFactory();

        var oauthParameters = MergeParameters(defaultParameters, requestSpecificParameters);

        var parametersForCreatingSignature = MergeParameters(oauthParameters, parameters);

        var signature = signatureCalculator.Calculate(
            new OAuthSignatureCreationContext(
                httpMethod,
                endpoint,
                parametersForCreatingSignature,
                options.ConsumerSecret,
                tokenSecret
            )
        );

        var oauthParametersWithSignature = MergeParameters(
            oauthParameters,
            [new OAuthParameter(OAuthConstants.ParameterNames.Signature, signature)]
        );

        return oauthParametersWithSignature;
    }

    [Pure]
    private IList<OAuthParameter> ConstructDefaultParameters(long timestamp, string nonce) =>
        [
            new OAuthParameter(OAuthConstants.ParameterNames.ConsumerKey, options.ConsumerKey),
            new OAuthParameter(OAuthConstants.ParameterNames.Nonce, nonce),
            new OAuthParameter(OAuthConstants.ParameterNames.Timestamp, timestamp.ToString()),
            new OAuthParameter(
                OAuthConstants.ParameterNames.SignatureMethod,
                signatureCalculator.SignatureMethod
            ),
            new OAuthParameter(OAuthConstants.ParameterNames.Version, OAuthConstants.Version)
        ];

    [Pure]
    private IList<OAuthParameter> ConstructRequestTokenRequestSpecificParameters(Uri callbackUri) =>
        [new OAuthParameter(OAuthConstants.ParameterNames.Callback, callbackUri.ToString())];

    [Pure]
    private IList<OAuthParameter> ConstructAccessTokenRequestSpecificParameters(
        string token,
        string verifier
    ) =>
        [
            new OAuthParameter(OAuthConstants.ParameterNames.Token, token),
            new OAuthParameter(OAuthConstants.ParameterNames.Verifier, verifier)
        ];

    [Pure]
    private IList<OAuthParameter> ConstructProtectedResourceRequestSpecificParameters(
        string token
    ) => [new OAuthParameter(OAuthConstants.ParameterNames.Token, token)];

    [Pure]
    private IList<T> MergeParameters<T>(params IEnumerable<T>[] enumerables) =>
        enumerables.SelectMany(x => x).ToList();
}
