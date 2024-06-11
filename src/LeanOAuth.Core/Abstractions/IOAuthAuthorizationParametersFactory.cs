using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Abstractions;

public interface IOAuthAuthorizationParametersFactory
{
    IList<OAuthParameter> CreateRequestTokenRequestParameters(
        HttpMethod httpMethod,
        Uri callbackUrl
    );

    IList<OAuthParameter> CreateRequestTokenRequestParameters(
        HttpMethod httpMethod,
        Uri callbackUrl,
        IList<OAuthParameter> parameters
    );

    IList<OAuthParameter> CreateAccessTokenRequestParameters(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier
    );

    IList<OAuthParameter> CreateAccessTokenRequestParameters(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier,
        IList<OAuthParameter> parameters
    );

    IList<OAuthParameter> CreateProtectedResourceRequestParameters(
        Uri requestUri,
        HttpMethod httpMethod,
        string token,
        string tokenSecret
    );

    IList<OAuthParameter> CreateProtectedResourceRequestParameters(
        Uri requestUri,
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        IList<OAuthParameter> parameters
    );
}
