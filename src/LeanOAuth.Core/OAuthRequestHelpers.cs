using System.Net.Http.Headers;
using LeanOAuth.Core.Common;

namespace LeanOAuth.Core;

public static class OAuthRequestHelpers
{
    public static HttpRequestMessage PrepareGetRequestMessage(
        Uri requestUrl,
        string authorizationHeaderValue
    ) => PrepareRequestMessage(HttpMethod.Get, requestUrl, authorizationHeaderValue);

    public static HttpRequestMessage PreparePostRequestMessage(
        Uri requestUrl,
        string authorizationHeaderValue
    ) => PrepareRequestMessage(HttpMethod.Post, requestUrl, authorizationHeaderValue);

    public static HttpRequestMessage PrepareRequestMessage(
        HttpMethod method,
        Uri requestUrl,
        string authorizationHeaderValue
    ) =>
        new(method, requestUrl)
        {
            Headers =
            {
                Authorization = new AuthenticationHeaderValue(
                    OAuthConstants.AuthorizationHeaderScheme,
                    authorizationHeaderValue
                )
            }
        };
}
