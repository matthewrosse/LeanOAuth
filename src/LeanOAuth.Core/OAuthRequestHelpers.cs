using System.Net.Http.Headers;

namespace LeanOAuth.Core;

public static class OAuthRequestHelpers
{
    public static HttpRequestMessage PrepareGetRequestMessage(
        Uri requestUrl,
        AuthenticationHeaderValue authorizationHeaderValue
    ) => PrepareRequestMessage(HttpMethod.Get, requestUrl, authorizationHeaderValue);

    public static HttpRequestMessage PreparePostRequestMessage(
        Uri requestUrl,
        AuthenticationHeaderValue authorizationHeaderValue
    ) => PrepareRequestMessage(HttpMethod.Post, requestUrl, authorizationHeaderValue);

    public static HttpRequestMessage PrepareRequestMessage(
        HttpMethod method,
        Uri requestUrl,
        AuthenticationHeaderValue authorizationHeaderValue
    ) => new(method, requestUrl) { Headers = { Authorization = authorizationHeaderValue } };
}
