using System.Web;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Responses;

namespace LeanOAuth.Core;

public static class OAuthResponseHelpers
{
    public static async Task<UnauthorizedRequestTokenResponse> GetUnauthorizedRequestTokenResponseAsync(
        HttpContent content
    )
    {
        var stream = await content.ReadAsStreamAsync();

        using var sr = new StreamReader(stream);

        var nameValueCollection = HttpUtility.ParseQueryString(await sr.ReadToEndAsync());

        var token = nameValueCollection[OAuthConstants.Responses.UnauthorizedRequestToken.Token];
        var tokenSecret = nameValueCollection[
            OAuthConstants.Responses.UnauthorizedRequestToken.TokenSecret
        ];
        var callbackConfirmed = nameValueCollection[
            OAuthConstants.Responses.UnauthorizedRequestToken.CallbackConfirmed
        ];

        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(tokenSecret);
        ArgumentNullException.ThrowIfNull(callbackConfirmed);

        return new UnauthorizedRequestTokenResponse(
            token,
            tokenSecret,
            bool.Parse(callbackConfirmed)
        );
    }

    public static async Task<AccessTokenResponse> GetAccessTokenResponseAsync(HttpContent content)
    {
        var stream = await content.ReadAsStreamAsync();

        using var sr = new StreamReader(stream);

        var nameValueCollection = HttpUtility.ParseQueryString(await sr.ReadToEndAsync());

        var token = nameValueCollection[OAuthConstants.Responses.AccessToken.Token];
        var tokenSecret = nameValueCollection[OAuthConstants.Responses.AccessToken.TokenSecret];

        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(tokenSecret);

        return new AccessTokenResponse(token, tokenSecret);
    }
}
