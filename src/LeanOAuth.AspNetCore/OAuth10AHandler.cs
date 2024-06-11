using System.Text.Encodings.Web;
using LeanOAuth.AspNetCore.Exceptions;
using LeanOAuth.AspNetCore.Options;
using LeanOAuth.Core;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace LeanOAuth.AspNetCore;

public class OAuth10AHandler<TOptions>(
    IOptionsMonitor<TOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOAuthHeaderFactory<TOptions> headerFactory
) : RemoteAuthenticationHandler<TOptions>(options, logger, encoder)
    where TOptions : OAuth10AOptions, new()
{
    private const string StateParameterName = "state";

    /// <summary>
    /// Gets the <see cref="T:System.Net.Http.HttpClient" /> instance used to communicate with the remote authentication provider.
    /// </summary>
    private HttpClient Backchannel => Options.Backchannel;

    /// <summary>
    /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
    /// If it is not provided a default instance is supplied which does nothing when the methods are called.
    /// </summary>
    private new OAuth10AEvents Events
    {
        get => (OAuth10AEvents)base.Events;
        set => base.Events = value;
    }

    /// <summary>
    /// Creates a new instance of the events instance.
    /// </summary>
    /// <returns>A new instance of the events instance.</returns>
    protected override Task<object> CreateEventsAsync() =>
        Task.FromResult<object>(new OAuth10AEvents());

    protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        throw new NotImplementedException();
    }

    private async Task<UnauthorizedRequestTokenResponse> GetUnauthorizedRequestTokenResponseAsync(
        string callbackUri
    )
    {
        var authorizationHeaderValue = headerFactory.CreateRequestTokenHeader(
            HttpMethod.Post,
            new Uri(callbackUri)
        );

        var requestMessage = OAuthRequestHelpers.PreparePostRequestMessage(
            Options.RequestTokenEndpoint,
            authorizationHeaderValue
        );

        var response = await Backchannel.SendAsync(requestMessage);

        if (!response.IsSuccessStatusCode)
        {
            throw new UnauthorizedTemporaryCredentialsRequestException(
                "The request was not authorized, possible reasons: wrong credentials."
            );
        }

        var unauthorizedRequestTokenResponse =
            await OAuthResponseHelpers.GetUnauthorizedRequestTokenResponseAsync(response.Content);

        return unauthorizedRequestTokenResponse;
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
        }

        var callbackUri = BuildRedirectUri(Options.CallbackPath);

        var unauthorizedRequestTokenResponse = await GetUnauthorizedRequestTokenResponseAsync(
            callbackUri
        );

        var authorizationEndpoint = BuildChallengeUrl(
            properties,
            callbackUri,
            unauthorizedRequestTokenResponse.Token,
            unauthorizedRequestTokenResponse.TokenSecret
        );

        var redirectContext = new RedirectContext<OAuth10AOptions>(
            Context,
            Scheme,
            Options,
            properties,
            authorizationEndpoint
        );

        await Events.RedirectToAuthorizationEndpoint(redirectContext);

        var location = Context.Response.Headers.Location;

        if (location == StringValues.Empty)
        {
            location = "(not set)";
        }

        var cookie = Context.Response.Headers.SetCookie;

        if (cookie == StringValues.Empty)
        {
            cookie = "(not set)";
        }

        Logger.LogDebug(
            "HandleChallenge with Location: {Location}; and Set-Cookie: {Cookie}., EventName = \"HandleChallenge\"",
            location.ToString(),
            cookie.ToString()
        );
    }

    private string BuildChallengeUrl(
        AuthenticationProperties properties,
        string callbackUri,
        string token,
        string tokenSecret
    )
    {
        var parameters = new Dictionary<string, string?>
        {
            { OAuthConstants.ParameterNames.Token, token },
            { OAuthConstants.ParameterNames.Callback, callbackUri }
        };

        // Store token secret for later retrieval in HandleRemoteAuthenticateAsync.
        properties.Items.Add(OAuthConstants.ParameterNames.TokenSecret, tokenSecret);

        parameters[StateParameterName] = Options.StateDataFormat.Protect(properties);

        return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint.ToString(), parameters);
    }
}
