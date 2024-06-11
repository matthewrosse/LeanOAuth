using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using LeanOAuth.AspNetCore.Events;
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
    IOAuthAuthorizationHeaderFactory<TOptions> authorizationHeaderFactory
) : RemoteAuthenticationHandler<TOptions>(options, logger, encoder)
    where TOptions : OAuth10AOptions, new()
{
    private const string StateParameterName = "state";
    private const string ErrorParameterName = "error";
    private const string ErrorAccessDenied = "access_denied";

    /// <summary>
    /// Gets the <see cref="T:System.Net.Http.HttpClient" /> instance used to communicate with the remote authentication provider.
    /// </summary>
    private HttpClient Backchannel => Options.Backchannel;

    /// <summary>
    /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
    /// If it is not provided a default instance is supplied which does nothing when the methods are called.
    /// </summary>
    private new OAuth10AEvents<TOptions> Events
    {
        get => (OAuth10AEvents<TOptions>)base.Events;
        set => base.Events = value;
    }

    /// <summary>
    /// Creates a new instance of the events instance.
    /// </summary>
    /// <returns>A new instance of the events instance.</returns>
    protected override Task<object> CreateEventsAsync() =>
        Task.FromResult<object>(new OAuth10AEvents<TOptions>());

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var query = Request.Query;

        var state = Context.Request.Cookies[StateParameterName];
        var properties = Options.StateDataFormat.Unprotect(state);

        Context.Response.Cookies.Delete(StateParameterName);

        if (properties is null)
        {
            return HandleRequestResult.Fail("The oauth state was missing or invalid");
        }

        var error = query[ErrorParameterName];

        if (!StringValues.IsNullOrEmpty(error))
        {
            // access_denied error indicates that the user didn't
            // approve the authorization demand requested by the remote authorization server
            // Since it's a frequent scenario (that is not caused by incorrect configuration),
            // denied errors are handled differently using HandleAccessDeniedErrorAsync().
            if (StringValues.Equals(error, ErrorAccessDenied))
            {
                var result = await HandleAccessDeniedErrorAsync(properties);
                if (!result.None)
                {
                    return result;
                }

                var deniedEx = new AuthenticationFailureException(
                    "Access was denied by the resource owner or by the remote server."
                );
                deniedEx.Data[ErrorParameterName] = error.ToString();

                return HandleRequestResult.Fail(deniedEx, properties);
            }

            var failureMessage = error.ToString();

            var ex = new AuthenticationFailureException(failureMessage);

            return HandleRequestResult.Fail(ex, properties);
        }

        var token = query[OAuthConstants.ParameterNames.Token];

        if (StringValues.IsNullOrEmpty(token))
        {
            return HandleRequestResult.Fail("Token was not found.", properties);
        }

        var tokenSecret = properties.Items[OAuthConstants.ParameterNames.TokenSecret];

        if (tokenSecret is null)
        {
            return HandleRequestResult.Fail("Token secret was not found.", properties);
        }

        var verifier = query[OAuthConstants.ParameterNames.Verifier];

        if (StringValues.IsNullOrEmpty(verifier))
        {
            return HandleRequestResult.Fail("Verifier was not found.", properties);
        }

        var tokenExchangeContext = new OAuth10ATokenExchangeContext(
            properties,
            token.ToString(),
            tokenSecret,
            verifier.ToString()
        );

        var accessTokenResponse = await ExchangeRequestTokenForAccessTokenAsync(
            tokenExchangeContext
        );

        var identity = new ClaimsIdentity(ClaimsIssuer);

        if (Options.SaveTokens)
        {
            var authTokens = new List<AuthenticationToken>
            {
                new() { Name = OAuthConstants.ParameterNames.Token, Value = token! },
                new() { Name = OAuthConstants.ParameterNames.TokenSecret, Value = tokenSecret }
            };

            properties.StoreTokens(authTokens);
        }

        var ticket = await CreateTicketAsync(identity, properties, accessTokenResponse);

        return HandleRequestResult.Success(ticket);
    }

    private async Task<AuthenticationTicket> CreateTicketAsync(
        ClaimsIdentity identity,
        AuthenticationProperties properties,
        AccessTokenResponse accessTokenResponse
    )
    {
        using var user = JsonDocument.Parse("{}");

        var context = new OAuth10ACreatingTicketContext<TOptions>(
            new ClaimsPrincipal(identity),
            properties,
            Context,
            Scheme,
            Options,
            Backchannel,
            authorizationHeaderFactory,
            accessTokenResponse,
            user.RootElement
        );

        await Events.CreatingTicket(context);

        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }

    private async Task<AccessTokenResponse> ExchangeRequestTokenForAccessTokenAsync(
        OAuth10ATokenExchangeContext context
    )
    {
        var authorizationHeader = authorizationHeaderFactory.CreateAccessTokenRequestHeader(
            HttpMethod.Post,
            context.Token,
            context.TokenSecret,
            context.Verifier
        );

        var requestMessage = OAuthRequestHelpers.PreparePostRequestMessage(
            Options.AccessTokenEndpoint,
            authorizationHeader
        );

        var response = await Backchannel.SendAsync(requestMessage);

        if (!response.IsSuccessStatusCode)
        {
            throw new AccessTokenRequestException(
                "Could not exchange request token for an access token. There's a possibility that the request token has expired."
            );
        }

        var accessTokenResponse = await OAuthResponseHelpers.GetAccessTokenResponseAsync(
            response.Content
        );

        return accessTokenResponse;
    }

    private async Task<UnauthorizedRequestTokenResponse> GetUnauthorizedRequestTokenResponseAsync(
        string callbackUri
    )
    {
        var scopes = string.Join(Options.ScopeParameterSeparator, Options.Scopes);

        var authorizationHeaderValue = authorizationHeaderFactory.CreateRequestTokenRequestHeader(
            HttpMethod.Post,
            new Uri(callbackUri),
            new Dictionary<string, string> { { Options.ScopeParameterName, scopes } }
        );

        var requestMessage = OAuthRequestHelpers.PreparePostRequestMessage(
            new Uri(
                $"{Options.RequestTokenEndpoint.ToString()}?{Options.ScopeParameterName}={Uri.EscapeDataString(scopes)}"
            ),
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

        var redirectContext = new RedirectContext<TOptions>(
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

        Context.Response.Cookies.Append(
            StateParameterName,
            Options.StateDataFormat.Protect(properties)
        );

        return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint.ToString(), parameters);
    }
}
