using System.Security.Claims;
using System.Text.Encodings.Web;
using LeanOAuth.Core.PercentEncoding;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace LeanOAuth.AspNetCore;

/// <summary>
/// Signs a resource owner in with OAuth 1.0a (RFC 5849 §2). Built entirely on the public surface
/// of <see cref="OAuthFlow"/> and the credential and token types below it: nothing here reaches
/// into an internal of a lower layer.
/// </summary>
/// <param name="options">The handler's options, monitored for changes.</param>
/// <param name="logger">The logger factory used to create the handler's logger.</param>
/// <param name="encoder">The URL encoder used when building redirect URIs.</param>
public sealed class OAuth10AHandler(
    IOptionsMonitor<OAuth10AOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder
) : RemoteAuthenticationHandler<OAuth10AOptions>(options, logger, encoder)
{
    private const string TokenItemKey = "LeanOAuth.Token";
    private const string TokenSecretItemKey = "LeanOAuth.TokenSecret";
    private const string OAuthTokenParameterName = "oauth_token";
    private const string OAuthVerifierParameterName = "oauth_verifier";
    private const string ErrorParameterName = "error";
    private const string AccessDeniedError = "access_denied";

    private new OAuth10AEvents Events
    {
        get => (OAuth10AEvents)base.Events;
        set => base.Events = value;
    }

    /// <summary>
    /// Scoped by scheme name, so two <c>AddOAuth10A</c> registrations in the same application
    /// never share a state cookie.
    /// </summary>
    private string StateCookieName => $"LeanOAuth.State.{Scheme.Name}";

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        ArgumentNullException.ThrowIfNull(properties);

        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;
        }

        var callbackUri = BuildRedirectUri(Options.CallbackPath);
        var flow = CreateFlow();

        Log.RequestingTemporaryCredentials(Logger, Scheme.Name);

        var temporaryCredentials = await flow.RequestTemporaryCredentialsAsync(
                OAuthCallback.For(new Uri(callbackUri)),
                Context.RequestAborted
            )
            .ConfigureAwait(false);

        properties.Items[TokenItemKey] = temporaryCredentials.Token;
        properties.Items[TokenSecretItemKey] = temporaryCredentials.TokenSecret;

        var cookieOptions = Options.CorrelationCookie.Build(Context, TimeProvider.System.GetUtcNow());
        Response.Cookies.Append(
            StateCookieName,
            Options.StateDataFormat.Protect(properties),
            cookieOptions
        );

        var redirectUri = flow.BuildAuthorizationUri(temporaryCredentials).ToString();
        var redirectContext = new RedirectContext<OAuth10AOptions>(
            Context,
            Scheme,
            Options,
            properties,
            redirectUri
        );

        Log.RedirectingToAuthorizationEndpoint(Logger, Scheme.Name);

        await Events.RedirectToAuthorizationEndpoint(redirectContext).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        var stateCookie = Request.Cookies[StateCookieName];
        var deleteCookieOptions = Options.CorrelationCookie.Build(Context, TimeProvider.System.GetUtcNow());
        Response.Cookies.Delete(StateCookieName, deleteCookieOptions);

        if (string.IsNullOrEmpty(stateCookie))
        {
            return HandleRequestResult.Fail("The oauth state cookie was missing.");
        }

        var properties = Options.StateDataFormat.Unprotect(stateCookie);
        if (properties is null)
        {
            return HandleRequestResult.Fail("The oauth state cookie could not be unprotected.");
        }

        var query = Request.Query;
        var error = query[ErrorParameterName];
        if (!StringValues.IsNullOrEmpty(error))
        {
            if (StringValues.Equals(error, AccessDeniedError))
            {
                var deniedResult = await HandleAccessDeniedErrorAsync(properties)
                    .ConfigureAwait(false);
                if (!deniedResult.None)
                {
                    return deniedResult;
                }

                return HandleRequestResult.Fail(
                    new AuthenticationFailureException(
                        "Access was denied by the resource owner or by the remote server."
                    ),
                    properties
                );
            }

            return HandleRequestResult.Fail(
                new AuthenticationFailureException(error.ToString()),
                properties
            );
        }

        if (
            !properties.Items.TryGetValue(TokenItemKey, out var expectedToken)
            || expectedToken is null
        )
        {
            return HandleRequestResult.Fail("The oauth state is missing the temporary credential token.", properties);
        }

        if (
            !properties.Items.TryGetValue(TokenSecretItemKey, out var tokenSecret)
            || tokenSecret is null
        )
        {
            return HandleRequestResult.Fail(
                "The oauth state is missing the temporary credential token secret.",
                properties
            );
        }

        var token = query[OAuthTokenParameterName];
        if (
            StringValues.IsNullOrEmpty(token)
            || !string.Equals(token, expectedToken, StringComparison.Ordinal)
        )
        {
            return HandleRequestResult.Fail(
                "The 'oauth_token' on the callback did not match the temporary credentials requested for this sign-in attempt.",
                properties
            );
        }

        var verifier = query[OAuthVerifierParameterName];
        if (StringValues.IsNullOrEmpty(verifier))
        {
            return HandleRequestResult.Fail("The 'oauth_verifier' was missing from the callback.", properties);
        }

        var temporaryCredentials = new TemporaryCredentials(
            token.ToString(),
            tokenSecret,
            CallbackConfirmed: true
        );

        TokenCredentials tokenCredentials;
        try
        {
            var flow = CreateFlow();
            tokenCredentials = await flow.ExchangeAsync(
                    temporaryCredentials,
                    verifier.ToString(),
                    Context.RequestAborted
                )
                .ConfigureAwait(false);
        }
        catch (OAuthException ex)
        {
            Log.TokenExchangeFailed(Logger, Scheme.Name);
            return HandleRequestResult.Fail(ex, properties);
        }

        if (Options.SaveTokens)
        {
            properties.StoreTokens(
                [
                    new AuthenticationToken { Name = "access_token", Value = tokenCredentials.Token },
                    new AuthenticationToken
                    {
                        Name = "access_token_secret",
                        Value = tokenCredentials.TokenSecret,
                    },
                ]
            );
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(ClaimsIssuer));
        var ticketContext = new OAuth10ACreatingTicketContext(
            Context,
            Scheme,
            Options,
            principal,
            properties,
            Options.Backchannel,
            Options.ClientCredentials,
            tokenCredentials
        );

        await Events.CreatingTicket(ticketContext).ConfigureAwait(false);

        Log.SignInSucceeded(Logger, Scheme.Name);

        var ticket = new AuthenticationTicket(
            ticketContext.Principal!,
            ticketContext.Properties,
            Scheme.Name
        );

        return HandleRequestResult.Success(ticket);
    }

    private OAuthFlow CreateFlow()
    {
        var endpoints = Options.Endpoints;

        if (Options.Scopes.Count > 0)
        {
            var scopeValue = string.Join(Options.ScopeParameterSeparator, Options.Scopes);
            var separator = endpoints.TemporaryCredentialRequest.Query.Length > 0 ? "&" : "?";
            var uri = new Uri(
                $"{endpoints.TemporaryCredentialRequest}{separator}{Options.ScopeParameterName}={PercentEncoder.Encode(scopeValue)}"
            );
            endpoints = endpoints with { TemporaryCredentialRequest = uri };
        }

        return new OAuthFlow(
            Options.Backchannel,
            endpoints,
            Options.ClientCredentials,
            options: new OAuthFlowOptions { Realm = Options.Realm }
        );
    }
}
