using System.Security.Claims;
using System.Text.Json;
using LeanOAuth.AspNetCore.Options;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace LeanOAuth.AspNetCore.Events;

/// <summary>
/// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity" />
/// </summary>
/// <typeparam name="TOptions">OAuth1.0A options</typeparam>
public sealed class OAuth10ACreatingTicketContext<TOptions> : ResultContext<TOptions>
    where TOptions : OAuth10AOptions
{
    /// <summary>
    /// Initializes a new <see cref="OAuth10ACreatingTicketContext{TOptions}"/>
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/>.</param>
    /// <param name="properties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="context">The HTTP environment.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="options">The options used by the authentication middleware.</param>
    /// <param name="backchannel">The HTTP client used by the authentication middleware</param>
    /// <param name="authorizationParametersFactory">The authorizationParametersFactory used to obtain parameters with valid signature.</param>
    /// <param name="accessTokenResponse">The tokens returned from the token endpoint.</param>
    /// <param name="user">The JSON-serialized user.</param>
    public OAuth10ACreatingTicketContext(
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        HttpContext context,
        AuthenticationScheme scheme,
        TOptions options,
        HttpClient backchannel,
        IOAuthAuthorizationParametersFactory authorizationParametersFactory,
        AccessTokenResponse accessTokenResponse,
        JsonElement user
    )
        : base(context, scheme, options)
    {
        ArgumentNullException.ThrowIfNull(backchannel);
        Principal = principal;
        Properties = properties;
        Backchannel = backchannel;
        AuthorizationParametersFactory = authorizationParametersFactory;
        AccessTokenResponse = accessTokenResponse;
        User = user;
    }

    /// <summary>
    /// Gets the JSON-serialized user or an empty
    /// <see cref="JsonElement"/> if it is not available.
    /// </summary>
    public JsonElement User { get; }

    /// <summary>
    /// Gets the token and tokenSecret response returned by the authenticadtion service.
    /// </summary>
    public AccessTokenResponse AccessTokenResponse { get; }

    /// <summary>
    /// The access token.
    /// </summary>
    public string Token => AccessTokenResponse.Token;

    /// <summary>
    /// The access token secret.
    /// </summary>
    public string TokenSecret => AccessTokenResponse.TokenSecret;

    /// <summary>
    /// Gets the backchannel used to communicate with the provide.r
    /// </summary>
    public HttpClient Backchannel { get; }

    /// <summary>
    /// Gets the authorization parameters factory used to obtain request parameters with valid signature.
    /// </summary>
    public IOAuthAuthorizationParametersFactory AuthorizationParametersFactory { get; }

    /// <summary>
    /// Gets the main identity exposed by the authentication ticket.
    /// </summary>
    public ClaimsIdentity? Identity => Principal?.Identity as ClaimsIdentity;

    /// <summary>
    /// Examines <see cref="User"/>, determine if the requisite data is present, and optionally add it
    /// to <see cref="Identity"/>.
    /// </summary>
    public void RunClaimActions() => RunClaimActions(User);

    /// <summary>
    /// Examines the specified <paramref name="userData"/>, determine if the requisite data is present, and optionally add it
    /// to <see cref="Identity"/>.
    /// </summary>
    public void RunClaimActions(JsonElement userData)
    {
        foreach (var action in Options.ClaimActions)
        {
            action.Run(userData, Identity!, Options.ClaimsIssuer ?? Scheme.Name);
        }
    }
}
