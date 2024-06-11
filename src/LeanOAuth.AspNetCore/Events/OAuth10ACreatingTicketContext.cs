using System.Security.Claims;
using System.Text.Json;
using LeanOAuth.AspNetCore.Options;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Responses;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace LeanOAuth.AspNetCore.Events;

public sealed class OAuth10ACreatingTicketContext<TOptions> : ResultContext<TOptions>
    where TOptions : OAuth10AOptions
{
    public OAuth10ACreatingTicketContext(
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        HttpContext context,
        AuthenticationScheme scheme,
        TOptions options,
        HttpClient backchannel,
        IOAuthAuthorizationHeaderFactory<TOptions> authorizationHeaderFactory,
        AccessTokenResponse accessTokenResponse,
        JsonElement user
    )
        : base(context, scheme, options)
    {
        ArgumentNullException.ThrowIfNull(backchannel);
        Principal = principal;
        Properties = properties;
        Backchannel = backchannel;
        AuthorizationHeaderFactory = authorizationHeaderFactory;
        AccessTokenResponse = accessTokenResponse;
        User = user;
    }

    public JsonElement User { get; }
    public AccessTokenResponse AccessTokenResponse { get; }
    public string Token => AccessTokenResponse.Token;
    public string TokenSecret => AccessTokenResponse.TokenSecret;

    public HttpClient Backchannel { get; }

    public IOAuthAuthorizationHeaderFactory<TOptions> AuthorizationHeaderFactory { get; }
    public ClaimsIdentity? Identity => Principal?.Identity as ClaimsIdentity;

    public void RunClaimActions() => RunClaimActions(User);

    public void RunClaimActions(JsonElement userData)
    {
        foreach (var action in Options.ClaimActions)
        {
            action.Run(userData, Identity!, Options.ClaimsIssuer ?? Scheme.Name);
        }
    }
}
