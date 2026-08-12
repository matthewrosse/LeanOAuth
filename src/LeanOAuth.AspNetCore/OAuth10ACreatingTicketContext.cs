using System.Security.Claims;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace LeanOAuth.AspNetCore;

/// <summary>
/// Raised after the handler has exchanged the verifier for token credentials and built the
/// principal, but before the ticket is issued. RFC 5849 defines no standard profile endpoint, so
/// this does not fetch or expose provider profile data itself: a consumer that needs it signs its
/// own request against <see cref="Backchannel"/>, using <see cref="ClientCredentials"/> and
/// <see cref="TokenCredentials"/> with the same public surface any headless caller uses.
/// </summary>
public sealed class OAuth10ACreatingTicketContext : ResultContext<OAuth10AOptions>
{
    /// <summary>Creates the context passed to <see cref="OAuth10AEvents.OnCreatingTicket"/>.</summary>
    public OAuth10ACreatingTicketContext(
        HttpContext context,
        AuthenticationScheme scheme,
        OAuth10AOptions options,
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        HttpClient backchannel,
        ClientCredentials clientCredentials,
        TokenCredentials tokenCredentials
    )
        : base(context, scheme, options)
    {
        ArgumentNullException.ThrowIfNull(backchannel);
        ArgumentNullException.ThrowIfNull(clientCredentials);
        ArgumentNullException.ThrowIfNull(tokenCredentials);

        Principal = principal;
        Properties = properties;
        Backchannel = backchannel;
        ClientCredentials = clientCredentials;
        TokenCredentials = tokenCredentials;
    }

    /// <summary>The backchannel HTTP client used to talk to the provider.</summary>
    public HttpClient Backchannel { get; }

    /// <summary>The client credentials the sign-in flow used.</summary>
    public ClientCredentials ClientCredentials { get; }

    /// <summary>The token credentials obtained from the provider.</summary>
    public TokenCredentials TokenCredentials { get; }

    /// <summary>The identity a consumer adds claims to.</summary>
    public ClaimsIdentity? Identity => Principal?.Identity as ClaimsIdentity;
}
