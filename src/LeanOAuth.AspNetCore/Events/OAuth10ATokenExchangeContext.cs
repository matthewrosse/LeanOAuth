using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore.Events;

/// <summary>
/// Contains information used to perform the access token exchange.
/// </summary>
/// <param name="Properties">The <see cref="AuthenticationProperties"/>.</param>
/// <param name="Token">The access token.</param>
/// <param name="TokenSecret">The access token secret.</param>
/// <param name="Verifier">The code verifier.</param>
public record OAuth10ATokenExchangeContext(
    AuthenticationProperties Properties,
    string Token,
    string TokenSecret,
    string Verifier
);
