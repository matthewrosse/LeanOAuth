using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore;

/// <summary>Events raised by the OAuth 1.0a sign-in handler.</summary>
public sealed class OAuth10AEvents : RemoteAuthenticationEvents
{
    /// <summary>Invoked when the handler is about to redirect to the authorization endpoint.</summary>
    public Func<RedirectContext<OAuth10AOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } =
        context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

    /// <summary>Invoked after the provider's verifier has been exchanged for token credentials.</summary>
    public Func<OAuth10ACreatingTicketContext, Task> OnCreatingTicket { get; set; } =
        _ => Task.CompletedTask;

    /// <summary>Called when a challenge redirects to the authorization endpoint.</summary>
    public Task RedirectToAuthorizationEndpoint(RedirectContext<OAuth10AOptions> context) =>
        OnRedirectToAuthorizationEndpoint(context);

    /// <summary>Called after the provider's verifier has been exchanged for token credentials.</summary>
    public Task CreatingTicket(OAuth10ACreatingTicketContext context) => OnCreatingTicket(context);
}
