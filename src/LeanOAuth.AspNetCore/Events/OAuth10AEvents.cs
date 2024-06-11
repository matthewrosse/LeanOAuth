using LeanOAuth.AspNetCore.Options;
using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore.Events;

public class OAuth10AEvents<TOptions> : RemoteAuthenticationEvents
    where TOptions : OAuth10AOptions
{
    /// <summary>
    /// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
    /// </summary>
    public Func<RedirectContext<TOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } =
        context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

    /// <summary>
    /// Called when a Challenge causes a redirect to authorize endpoint in the OAuth10A handler.
    /// </summary>
    /// <param name="context">Contains redirect URI and <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" /> of the challenge.</param>
    public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<TOptions> context)
    {
        return OnRedirectToAuthorizationEndpoint(context);
    }

    public Func<OAuth10ACreatingTicketContext<TOptions>, Task> OnCreatingTicket { get; set; } =
        context => Task.CompletedTask;

    public virtual Task CreatingTicket(OAuth10ACreatingTicketContext<TOptions> context) =>
        OnCreatingTicket(context);
}
