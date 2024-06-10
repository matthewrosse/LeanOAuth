using LeanOAuth.AspNetCore.Options;
using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore;

public class OAuth10AEvents : RemoteAuthenticationEvents
{
    /// <summary>
    /// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
    /// </summary>
    public Func<
        RedirectContext<OAuth10AOptions>,
        Task
    > OnRedirectToAuthorizationEndpoint { get; set; } =
        context =>
        {
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };

    /// <summary>
    /// Called when a Challenge causes a redirect to authorize endpoint in the OAuth10A handler.
    /// </summary>
    /// <param name="context">Contains redirect URI and <see cref="T:Microsoft.AspNetCore.Authentication.AuthenticationProperties" /> of the challenge.</param>
    public virtual Task RedirectToAuthorizationEndpoint(RedirectContext<OAuth10AOptions> context)
    {
        return OnRedirectToAuthorizationEndpoint(context);
    }
}
