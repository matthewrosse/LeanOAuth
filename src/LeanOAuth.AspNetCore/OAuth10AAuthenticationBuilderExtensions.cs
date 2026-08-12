using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace LeanOAuth.AspNetCore;

/// <summary>Registers OAuth 1.0a sign-in with ASP.NET Core authentication.</summary>
public static class OAuth10AAuthenticationBuilderExtensions
{
    /// <summary>Registers the OAuth 1.0a scheme, its options, and its handler.</summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="authenticationScheme">The scheme name.</param>
    /// <param name="configureOptions">Configures <see cref="OAuth10AOptions"/>.</param>
    public static AuthenticationBuilder AddOAuth10A(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<OAuth10AOptions> configureOptions
    )
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IPostConfigureOptions<OAuth10AOptions>,
                OAuth10APostConfigureOptions
            >()
        );

        return builder.AddRemoteScheme<OAuth10AOptions, OAuth10AHandler>(
            authenticationScheme,
            displayName: "OAuth 1.0a",
            configureOptions
        );
    }
}
