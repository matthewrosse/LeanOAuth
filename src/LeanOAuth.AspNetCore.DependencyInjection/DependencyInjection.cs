using LeanOAuth.AspNetCore.Options;
using LeanOAuth.Core;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Signatures;
using LeanOAuth.Core.Signatures.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace LeanOAuth.AspNetCore.DependencyInjection;

public static class DependencyInjection
{
    public static AuthenticationBuilder AddOAuth10A(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<OAuth10AOptions> configureOptions
    ) =>
        builder.AddOAuth10A<OAuth10AOptions, OAuth10AHandler<OAuth10AOptions>>(
            authenticationScheme,
            "OAuth1.0A",
            configureOptions
        );

    public static AuthenticationBuilder AddOAuth10A(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string displayName,
        Action<OAuth10AOptions> configureOptions
    ) =>
        builder.AddOAuth10A<OAuth10AOptions, OAuth10AHandler<OAuth10AOptions>>(
            authenticationScheme,
            displayName,
            configureOptions
        );

    public static AuthenticationBuilder AddOAuth10A<TOptions, THandler>(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<TOptions> configureOptions
    )
        where TOptions : OAuth10AOptions, new()
        where THandler : OAuth10AHandler<TOptions> =>
        builder.AddOAuth10A<TOptions, THandler>(
            authenticationScheme,
            "OAuth1.0A",
            configureOptions
        );

    public static AuthenticationBuilder AddOAuth10A<TOptions, THandler>(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string displayName,
        Action<TOptions> configureOptions
    )
        where TOptions : OAuth10AOptions, new()
        where THandler : OAuth10AHandler<TOptions>
    {
        builder
            .Services.AddTransient<INonceGenerator, CryptographicallySecureNonceGenerator>()
            .AddTransient<OAuthSignatureCalculator, OAuthHmacSha1SignatureCalculator>()
            .AddSingleton(TimeProvider.System)
            .AddScoped<
                IOAuthAuthorizationParametersFactory,
                OAuthAuthorizationParametersFactory<TOptions>
            >(sp =>
            {
                var optionsMonitor = sp.GetRequiredService<IOptionsMonitor<TOptions>>();
                var options = optionsMonitor.Get(authenticationScheme);
                var nonceGenerator = sp.GetRequiredService<INonceGenerator>();
                var signatureCalculator = sp.GetRequiredService<OAuthSignatureCalculator>();
                var timeProvider = sp.GetRequiredService<TimeProvider>();

                return new OAuthAuthorizationParametersFactory<TOptions>(
                    options,
                    signatureCalculator,
                    timeProvider,
                    nonceGenerator
                );
            })
            .TryAddEnumerable(
                ServiceDescriptor.Singleton<
                    IPostConfigureOptions<TOptions>,
                    OAuth10APostConfigureOptions<TOptions, THandler>
                >()
            );

        return builder.AddRemoteScheme<TOptions, THandler>(
            authenticationScheme,
            displayName,
            configureOptions
        );
    }
}
