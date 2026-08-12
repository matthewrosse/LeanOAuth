using System.Net.Http;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Shouldly;

namespace LeanOAuth.AspNetCore.Tests.Unit;

public sealed class OAuth10AOptionsTests
{
    private static readonly OAuthProviderEndpoints Endpoints = new(
        new Uri("https://provider.example/oauth/request_token"),
        new Uri("https://provider.example/oauth/authorize"),
        new Uri("https://provider.example/oauth/access_token")
    );

    private static readonly ClientCredentials Credentials = new HmacSha1ClientCredentials(
        "consumer-key",
        "consumer-secret"
    );

    [Fact]
    public void Validate_throws_when_client_credentials_are_missing()
    {
        var options = new OAuth10AOptions { Endpoints = Endpoints, CallbackPath = "/signin-oauth10a" };

        Should.Throw<ArgumentNullException>(options.Validate);
    }

    [Fact]
    public void Validate_throws_when_endpoints_are_missing()
    {
        var options = new OAuth10AOptions
        {
            ClientCredentials = Credentials,
            CallbackPath = "/signin-oauth10a",
        };

        Should.Throw<ArgumentNullException>(options.Validate);
    }

    [Fact]
    public void Validate_succeeds_without_realm_or_scope_parameter_name()
    {
        var options = new OAuth10AOptions
        {
            ClientCredentials = Credentials,
            Endpoints = Endpoints,
            CallbackPath = "/signin-oauth10a",
        };

        Should.NotThrow(options.Validate);
        options.Realm.ShouldBeNull();
    }

    [Fact]
    public void PostConfigure_builds_a_default_backchannel_that_does_not_follow_redirects()
    {
        var services = new ServiceCollection();
        services.AddDataProtection();
        services
            .AddAuthentication()
            .AddCookie()
            .AddOAuth10A(
                "oauth10a",
                options =>
                {
                    options.ClientCredentials = Credentials;
                    options.Endpoints = Endpoints;
                    options.CallbackPath = "/signin-oauth10a";
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                }
            );

        using var provider = services.BuildServiceProvider();
        var options = provider
            .GetRequiredService<IOptionsMonitor<OAuth10AOptions>>()
            .Get("oauth10a");

        options.BackchannelHttpHandler.ShouldBeOfType<HttpClientHandler>();
        ((HttpClientHandler)options.BackchannelHttpHandler!).AllowAutoRedirect.ShouldBeFalse();
    }

    [Fact]
    public void PostConfigure_leavesACallerSuppliedBackchannelHandlersRedirectBehaviorAlone()
    {
        var suppliedHandler = new HttpClientHandler { AllowAutoRedirect = true };
        var services = new ServiceCollection();
        services.AddDataProtection();
        services
            .AddAuthentication()
            .AddCookie()
            .AddOAuth10A(
                "oauth10a",
                options =>
                {
                    options.ClientCredentials = Credentials;
                    options.Endpoints = Endpoints;
                    options.CallbackPath = "/signin-oauth10a";
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.BackchannelHttpHandler = suppliedHandler;
                }
            );

        using var provider = services.BuildServiceProvider();
        var options = provider
            .GetRequiredService<IOptionsMonitor<OAuth10AOptions>>()
            .Get("oauth10a");

        options.BackchannelHttpHandler.ShouldBeSameAs(suppliedHandler);
        suppliedHandler.AllowAutoRedirect.ShouldBeTrue();
    }
}
