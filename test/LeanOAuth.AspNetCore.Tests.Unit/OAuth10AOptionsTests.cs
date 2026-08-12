using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
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
}
