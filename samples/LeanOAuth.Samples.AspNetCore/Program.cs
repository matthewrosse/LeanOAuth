// Demonstrates "sign in with OAuth 1.0a" using LeanOAuth.AspNetCore. Provider-neutral: every
// provider-specific value (endpoints, consumer key/secret) comes from configuration, not code.
// Fill them in with `dotnet user-secrets set OAuth10A:ConsumerKey ...` (see README.md).

using System.Security.Claims;
using LeanOAuth.AspNetCore;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

var providerConfig = builder.Configuration.GetSection("OAuth10A");
var consumerKey = RequireConfig(providerConfig, "ConsumerKey");
var consumerSecret = RequireConfig(providerConfig, "ConsumerSecret");
var temporaryCredentialRequestUri = RequireConfig(providerConfig, "TemporaryCredentialRequestUri");
var resourceOwnerAuthorizationUri = RequireConfig(providerConfig, "ResourceOwnerAuthorizationUri");
var tokenRequestUri = RequireConfig(providerConfig, "TokenRequestUri");

builder
    .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOAuth10A(
        "oauth1a",
        options =>
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.ClientCredentials = new HmacSha1ClientCredentials(consumerKey, consumerSecret);
            options.Endpoints = new OAuthProviderEndpoints(
                new Uri(temporaryCredentialRequestUri),
                new Uri(resourceOwnerAuthorizationUri),
                new Uri(tokenRequestUri)
            );
            options.CallbackPath = "/signin-oauth1a";
        }
    );

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet(
    "/",
    (HttpContext context) =>
        context.User.Identity?.IsAuthenticated == true
            ? Results.Redirect("/account")
            : Results.Content(
                """<a href="/signin">Sign in</a>""",
                "text/html"
            )
);

app.MapGet(
    "/signin",
    () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/account" }, ["oauth1a"])
);

app.MapGet(
    "/account",
    (ClaimsPrincipal user) =>
    {
        if (user.Identity?.IsAuthenticated != true)
        {
            return Results.Redirect("/");
        }

        var claims = user.Claims.Select(c => $"{c.Type}: {c.Value}");
        return Results.Content(
            $"""<p>Signed in.</p><pre>{string.Join('\n', claims)}</pre><a href="/signout">Sign out</a>""",
            "text/html"
        );
    }
).RequireAuthorization();

app.MapGet(
    "/signout",
    async (HttpContext context) =>
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.Redirect("/");
    }
);

app.Run();

static string RequireConfig(IConfigurationSection section, string key)
{
    var value = section[key];
    if (string.IsNullOrWhiteSpace(value))
    {
        throw new InvalidOperationException(
            $"Configuration 'OAuth10A:{key}' is missing. Set it with "
                + $"'dotnet user-secrets set OAuth10A:{key} <value>' — see README.md."
        );
    }

    return value;
}
