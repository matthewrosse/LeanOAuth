using System.Net;
using System.Security.Claims;
using System.Web;
using LeanOAuth.AspNetCore.Tests.Unit.Testing;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;

namespace LeanOAuth.AspNetCore.Tests.Unit;

public sealed class OAuth10ASignInTests
{
    private static readonly Uri TemporaryCredentialRequest = new(
        "https://provider.example/oauth/request_token"
    );
    private static readonly Uri ResourceOwnerAuthorization = new(
        "https://provider.example/oauth/authorize"
    );
    private static readonly Uri TokenRequest = new("https://provider.example/oauth/access_token");

    [Fact]
    public async Task Challenge_redirects_to_the_authorization_endpoint_with_the_temporary_token()
    {
        using var backchannel = new HttpClient(
            new StubHttpMessageHandler(_ =>
                FormResponse("oauth_token=temp-token&oauth_token_secret=temp-secret&oauth_callback_confirmed=true")
            )
        );
        using var host = await BuildHostAsync(backchannel);
        using var client = host.GetTestClient();

        using var response = await client.GetAsync("/login", TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Found);
        var location = response.Headers.Location.ShouldNotBeNull();
        location.GetLeftPart(UriPartial.Path).ShouldBe(ResourceOwnerAuthorization.ToString());
        HttpUtility.ParseQueryString(location.Query)["oauth_token"].ShouldBe("temp-token");
        response.Headers.TryGetValues("Set-Cookie", out _).ShouldBeTrue();
    }

    [Fact]
    public async Task Callback_completes_sign_in_and_exposes_token_credentials_to_the_creating_ticket_event()
    {
        using var backchannel = new HttpClient(
            new StubHttpMessageHandler(request =>
                request.RequestUri!.GetLeftPart(UriPartial.Path) == TemporaryCredentialRequest.ToString()
                    ? FormResponse(
                        "oauth_token=temp-token&oauth_token_secret=temp-secret&oauth_callback_confirmed=true"
                    )
                    : FormResponse("oauth_token=final-token&oauth_token_secret=final-secret")
            )
        );
        using var host = await BuildHostAsync(backchannel);
        using var client = host.GetTestClient();

        using var challengeResponse = await client.GetAsync(
            "/login",
            TestContext.Current.CancellationToken
        );
        var stateCookie = ExtractCookie(challengeResponse, "LeanOAuth.State.oauth10a");

        using var callbackRequest = new HttpRequestMessage(
            HttpMethod.Get,
            "/signin-oauth10a?oauth_token=temp-token&oauth_verifier=verifier-123"
        );
        callbackRequest.Headers.Add("Cookie", stateCookie);
        using var callbackResponse = await client.SendAsync(
            callbackRequest,
            TestContext.Current.CancellationToken
        );

        callbackResponse.StatusCode.ShouldBe(HttpStatusCode.Found);
        var authCookie = ExtractCookie(callbackResponse, ".AspNetCore.Cookies");

        using var whoAmIRequest = new HttpRequestMessage(HttpMethod.Get, "/whoami");
        whoAmIRequest.Headers.Add("Cookie", authCookie);
        using var whoAmIResponse = await client.SendAsync(
            whoAmIRequest,
            TestContext.Current.CancellationToken
        );

        var body = await whoAmIResponse.Content.ReadAsStringAsync(
            TestContext.Current.CancellationToken
        );
        body.ShouldBe("token:final-token;secret:final-secret");
    }

    private static async Task<IHost> BuildHostAsync(HttpClient backchannel) =>
        await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services
                            .AddAuthentication(options =>
                            {
                                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                options.DefaultChallengeScheme = "oauth10a";
                            })
                            .AddCookie()
                            .AddOAuth10A(
                                "oauth10a",
                                options =>
                                {
                                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                                    options.CallbackPath = "/signin-oauth10a";
                                    options.ClientCredentials = new HmacSha1ClientCredentials(
                                        "consumer-key",
                                        "consumer-secret"
                                    );
                                    options.Endpoints = new OAuthProviderEndpoints(
                                        TemporaryCredentialRequest,
                                        ResourceOwnerAuthorization,
                                        TokenRequest
                                    );
                                    options.Backchannel = backchannel;
                                    options.Events.OnCreatingTicket = context =>
                                    {
                                        context.Identity!.AddClaim(
                                            new Claim("token", context.TokenCredentials.Token)
                                        );
                                        context.Identity.AddClaim(
                                            new Claim("secret", context.TokenCredentials.TokenSecret)
                                        );
                                        return Task.CompletedTask;
                                    };
                                }
                            );
                    })
                    .Configure(app =>
                    {
                        app.UseAuthentication();
                        app.Run(async ctx =>
                        {
                            if (ctx.Request.Path == "/login")
                            {
                                await ctx.ChallengeAsync("oauth10a");
                                return;
                            }

                            if (ctx.Request.Path == "/whoami")
                            {
                                var token = ctx.User.FindFirst("token")?.Value;
                                var secret = ctx.User.FindFirst("secret")?.Value;
                                await ctx.Response.WriteAsync($"token:{token};secret:{secret}");
                                return;
                            }

                            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
                        });
                    })
            )
            .StartAsync();

    private static HttpResponseMessage FormResponse(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body) };

    private static string ExtractCookie(HttpResponseMessage response, string name)
    {
        var setCookie = response
            .Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith(name + "=", StringComparison.Ordinal));
        return setCookie[..setCookie.IndexOf(';')];
    }
}
