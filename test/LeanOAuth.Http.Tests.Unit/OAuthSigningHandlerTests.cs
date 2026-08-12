using System.Net;
using System.Net.Http.Headers;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http.Tests.Unit.Testing;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;

namespace LeanOAuth.Http.Tests.Unit;

public class OAuthSigningHandlerTests
{
    private static readonly HmacSha1ClientCredentials Credentials = new(
        "consumer-key",
        "consumer-secret"
    );

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static OAuthSigner CreateSigner(string nonce = "fixednonce") =>
        new(
            new OAuthSigningOptions
            {
                Clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds(1191242096)),
                NonceGenerator = new FixedNonceGenerator(nonce),
            }
        );

    private static HttpClient CreateClient(
        OAuthSigningHandler handler,
        StubHttpMessageHandler stub
    )
    {
        handler.InnerHandler = stub;
        return new HttpClient(handler);
    }

    [Fact]
    public async Task SendAsync_SignsEveryOutboundRequest()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var handler = new OAuthSigningHandler(Credentials, signer: CreateSigner());
        using var client = CreateClient(handler, stub);

        await client.GetAsync(new Uri("http://example.com/resource"), Ct);

        stub.LastRequest!.Headers.Contains("Authorization").ShouldBeTrue();
    }

    [Fact]
    public async Task SendAsync_UsesTheDefaultTokenWhenNoPerRequestOverrideIsSupplied()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var handler = new OAuthSigningHandler(
            Credentials,
            new OAuthToken("default-token", "default-secret"),
            CreateSigner()
        );
        using var client = CreateClient(handler, stub);

        await client.GetAsync(new Uri("http://example.com/resource"), Ct);

        stub.LastRequest!
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldContain("oauth_token=\"default-token\"");
    }

    [Fact]
    public async Task SendAsync_PerRequestTokenOverridesTheDefault()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var handler = new OAuthSigningHandler(
            Credentials,
            new OAuthToken("default-token", "default-secret"),
            CreateSigner()
        );
        using var client = CreateClient(handler, stub);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource")
            .WithOAuthToken(new OAuthToken("override-token", "override-secret"));

        await client.SendAsync(request, Ct);

        stub.LastRequest!
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldContain("oauth_token=\"override-token\"");
    }

    [Fact]
    public async Task SendAsync_ThrowsWhenTheRequestAlreadyHasAnAuthorizationHeader()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var handler = new OAuthSigningHandler(Credentials, signer: CreateSigner());
        using var client = CreateClient(handler, stub);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "some-token");

        await Should.ThrowAsync<InvalidOperationException>(() => client.SendAsync(request, Ct));
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.SeeOther)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    [InlineData(HttpStatusCode.PermanentRedirect)]
    public async Task SendAsync_ThrowsOnAnUnexpectedRedirectResponse(HttpStatusCode statusCode)
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(statusCode));
        var handler = new OAuthSigningHandler(Credentials, signer: CreateSigner());
        using var client = CreateClient(handler, stub);

        await Should.ThrowAsync<InvalidOperationException>(
            () => client.GetAsync(new Uri("http://example.com/resource"), Ct)
        );
    }

    [Fact]
    public void Send_SynchronousSendIsNotSupported()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var handler = new OAuthSigningHandler(Credentials, signer: CreateSigner())
        {
            InnerHandler = stub,
        };
        using var invoker = new HttpMessageInvoker(handler);
        var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");

        Should.Throw<NotSupportedException>(() => invoker.Send(request, CancellationToken.None));
    }

    [Fact]
    public async Task SendAsync_ComposesWithTheStandardHttpClientFactoryRegistrationPattern()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var services = new ServiceCollection();
        services
            .AddHttpClient("provider")
            .AddHttpMessageHandler(() => new OAuthSigningHandler(Credentials, signer: CreateSigner()))
            .ConfigurePrimaryHttpMessageHandler(() => stub);

        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("provider");

        await client.GetAsync(new Uri("http://example.com/resource"), Ct);

        stub.LastRequest!.Headers.Contains("Authorization").ShouldBeTrue();
    }
}
