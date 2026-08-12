using System.Net;
using System.Net.Http.Headers;
using System.Text;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Http.Tests.Unit;

public class HttpRequestMessageSigningExtensionsTests
{
    private static readonly HmacSha1ClientCredentials Credentials = new(
        "consumer-key",
        "consumer-secret"
    );

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static OAuthSigner CreateSigner(string nonce = "fixednonce", long timestamp = 1191242096) =>
        new(
            new OAuthSigningOptions
            {
                Clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds(timestamp)),
                NonceGenerator = new FixedNonceGenerator(nonce),
            }
        );

    [Fact]
    public async Task SignAsync_AttachesAuthorizationHeader()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");

        await request.SignAsync(Credentials, null, CreateSigner(), Ct);

        request.Headers.Contains("Authorization").ShouldBeTrue();
        request.Headers.GetValues("Authorization").Single().ShouldStartWith("OAuth ");
    }

    [Fact]
    public async Task SignAsync_ThrowsWhenRequestAlreadyHasAnAuthorizationHeader()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "some-token");

        await Should.ThrowAsync<InvalidOperationException>(
            () => request.SignAsync(Credentials, null, CreateSigner(), Ct)
        );
    }

    [Fact]
    public async Task SignAsync_FormEncodedBodyParametersParticipateInTheSignature()
    {
        var withBody = new HttpRequestMessage(HttpMethod.Post, "http://example.com/resource")
        {
            Content = new FormUrlEncodedContent(
                [new KeyValuePair<string, string>("a", "1")]
            ),
        };
        var withoutBody = new HttpRequestMessage(HttpMethod.Post, "http://example.com/resource");

        await withBody.SignAsync(Credentials, null, CreateSigner(), Ct);
        await withoutBody.SignAsync(Credentials, null, CreateSigner(), Ct);

        withBody
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldNotBe(withoutBody.Headers.GetValues("Authorization").Single());
    }

    [Fact]
    public async Task SignAsync_FormEncodedBodyRemainsReadableAndSendableAfterSigning()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "http://example.com/resource")
        {
            Content = new FormUrlEncodedContent(
                [
                    new KeyValuePair<string, string>("a", "1"),
                    new KeyValuePair<string, string>("b", "2"),
                ]
            ),
        };

        await request.SignAsync(Credentials, null, CreateSigner(), Ct);

        var bodyAfterSigning = await request.Content!.ReadAsStringAsync(Ct);
        bodyAfterSigning.ShouldBe("a=1&b=2");

        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(stub);
        await client.SendAsync(request, Ct);

        var bodyOnTheWire = await stub.LastRequest!.Content!.ReadAsStringAsync(Ct);
        bodyOnTheWire.ShouldBe("a=1&b=2");
    }

    [Fact]
    public async Task SignAsync_JsonBodyDoesNotParticipateInTheSignature()
    {
        var withJsonBody = new HttpRequestMessage(HttpMethod.Post, "http://example.com/resource")
        {
            Content = new StringContent("{\"a\":1}", Encoding.UTF8, "application/json"),
        };
        var withoutBody = new HttpRequestMessage(HttpMethod.Post, "http://example.com/resource");

        await withJsonBody.SignAsync(Credentials, null, CreateSigner(), Ct);
        await withoutBody.SignAsync(Credentials, null, CreateSigner(), Ct);

        withJsonBody
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldBe(withoutBody.Headers.GetValues("Authorization").Single());
    }

    [Fact]
    public async Task SignAsync_NeverReadsANonFormStreamingBody()
    {
        var counting = new CountingStream(new MemoryStream(Encoding.UTF8.GetBytes("{\"a\":1}")));
        var request = new HttpRequestMessage(HttpMethod.Post, "http://example.com/resource")
        {
            Content = new StreamContent(counting)
            {
                Headers = { ContentType = new MediaTypeHeaderValue("application/json") },
            },
        };

        await request.SignAsync(Credentials, null, CreateSigner(), Ct);

        counting.TotalBytesRead.ShouldBe(0L);
    }

    [Fact]
    public async Task SignAsync_ProducesADifferentNonceForEachRequest()
    {
        var signer = new OAuthSigner();
        var request1 = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");
        var request2 = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");

        await request1.SignAsync(Credentials, null, signer, Ct);
        await request2.SignAsync(Credentials, null, signer, Ct);

        request1
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldNotBe(request2.Headers.GetValues("Authorization").Single());
    }

    [Fact]
    public async Task SignAsync_ProducesADifferentTimestamp_WhenTheClockHasAdvanced()
    {
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds(1000));
        var signer = new OAuthSigner(
            new OAuthSigningOptions { Clock = clock, NonceGenerator = new FixedNonceGenerator("n") }
        );
        var request1 = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");
        await request1.SignAsync(Credentials, null, signer, Ct);

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(2000);
        var request2 = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");
        await request2.SignAsync(Credentials, null, signer, Ct);

        request1.Headers.GetValues("Authorization").Single().ShouldContain("oauth_timestamp=\"1000\"");
        request2.Headers.GetValues("Authorization").Single().ShouldContain("oauth_timestamp=\"2000\"");
    }

    [Fact]
    public void WithOAuthToken_SetsThePerRequestOptionOverride()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "http://example.com/resource");
        var token = new OAuthToken("token", "token-secret");

        request.WithOAuthToken(token);

        request.Options.TryGetValue(OAuthSigningHandler.TokenKey, out var stored).ShouldBeTrue();
        stored.ShouldBe(token);
    }
}
