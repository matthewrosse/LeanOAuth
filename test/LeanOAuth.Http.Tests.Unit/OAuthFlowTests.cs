using System.Net;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Http.Tests.Unit;

public class OAuthFlowTests
{
    private static readonly HmacSha1ClientCredentials Credentials = new(
        "consumer-key",
        "consumer-secret"
    );

    private static readonly OAuthProviderEndpoints Endpoints = new(
        new Uri("http://example.com/oauth/request_token"),
        new Uri("http://example.com/oauth/authorize"),
        new Uri("http://example.com/oauth/access_token")
    );

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static OAuthSigner CreateSigner() =>
        new(
            new OAuthSigningOptions
            {
                Clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds(1191242096)),
                NonceGenerator = new FixedNonceGenerator("fixednonce"),
            }
        );

    private static OAuthFlow CreateFlow(
        StubHttpMessageHandler stub,
        OAuthFlowOptions? options = null
    ) => new(new HttpClient(stub), Endpoints, Credentials, CreateSigner(), options);

    private static HttpResponseMessage FormResponse(
        string body,
        string mediaType = "application/x-www-form-urlencoded"
    ) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, mediaType),
        };

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_ReturnsCredentials_WhenCallbackIsConfirmed()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_token=temp-token&oauth_token_secret=temp-secret&oauth_callback_confirmed=true")
        );
        var flow = CreateFlow(stub);

        var result = await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct);

        result.Token.ShouldBe("temp-token");
        result.TokenSecret.ShouldBe("temp-secret");
        result.CallbackConfirmed.ShouldBeTrue();
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_SendsTheLiteralOobValue_ForOutOfBandCallback()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=true")
        );
        var flow = CreateFlow(stub);

        await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct);

        stub.LastRequest!
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldContain("oauth_callback=\"oob\"");
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_SendsTheCallbackUri_ForAUriCallback()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=true")
        );
        var flow = CreateFlow(stub);
        var callbackUri = new Uri("https://client.example/callback");

        await flow.RequestTemporaryCredentialsAsync(OAuthCallback.For(callbackUri), Ct);

        stub.LastRequest!
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldContain("oauth_callback=\"https%3A%2F%2Fclient.example%2Fcallback\"");
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_Throws_WhenCallbackConfirmedIsMissing()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_token=t&oauth_token_secret=s")
        );
        var flow = CreateFlow(stub);

        await Should.ThrowAsync<OAuthProtocolException>(
            () => flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct)
        );
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_Throws_WhenCallbackConfirmedIsNotTrue()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=false")
        );
        var flow = CreateFlow(stub);

        await Should.ThrowAsync<OAuthProtocolException>(
            () => flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct)
        );
    }

    [Theory]
    [InlineData("oauth_token=t&oauth_token_secret=s")]
    [InlineData("oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=false")]
    public async Task RequestTemporaryCredentialsAsync_AllowsUnconfirmedCallback_WhenOptedOut(
        string body
    )
    {
        var stub = new StubHttpMessageHandler(FormResponse(body));
        var flow = CreateFlow(stub, new OAuthFlowOptions { AllowUnconfirmedCallback = true });

        var result = await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct);

        result.CallbackConfirmed.ShouldBeFalse();
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_ParsesTheResponse_RegardlessOfContentType()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse(
                "oauth_token=t&oauth_token_secret=s&oauth_callback_confirmed=true",
                "text/plain"
            )
        );
        var flow = CreateFlow(stub);

        var result = await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct);

        result.Token.ShouldBe("t");
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_Throws_ProtocolException_WhenTokenIsMissing()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_callback_confirmed=true")
        );
        var flow = CreateFlow(stub);

        await Should.ThrowAsync<OAuthProtocolException>(
            () => flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct)
        );
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_Throws_RequestFailedException_WithStatusAndExcerpt_OnNonSuccess()
    {
        var stub = new StubHttpMessageHandler(
            new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("invalid consumer key"),
            }
        );
        var flow = CreateFlow(stub);

        var exception = await Should.ThrowAsync<OAuthRequestFailedException>(
            () => flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct)
        );

        exception.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        exception.ResponseExcerpt.ShouldBe("invalid consumer key");
    }

    [Fact]
    public async Task RequestTemporaryCredentialsAsync_TruncatesTheResponseExcerpt()
    {
        var body = new string('x', 1000);
        var stub = new StubHttpMessageHandler(
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent(body),
            }
        );
        var flow = CreateFlow(stub);

        var exception = await Should.ThrowAsync<OAuthRequestFailedException>(
            () => flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct)
        );

        exception.ResponseExcerpt!.Length.ShouldBe(500);
    }

    [Fact]
    public void BuildAuthorizationUri_IncludesTheTemporaryToken()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var flow = CreateFlow(stub);
        var temporary = new TemporaryCredentials("temp token/1", "secret", true);

        var uri = flow.BuildAuthorizationUri(temporary);

        uri.ShouldBe(new Uri("http://example.com/oauth/authorize?oauth_token=temp%20token%2F1"));
    }

    [Fact]
    public void BuildAuthorizationUri_AppendsWithAmpersand_WhenTheEndpointAlreadyHasAQuery()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var endpoints = Endpoints with
        {
            ResourceOwnerAuthorization = new Uri("http://example.com/oauth/authorize?tenant=acme"),
        };
        var flow = new OAuthFlow(new HttpClient(stub), endpoints, Credentials, CreateSigner());
        var temporary = new TemporaryCredentials("temp-token", "secret", true);

        var uri = flow.BuildAuthorizationUri(temporary);

        uri.ShouldBe(
            new Uri("http://example.com/oauth/authorize?tenant=acme&oauth_token=temp-token")
        );
    }

    [Fact]
    public void BuildAuthorizationUri_KeepsTheTokenInTheQuery_WhenTheEndpointHasAFragment()
    {
        var stub = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var endpoints = Endpoints with
        {
            ResourceOwnerAuthorization = new Uri("http://example.com/oauth/authorize#step1"),
        };
        var flow = new OAuthFlow(new HttpClient(stub), endpoints, Credentials, CreateSigner());
        var temporary = new TemporaryCredentials("temp-token", "secret", true);

        var uri = flow.BuildAuthorizationUri(temporary);

        uri.Query.ShouldBe("?oauth_token=temp-token");
        uri.Fragment.ShouldBe("#step1");
    }

    [Fact]
    public async Task ExchangeAsync_ReturnsTokenCredentials_SignedWithTheTemporaryCredentials()
    {
        var stub = new StubHttpMessageHandler(
            FormResponse("oauth_token=access-token&oauth_token_secret=access-secret")
        );
        var flow = CreateFlow(stub);
        var temporary = new TemporaryCredentials("temp-token", "temp-secret", true);

        var result = await flow.ExchangeAsync(temporary, "the-verifier", Ct);

        result.Token.ShouldBe("access-token");
        result.TokenSecret.ShouldBe("access-secret");
        stub.LastRequest!
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldContain("oauth_token=\"temp-token\"");
        stub.LastRequest!
            .Headers.GetValues("Authorization")
            .Single()
            .ShouldContain("oauth_verifier=\"the-verifier\"");
    }

    [Fact]
    public async Task ExchangeAsync_Throws_ProtocolException_WhenTheResponseIsMissingAField()
    {
        var stub = new StubHttpMessageHandler(FormResponse("oauth_token=access-token"));
        var flow = CreateFlow(stub);
        var temporary = new TemporaryCredentials("temp-token", "temp-secret", true);

        await Should.ThrowAsync<OAuthProtocolException>(
            () => flow.ExchangeAsync(temporary, "the-verifier", Ct)
        );
    }

    [Fact]
    public async Task EndToEnd_AllThreeLegsComplete_AgainstAStubbedHandlerWithNoNetworkAccess()
    {
        var stub = new StubHttpMessageHandler(
            (request, _) =>
                Task.FromResult(
                    request.RequestUri!.AbsolutePath switch
                    {
                        "/oauth/request_token"
                            => FormResponse(
                                "oauth_token=temp-token&oauth_token_secret=temp-secret&oauth_callback_confirmed=true"
                            ),
                        "/oauth/access_token"
                            => FormResponse("oauth_token=access-token&oauth_token_secret=access-secret"),
                        _ => new HttpResponseMessage(HttpStatusCode.NotFound),
                    }
                )
        );
        var flow = CreateFlow(stub);

        var temporary = await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand, Ct);
        var authorizationUri = flow.BuildAuthorizationUri(temporary);
        var token = await flow.ExchangeAsync(temporary, "the-verifier", Ct);

        authorizationUri.ShouldBe(
            new Uri("http://example.com/oauth/authorize?oauth_token=temp-token")
        );
        token.Token.ShouldBe("access-token");
        token.TokenSecret.ShouldBe("access-secret");
    }

    [Fact]
    public async Task OneFlowInstance_ServesTwoResourceOwnersOfTheSameProviderIndependently()
    {
        var stub = new StubHttpMessageHandler(
            (request, _) =>
            {
                var body = request.Headers.GetValues("Authorization").Single();
                return Task.FromResult(
                    body.Contains("owner-a-temp-token", StringComparison.Ordinal)
                        ? FormResponse("oauth_token=owner-a-access&oauth_token_secret=owner-a-secret")
                        : FormResponse("oauth_token=owner-b-access&oauth_token_secret=owner-b-secret")
                );
            }
        );
        var flow = CreateFlow(stub);
        var ownerA = new TemporaryCredentials("owner-a-temp-token", "owner-a-temp-secret", true);
        var ownerB = new TemporaryCredentials("owner-b-temp-token", "owner-b-temp-secret", true);

        var tokenA = await flow.ExchangeAsync(ownerA, "verifier-a", Ct);
        var tokenB = await flow.ExchangeAsync(ownerB, "verifier-b", Ct);

        tokenA.Token.ShouldBe("owner-a-access");
        tokenB.Token.ShouldBe("owner-b-access");
    }

    [Fact]
    public async Task NoExceptionMessageContainsSecretMaterial()
    {
        const string consumerSecret = "very-secret-consumer-value";
        const string tokenSecret = "very-secret-token-value";
        var credentials = new HmacSha1ClientCredentials("consumer-key", consumerSecret);
        var temporary = new TemporaryCredentials("temp-token", tokenSecret, true);

        var protocolFailure = new StubHttpMessageHandler(FormResponse("oauth_token=only-one-field"));
        var protocolFlow = new OAuthFlow(
            new HttpClient(protocolFailure),
            Endpoints,
            credentials,
            CreateSigner()
        );
        var protocolException = await Should.ThrowAsync<OAuthProtocolException>(
            () => protocolFlow.ExchangeAsync(temporary, "verifier", Ct)
        );

        var requestFailure = new StubHttpMessageHandler(
            new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent($"secret leak test: {consumerSecret} {tokenSecret}"),
            }
        );
        var requestFailedFlow = new OAuthFlow(
            new HttpClient(requestFailure),
            Endpoints,
            credentials,
            CreateSigner()
        );
        var requestFailedException = await Should.ThrowAsync<OAuthRequestFailedException>(
            () => requestFailedFlow.ExchangeAsync(temporary, "verifier", Ct)
        );

        protocolException.Message.ShouldNotContain(consumerSecret);
        protocolException.Message.ShouldNotContain(tokenSecret);
        requestFailedException.Message.ShouldNotContain(consumerSecret);
        requestFailedException.Message.ShouldNotContain(tokenSecret);
    }
}
