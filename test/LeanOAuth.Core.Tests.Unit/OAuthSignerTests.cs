using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class OAuthSignerTests
{
    private static readonly HmacSha1ClientCredentials Credentials = new("consumer-key", "consumer-secret");

    private static OAuthSigner CreateSigner(ParameterHook? hook = null) => new(new OAuthSigningOptions
    {
        Clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1191242096)),
        NonceGenerator = new FixedNonceGenerator("fixednonce"),
        ParameterHook = hook,
    });

    [Fact]
    public void Sign_IncludesQueryStringParametersFromTheRequestUri()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource?a=1&b=2"),
            Credentials);

        result.Parameters.ShouldContain(p => p.Key == "a" && p.Value == "1");
        result.Parameters.ShouldContain(p => p.Key == "b" && p.Value == "2");
    }

    [Fact]
    public void Sign_AppliesTheParameterHookBeforeSigning_AndTheAddedParameterIsCoveredByTheSignature()
    {
        var withoutHook = CreateSigner().Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials);
        var withHook = CreateSigner(parameters => [.. parameters, new OAuthParameter("hooked", "value")])
            .Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials);

        withHook.Parameters.ShouldContain(p => p.Key == "hooked" && p.Value == "value");
        withHook.SignatureBaseString.ShouldContain("hooked%3Dvalue");
        withHook.AuthorizationHeaderValue.ShouldNotBe(withoutHook.AuthorizationHeaderValue);
    }

    [Fact]
    public void Sign_EncodesParametersBeforeSorting()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            additionalParameters: [new OAuthParameter("z", "1"), new OAuthParameter("a", "2")]);

        var normalizedSegment = result.SignatureBaseString.Split('&', 3)[2];
        var decoded = Uri.UnescapeDataString(normalizedSegment);
        decoded.IndexOf("a=2", StringComparison.Ordinal).ShouldBeLessThan(decoded.IndexOf("z=1", StringComparison.Ordinal));
    }

    [Fact]
    public void Sign_SortsDuplicateKeysByEncodedValue()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            additionalParameters: [new OAuthParameter("k", "2"), new OAuthParameter("k", "1")]);

        var decoded = Uri.UnescapeDataString(result.SignatureBaseString.Split('&', 3)[2]);
        decoded.IndexOf("k=1", StringComparison.Ordinal).ShouldBeLessThan(decoded.IndexOf("k=2", StringComparison.Ordinal));
    }

    [Fact]
    public void Sign_EscapesQuotesAndBackslashesInRealm()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            realm: "tenant\" evil=\"x");

        result.AuthorizationHeaderValue.ShouldStartWith("OAuth realm=\"tenant\\\" evil=\\\"x\", ");
    }

    [Fact]
    public void Sign_ThrowsForNonHttpScheme()
    {
        var signer = CreateSigner();

        Should.Throw<ArgumentException>(() => signer.Sign(HttpMethod.Get, new Uri("ftp://example.com/resource"), Credentials));
    }

    [Fact]
    public void Sign_ThrowsWhenUriContainsUserinfo()
    {
        var signer = CreateSigner();

        Should.Throw<ArgumentException>(() => signer.Sign(HttpMethod.Get, new Uri("http://user:pass@example.com/resource"), Credentials));
    }

    [Fact]
    public void Sign_StripsFragmentAndLowercasesSchemeAndHost()
    {
        var signer = CreateSigner();

        var result = signer.Sign(HttpMethod.Get, new Uri("HTTP://Example.COM/resource#fragment"), Credentials);

        result.SignatureBaseString.ShouldContain(Uri.EscapeDataString("http://example.com/resource"));
        result.SignatureBaseString.ShouldNotContain("fragment");
    }

    [Fact]
    public void Sign_RemovesDefaultPortButKeepsExplicitNonDefaultPort()
    {
        var signer = CreateSigner();

        var defaultPortResult = signer.Sign(HttpMethod.Get, new Uri("http://example.com:80/resource"), Credentials);
        var explicitPortResult = signer.Sign(HttpMethod.Get, new Uri("http://example.com:8080/resource"), Credentials);

        defaultPortResult.SignatureBaseString.ShouldContain(Uri.EscapeDataString("http://example.com/resource"));
        explicitPortResult.SignatureBaseString.ShouldContain(Uri.EscapeDataString("http://example.com:8080/resource"));
    }

    [Fact]
    public void Sign_WithHmacCredentialsAndNoToken_UsesEmptyTokenSecretInSigningKey()
    {
        var signer = CreateSigner();

        var result = signer.Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials);

        result.AuthorizationHeaderValue.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Sign_ConcurrentSigningWithSameCredentials_ProducesIndependentResults()
    {
        var signer = new OAuthSigner();

        var results = Enumerable.Range(0, 32)
            .AsParallel()
            .Select(_ => signer.Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials))
            .ToList();

        results.ShouldAllBe(r => !string.IsNullOrEmpty(r.AuthorizationHeaderValue));
    }
}
