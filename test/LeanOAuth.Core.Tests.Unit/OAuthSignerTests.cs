using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class OAuthSignerTests
{
    private static readonly HmacSha1ClientCredentials Credentials =
        new("consumer-key", "consumer-secret");

    private static OAuthSigner CreateSigner(ParameterHook? hook = null) =>
        new(
            new OAuthSigningOptions
            {
                Clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1191242096)),
                NonceGenerator = new FixedNonceGenerator("fixednonce"),
                ParameterHook = hook,
            }
        );

    [Fact]
    public void Sign_IncludesQueryStringParametersFromTheRequestUri()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource?a=1&b=2"),
            Credentials
        );

        result.Parameters.ShouldContain(p => p.Key == "a" && p.Value == "1");
        result.Parameters.ShouldContain(p => p.Key == "b" && p.Value == "2");
    }

    [Fact]
    public void Sign_AppliesTheParameterHookBeforeSigning_AndTheAddedParameterIsCoveredByTheSignature()
    {
        var withoutHook = CreateSigner()
            .Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials);
        var withHook = CreateSigner(parameters =>
                [.. parameters, new OAuthParameter("hooked", "value")]
            )
            .Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials);

        withHook.Parameters.ShouldContain(p => p.Key == "hooked" && p.Value == "value");
        withHook.SignatureBaseString.ShouldContain("hooked%3Dvalue");
        withHook.AuthorizationHeaderValue.ShouldNotBe(withoutHook.AuthorizationHeaderValue);
    }

    [Fact]
    public void Sign_WhenHookRemovesAnOAuthParameter_OmitsItFromTheHeader()
    {
        var signer = CreateSigner(parameters =>
            [.. parameters.Where(p => p.Key != "oauth_version")]
        );

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials
        );

        result.AuthorizationHeaderValue.ShouldNotContain("oauth_version");
        result.SignatureBaseString.ShouldNotContain("oauth_version");
    }

    [Fact]
    public void Sign_WhenHookAddsAnOAuthPrefixedParameter_IncludesItInTheHeader()
    {
        var signer = CreateSigner(parameters =>
            [.. parameters, new OAuthParameter("oauth_body_hash", "abc123")]
        );

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials
        );

        result.AuthorizationHeaderValue.ShouldContain("oauth_body_hash=\"abc123\"");
        result.SignatureBaseString.ShouldContain("oauth_body_hash%3Dabc123");
    }

    [Fact]
    public void Sign_WhenHookAddsANonOAuthParameter_ContributesToBaseStringOnly()
    {
        var signer = CreateSigner(parameters =>
            [.. parameters, new OAuthParameter("hooked", "value")]
        );

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials
        );

        result.SignatureBaseString.ShouldContain("hooked%3Dvalue");
        result.AuthorizationHeaderValue.ShouldNotContain("hooked");
    }

    [Fact]
    public void Sign_DoesNotLeakQueryStringParametersIntoTheHeaderEvenWhenOAuthPrefixed()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource?oauth_version=zzz-query"),
            Credentials
        );

        result.AuthorizationHeaderValue.ShouldContain("oauth_version=\"1.0\"");
        result.AuthorizationHeaderValue.ShouldNotContain("zzz-query");
        var oauthVersionOccurrences = result
            .AuthorizationHeaderValue.Split("oauth_version=")
            .Length - 1;
        oauthVersionOccurrences.ShouldBe(1);
    }

    [Fact]
    public void Sign_EncodesParametersBeforeSorting()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            additionalParameters: [new OAuthParameter("z", "1"), new OAuthParameter("a", "2")]
        );

        var normalizedSegment = result.SignatureBaseString.Split('&', 3)[2];
        var decoded = Uri.UnescapeDataString(normalizedSegment);
        decoded
            .IndexOf("a=2", StringComparison.Ordinal)
            .ShouldBeLessThan(decoded.IndexOf("z=1", StringComparison.Ordinal));
    }

    [Fact]
    public void Sign_SortsDuplicateKeysByEncodedValue()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            additionalParameters: [new OAuthParameter("k", "2"), new OAuthParameter("k", "1")]
        );

        var decoded = Uri.UnescapeDataString(result.SignatureBaseString.Split('&', 3)[2]);
        decoded
            .IndexOf("k=1", StringComparison.Ordinal)
            .ShouldBeLessThan(decoded.IndexOf("k=2", StringComparison.Ordinal));
    }

    [Fact]
    public void Sign_EscapesQuotesAndBackslashesInRealm()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            realm: "tenant\" evil=\"x"
        );

        result.AuthorizationHeaderValue.ShouldStartWith("OAuth realm=\"tenant\\\" evil=\\\"x\", ");
    }

    [Fact]
    public void Sign_ThrowsForNonHttpScheme()
    {
        var signer = CreateSigner();

        Should.Throw<ArgumentException>(
            () => signer.Sign(HttpMethod.Get, new Uri("ftp://example.com/resource"), Credentials)
        );
    }

    [Fact]
    public void Sign_ThrowsWhenUriContainsUserinfo()
    {
        var signer = CreateSigner();

        Should.Throw<ArgumentException>(
            () =>
                signer.Sign(
                    HttpMethod.Get,
                    new Uri("http://user:pass@example.com/resource"),
                    Credentials
                )
        );
    }

    [Fact]
    public void Sign_StripsFragmentAndLowercasesSchemeAndHost()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("HTTP://Example.COM/resource#fragment"),
            Credentials
        );

        result.SignatureBaseString.ShouldContain(
            Uri.EscapeDataString("http://example.com/resource")
        );
        result.SignatureBaseString.ShouldNotContain("fragment");
    }

    [Fact]
    public void Sign_RemovesDefaultPortButKeepsExplicitNonDefaultPort()
    {
        var signer = CreateSigner();

        var defaultPortResult = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com:80/resource"),
            Credentials
        );
        var explicitPortResult = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com:8080/resource"),
            Credentials
        );

        defaultPortResult.SignatureBaseString.ShouldContain(
            Uri.EscapeDataString("http://example.com/resource")
        );
        explicitPortResult.SignatureBaseString.ShouldContain(
            Uri.EscapeDataString("http://example.com:8080/resource")
        );
    }

    [Fact]
    public void Sign_WithHmacCredentialsAndNoToken_UsesEmptyTokenSecretInSigningKey()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials
        );

        result.AuthorizationHeaderValue.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Sign_OrdersDuplicateKeysFromDifferentSourcesByEncodedValue()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource?oauth_version=zzz-query"),
            Credentials,
            additionalParameters: [new OAuthParameter("oauth_version", "aaa-additional")]
        );

        var decoded = Uri.UnescapeDataString(result.SignatureBaseString.Split('&', 3)[2]);
        decoded
            .IndexOf("oauth_version=1.0", StringComparison.Ordinal)
            .ShouldBeLessThan(decoded.IndexOf("oauth_version=aaa-additional", StringComparison.Ordinal));
        decoded
            .IndexOf("oauth_version=aaa-additional", StringComparison.Ordinal)
            .ShouldBeLessThan(decoded.IndexOf("oauth_version=zzz-query", StringComparison.Ordinal));
    }

    [Fact]
    public void Sign_HandlesEmptyParameterValuesAndKeysWithNoValue()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource?flag&empty="),
            Credentials
        );

        result.Parameters.ShouldContain(p => p.Key == "flag" && p.Value == string.Empty);
        result.Parameters.ShouldContain(p => p.Key == "empty" && p.Value == string.Empty);
        result.SignatureBaseString.ShouldContain(Uri.EscapeDataString("flag="));
        result.SignatureBaseString.ShouldContain(Uri.EscapeDataString("empty="));
    }

    [Fact]
    public void Sign_EncodesUnicodeParameterKeysAndValuesOverUtf8Bytes()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            Credentials,
            additionalParameters: [new OAuthParameter("café", "日本語")]
        );

        var decoded = Uri.UnescapeDataString(result.SignatureBaseString.Split('&', 3)[2]);
        decoded.ShouldContain("caf%C3%A9");
        decoded.ShouldContain("%E6%97%A5%E6%9C%AC%E8%AA%9E");
    }

    [Fact]
    public void Sign_DoesNotDoubleEncodeAlreadyPercentEncodedQueryInput()
    {
        var signer = CreateSigner();

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource?greeting=hello%20world"),
            Credentials
        );

        result.Parameters.ShouldContain(p => p.Key == "greeting" && p.Value == "hello world");
        var decoded = Uri.UnescapeDataString(result.SignatureBaseString.Split('&', 3)[2]);
        decoded.ShouldContain("greeting=hello%20world");
        decoded.ShouldNotContain("hello%2520world");
    }

    [Fact]
    public void Sign_ConcurrentSigningWithSameCredentials_ProducesIndependentResults()
    {
        var signer = new OAuthSigner();

        var results = Enumerable
            .Range(0, 32)
            .AsParallel()
            .Select(_ =>
                signer.Sign(HttpMethod.Get, new Uri("http://example.com/resource"), Credentials)
            )
            .ToList();

        results.ShouldAllBe(r => !string.IsNullOrEmpty(r.AuthorizationHeaderValue));
    }
}
