using System.Net.Http.Headers;
using FluentAssertions;
using LeanOAuth.Core.Abstractions;
using LeanOAuth.Core.Common;
using LeanOAuth.Core.Signatures;
using LeanOAuth.Core.Signatures.Abstractions;
using NSubstitute;

namespace LeanOAuth.Core.Tests.Unit.Headers;

public record TestOAuthOptions(
    string ConsumerKey,
    string ConsumerSecret,
    Uri RequestTokenEndpoint,
    Uri AuthorizationEndpoint,
    Uri AccessTokenEndpoint,
    string Realm,
    string ScopeParameterName,
    char ScopeParameterSeparator,
    ICollection<string>? Scopes = default
) : IOAuthOptions
{
    public ICollection<string> Scopes { get; } = Scopes ?? new List<string>();
}

// TODO: Look for some reliable test data.
public class OAuthAuthorizationHeaderFactoryTests
{
    [Fact]
    public void CreateRequestTokenHeader_ShouldCreateValidHeader()
    {
        var testOptions = new TestOAuthOptions(
            "dpf43f3p2l4k3l03",
            "kd94hf93k423kf44",
            new Uri("https://photos.example.net/request_token"),
            new Uri("http://photos.example.net/authorize"),
            new Uri("https://photos.example.net/access_token"),
            "http://photos.example.net/",
            "scopes",
            '|'
        );

        var callbackUrl = new Uri("http://printer.example.com/request_token_ready");

        var nonceGenerator = Substitute.For<INonceGenerator>();

        nonceGenerator.Generate().Returns("kllo9940pd9333jh");

        var signatureCalculator = Substitute.For<OAuthSignatureCalculator>();

        signatureCalculator
            .Calculate(Arg.Any<OAuthSignatureCreationContext>())
            .Returns("tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D");

        signatureCalculator.SignatureMethod.Returns(OAuthConstants.SignatureMethods.HmacSha1);

        var timeProvider = Substitute.For<TimeProvider>();

        timeProvider.LocalTimeZone.Returns(TimeZoneInfo.Utc);
        timeProvider.GetUtcNow().Returns(DateTimeOffset.FromUnixTimeSeconds(1191242090));

        var sut = new OAuthAuthorizationHeaderFactory<TestOAuthOptions>(
            testOptions,
            signatureCalculator,
            timeProvider,
            nonceGenerator
        );

        var headerValue = sut.CreateRequestTokenRequestHeader(HttpMethod.Post, callbackUrl);

        var header = new AuthenticationHeaderValue(
            OAuthConstants.AuthorizationHeaderScheme,
            headerValue
        );

        // TODO: Maybe think about returning some object from the method and override .ToString(), so the testing is easier.
        var expected =
            @"OAuth realm=""http://photos.example.net/"",oauth_consumer_key=""dpf43f3p2l4k3l03"",oauth_nonce=""kllo9940pd9333jh"",oauth_timestamp=""1191242090"",oauth_signature_method=""HMAC-SHA1"",oauth_version=""1.0"",oauth_callback=""http%3A%2F%2Fprinter.example.com%2Frequest_token_ready"",oauth_signature=""tR3%252BTy81lMeYAr%252FFid0kMTYa%252FWM%253D""";

        header.ToString().Should().Be(expected);
    }

    [Fact]
    public void CreateAccessTokenHeader_ShouldCreateValidHeader()
    {
        var testOptions = new TestOAuthOptions(
            "abcd",
            "efgh",
            new Uri("http://host.net/request_token"),
            new Uri("http://host.net/authorize"),
            new Uri("http://host.net/access_token"),
            "realm",
            "scopes",
            '|',
            ["email", "photo"]
        );

        var callbackUrl = new Uri("http://printer.example.com/request_token_ready");

        var nonceGenerator = Substitute.For<INonceGenerator>();

        nonceGenerator.Generate().Returns("FDRMnsTvyF1");

        var signatureCalculator = Substitute.For<OAuthSignatureCalculator>();

        signatureCalculator
            .Calculate(Arg.Any<OAuthSignatureCreationContext>())
            .Returns("eUa2pTF4AeFigE5XgtIwoPzAyH0=");

        signatureCalculator.SignatureMethod.Returns(OAuthConstants.SignatureMethods.HmacSha1);

        var timeProvider = Substitute.For<TimeProvider>();

        timeProvider.LocalTimeZone.Returns(TimeZoneInfo.Utc);
        timeProvider.GetUtcNow().Returns(DateTimeOffset.FromUnixTimeSeconds(1462028665));

        var sut = new OAuthAuthorizationHeaderFactory<TestOAuthOptions>(
            testOptions,
            signatureCalculator,
            timeProvider,
            nonceGenerator
        );

        var headerValue = sut.CreateAccessTokenRequestHeader(
            HttpMethod.Post,
            "ijkl",
            "mnop",
            "xyz"
        );

        var header = new AuthenticationHeaderValue(
            OAuthConstants.AuthorizationHeaderScheme,
            headerValue
        );

        // TODO: Maybe think about returning some object from the method and override .ToString(), so the testing is easier.
        var expected =
            @"OAuth realm=""realm"",oauth_consumer_key=""abcd"",oauth_nonce=""FDRMnsTvyF1"",oauth_timestamp=""1462028665"",oauth_signature_method=""HMAC-SHA1"",oauth_version=""1.0"",oauth_token=""ijkl"",oauth_verifier=""xyz"",oauth_signature=""eUa2pTF4AeFigE5XgtIwoPzAyH0%3D""";

        header.ToString().Should().Be(expected);
    }
}
