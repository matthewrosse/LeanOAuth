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
    Uri CallbackEndpoint,
    string Realm
) : IOAuthOptions;

// TODO: Look for some reliable test data.
public class OAuthHeaderFactoryTests
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
            new Uri("http://printer.example.com/request_token_ready"),
            "http://photos.example.net/"
        );

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

        var sut = new OAuthHeaderFactory<TestOAuthOptions>(
            testOptions,
            signatureCalculator,
            timeProvider,
            nonceGenerator
        );

        var header = sut.CreateRequestTokenHeader(
            HttpMethod.Post,
            new Dictionary<string, string>()
        );

        // TODO: Maybe think about returning some object from the method and override .ToString(), so the testing is easier.
        var expected =
            @"Authorization: OAuth realm=""http://photos.example.net/"",oauth_consumer_key=""dpf43f3p2l4k3l03"",oauth_nonce=""kllo9940pd9333jh"",oauth_timestamp=""1191242090"",oauth_signature_method=""HMAC-SHA1"",oauth_version=""1.0"",oauth_callback=""http%3A%2F%2Fprinter.example.com%2Frequest_token_ready"",oauth_signature=""tR3%252BTy81lMeYAr%252FFid0kMTYa%252FWM%253D""";

        header.Should().Be(expected);
    }
}
