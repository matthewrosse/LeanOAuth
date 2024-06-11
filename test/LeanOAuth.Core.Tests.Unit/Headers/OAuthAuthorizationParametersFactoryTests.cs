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

public class OAuthAuthorizationParametersFactoryTests
{
    [Fact]
    public void CreateRequestTokenRequestParameters_ShouldProduceCorrectParameters()
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

        var nonceMockedValue = "kllo9940pd9333jh";

        nonceGenerator.Generate().Returns(nonceMockedValue);

        var signatureCalculator = Substitute.For<OAuthSignatureCalculator>();

        var signatureMockedValue = "tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D";

        signatureCalculator
            .Calculate(Arg.Any<OAuthSignatureCreationContext>())
            .Returns(signatureMockedValue);

        signatureCalculator.SignatureMethod.Returns(OAuthConstants.SignatureMethods.HmacSha1);

        var timeProvider = Substitute.For<TimeProvider>();

        var timestampMockedValue = 1191242090;

        timeProvider.LocalTimeZone.Returns(TimeZoneInfo.Utc);
        timeProvider.GetUtcNow().Returns(DateTimeOffset.FromUnixTimeSeconds(timestampMockedValue));

        var sut = new OAuthAuthorizationParametersFactory<TestOAuthOptions>(
            testOptions,
            signatureCalculator,
            timeProvider,
            nonceGenerator
        );

        var requestParameters = sut.CreateRequestTokenRequestParameters(
            HttpMethod.Post,
            callbackUrl
        );

        List<OAuthParameter> expectedParameters =
        [
            new OAuthParameter(OAuthConstants.ParameterNames.ConsumerKey, testOptions.ConsumerKey),
            new OAuthParameter(OAuthConstants.ParameterNames.Nonce, nonceMockedValue),
            new OAuthParameter(
                OAuthConstants.ParameterNames.Timestamp,
                timestampMockedValue.ToString()
            ),
            new OAuthParameter(
                OAuthConstants.ParameterNames.SignatureMethod,
                signatureCalculator.SignatureMethod
            ),
            new OAuthParameter(OAuthConstants.ParameterNames.Signature, signatureMockedValue),
            new OAuthParameter(OAuthConstants.ParameterNames.Version, OAuthConstants.Version),
            new OAuthParameter(OAuthConstants.ParameterNames.Callback, callbackUrl.ToString())
        ];

        requestParameters.Should().BeEquivalentTo(expectedParameters);
    }

    [Fact]
    public void CreateAccessTokenRequestParameters_ShouldProduceCorrectParameters()
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

        var nonceGenerator = Substitute.For<INonceGenerator>();

        var nonceMockedValue = "FDRMnsTvyF1";

        nonceGenerator.Generate().Returns(nonceMockedValue);

        var signatureCalculator = Substitute.For<OAuthSignatureCalculator>();

        var signatureMockedValue = "eUa2pTF4AeFigE5XgtIwoPzAyH0=";

        signatureCalculator
            .Calculate(Arg.Any<OAuthSignatureCreationContext>())
            .Returns(signatureMockedValue);

        signatureCalculator.SignatureMethod.Returns(OAuthConstants.SignatureMethods.HmacSha1);

        var timeProvider = Substitute.For<TimeProvider>();

        var timestampMockedValue = 1462028665;

        timeProvider.LocalTimeZone.Returns(TimeZoneInfo.Utc);
        timeProvider.GetUtcNow().Returns(DateTimeOffset.FromUnixTimeSeconds(timestampMockedValue));

        var sut = new OAuthAuthorizationParametersFactory<TestOAuthOptions>(
            testOptions,
            signatureCalculator,
            timeProvider,
            nonceGenerator
        );

        var token = "ijkl";
        var verifier = "xyz";

        var requestParameters = sut.CreateAccessTokenRequestParameters(
            HttpMethod.Post,
            token,
            "mnop",
            "xyz"
        );

        List<OAuthParameter> expected =
        [
            new OAuthParameter(OAuthConstants.ParameterNames.ConsumerKey, testOptions.ConsumerKey),
            new OAuthParameter(OAuthConstants.ParameterNames.Nonce, nonceMockedValue),
            new OAuthParameter(
                OAuthConstants.ParameterNames.Timestamp,
                timestampMockedValue.ToString()
            ),
            new OAuthParameter(
                OAuthConstants.ParameterNames.SignatureMethod,
                signatureCalculator.SignatureMethod
            ),
            new OAuthParameter(OAuthConstants.ParameterNames.Signature, signatureMockedValue),
            new OAuthParameter(OAuthConstants.ParameterNames.Token, token),
            new OAuthParameter(OAuthConstants.ParameterNames.Verifier, verifier),
            new OAuthParameter(OAuthConstants.ParameterNames.Version, OAuthConstants.Version)
        ];

        requestParameters.Should().BeEquivalentTo(expected);
    }
}
