using System.Net.Http.Headers;
using FluentAssertions;
using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Tests.Unit.Common;

public class OAuthToolsTests
{
    [Theory]
    [MemberData(nameof(GenerateQueryParametersValueData))]
    public void GenerateQueryParametersValue_ShouldGenerateCorrectQueryString(
        IList<OAuthParameter> parameters,
        string expected
    )
    {
        var result = OAuthTools.GenerateQueryStringParametersValue(parameters);

        result.Should().Be(expected);
    }

    [Theory]
    [MemberData(nameof(GenerateAuthorizationHeaderValueData))]
    public void GenerateAuthorizationHeaderValue_ShouldGenerateCorrectHeaderValue(
        IList<OAuthParameter> parameters,
        AuthenticationHeaderValue expected
    )
    {
        var realm = "TEST_REALM";

        var result = OAuthTools.GenerateAuthorizationHeaderValue(parameters, realm);

        result.Should().Be(expected);
    }

    public static IEnumerable<object[]> GenerateQueryParametersValueData() =>
        new[]
        {
            new object[]
            {
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "dpf43f3p2l4k3l03"),
                    new(OAuthConstants.ParameterNames.Token, "nnch734d00sl2jdk"),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1191242096"),
                    new(OAuthConstants.ParameterNames.Nonce, "kllo9940pd9333jh"),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new("file", "vacation.jpg"),
                    new("size", "original")
                },
                "file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original"
            },

            [
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "xvz1evFS4wEEPTGEFPHBog"),
                    new(
                        OAuthConstants.ParameterNames.Token,
                        "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
                    ),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1318622958"),
                    new(
                        OAuthConstants.ParameterNames.Nonce,
                        "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
                    ),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new("status", "Hello Ladies + Gentlemen, a signed OAuth request!"),
                    new("include_entities", "true")
                },
                "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
            ]
        };

    public static IEnumerable<object[]> GenerateAuthorizationHeaderValueData() =>
        new[]
        {
            new object[]
            {
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "dpf43f3p2l4k3l03"),
                    new(OAuthConstants.ParameterNames.Token, "nnch734d00sl2jdk"),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1191242096"),
                    new(OAuthConstants.ParameterNames.Nonce, "kllo9940pd9333jh"),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                },
                new AuthenticationHeaderValue(
                    OAuthConstants.AuthorizationHeaderScheme,
                    "realm=\"TEST_REALM\",oauth_consumer_key=\"dpf43f3p2l4k3l03\",oauth_nonce=\"kllo9940pd9333jh\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1191242096\",oauth_token=\"nnch734d00sl2jdk\",oauth_version=\"1.0\""
                )
            },

            [
                new List<OAuthParameter>
                {
                    new(OAuthConstants.ParameterNames.ConsumerKey, "xvz1evFS4wEEPTGEFPHBog"),
                    new(
                        OAuthConstants.ParameterNames.Token,
                        "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
                    ),
                    new(OAuthConstants.ParameterNames.SignatureMethod, "HMAC-SHA1"),
                    new(OAuthConstants.ParameterNames.Timestamp, "1318622958"),
                    new(
                        OAuthConstants.ParameterNames.Nonce,
                        "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
                    ),
                    new(OAuthConstants.ParameterNames.Version, "1.0"),
                    new("status", "Hello Ladies + Gentlemen, a signed OAuth request!"),
                    new("include_entities", "true")
                },
                new AuthenticationHeaderValue(
                    OAuthConstants.AuthorizationHeaderScheme,
                    "realm=\"TEST_REALM\",include_entities=\"true\",oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\",oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1318622958\",oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\",oauth_version=\"1.0\",status=\"Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21\""
                )
            ]
        };
}
