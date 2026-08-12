using System.Security.Cryptography;
using System.Text;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.PercentEncoding;
using LeanOAuth.Core.Tests.Unit.Testing;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class OAuthSignerPlainTextTests
{
    private static OAuthSigner CreateSigner() =>
        new(
            new OAuthSigningOptions
            {
                Clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1191242096)),
                NonceGenerator = new FixedNonceGenerator("fixednonce"),
            }
        );

    [Fact]
    public void Sign_WithPlainTextCredentialsAndNoToken_SignatureIsConsumerSecretAndEmptyTokenSecret()
    {
        var signer = CreateSigner();
        var credentials = new PlainTextClientCredentials("consumer-key", "consumer-secret");

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            credentials
        );

        var expectedSignature = $"{PercentEncoder.Encode("consumer-secret")}&";
        result.AuthorizationHeaderValue.ShouldContain(
            $"oauth_signature=\"{PercentEncoder.Encode(expectedSignature)}\""
        );
    }

    [Fact]
    public void Sign_WithPlainTextCredentialsAndToken_SignatureIsConsumerSecretAndTokenSecret()
    {
        var signer = CreateSigner();
        var credentials = new PlainTextClientCredentials("consumer-key", "consumer-secret");

        var result = signer.Sign(
            HttpMethod.Get,
            new Uri("http://example.com/resource"),
            credentials,
            new OAuthToken("token", "token-secret")
        );

        var expectedSignature =
            $"{PercentEncoder.Encode("consumer-secret")}&{PercentEncoder.Encode("token-secret")}";
        result.AuthorizationHeaderValue.ShouldContain(
            $"oauth_signature=\"{PercentEncoder.Encode(expectedSignature)}\""
        );
    }

    [Theory]
    [InlineData("!*'()")]
    public void Sign_SecretContainingAllFiveRfc2396Rfc3986DivergenceCharacters_EncodesConsistentlyUnderAllThreeMethods(
        string secretWithDivergenceCharacters
    )
    {
        var signer = CreateSigner();
        var uri = new Uri("http://example.com/resource");
        using var rsaKey = RSA.Create(2048);

        // v1 percent-encoded PLAINTEXT with RFC 2396 (via the framework's default escaper)
        // while HMAC-SHA1 used RFC 3986, so a secret with these characters signed differently
        // under the two methods. All three credential types now route every value -- consumer
        // secrets, token secrets, and ordinary parameters -- through the same RFC 3986 encoder.
        var hmacResult = signer.Sign(
            HttpMethod.Get,
            uri,
            new HmacSha1ClientCredentials("consumer-key", secretWithDivergenceCharacters),
            new OAuthToken("token", secretWithDivergenceCharacters)
        );
        var plainTextResult = signer.Sign(
            HttpMethod.Get,
            uri,
            new PlainTextClientCredentials("consumer-key", secretWithDivergenceCharacters),
            new OAuthToken("token", secretWithDivergenceCharacters)
        );
        var rsaResult = signer.Sign(
            HttpMethod.Get,
            uri,
            new RsaSha1ClientCredentials("consumer-key", rsaKey),
            additionalParameters:
            [
                new OAuthParameter("shared_value", secretWithDivergenceCharacters),
            ]
        );

        var expectedEncoded = PercentEncoder.Encode(secretWithDivergenceCharacters);
        // RFC 3986 must escape every one of the five divergence characters; RFC 2396 would
        // have left them bare.
        expectedEncoded.ShouldBe("%21%2A%27%28%29");

        var actualPlainTextSignature = Uri.UnescapeDataString(
            plainTextResult.AuthorizationHeaderValue.Split("oauth_signature=\"")[1].TrimEnd('"')
        );
        actualPlainTextSignature.ShouldBe($"{expectedEncoded}&{expectedEncoded}");

        // The HMAC-SHA1 key is built from the same "encodedSecret&encodedTokenSecret" shape;
        // independently reproducing it from the encoded secret and comparing the resulting
        // signature proves HMAC-SHA1 encodes the secret the same way PLAINTEXT does.
#pragma warning disable CA5350 // HMAC-SHA1 is the RFC 5849 signature method under test, not a discretionary crypto choice.
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes($"{expectedEncoded}&{expectedEncoded}"));
#pragma warning restore CA5350
        var expectedHmacSignature = Convert.ToBase64String(
            hmac.ComputeHash(Encoding.UTF8.GetBytes(hmacResult.SignatureBaseString))
        );
        var actualHmacSignature = Uri.UnescapeDataString(
            hmacResult.AuthorizationHeaderValue.Split("oauth_signature=\"")[1].TrimEnd('"')
        );
        actualHmacSignature.ShouldBe(expectedHmacSignature);

        // RSA-SHA1 has no secret of its own, but it shares the same percent-encoder for
        // ordinary parameter values, so the divergence characters are escaped identically
        // there too. The normalized parameter string is percent-encoded once more when
        // folded into the base string, so decode one layer before comparing.
        var rsaDecodedParameters = Uri.UnescapeDataString(
            rsaResult.SignatureBaseString.Split('&', 3)[2]
        );
        rsaDecodedParameters.ShouldContain(expectedEncoded);
    }
}
