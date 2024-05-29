using FluentAssertions;

namespace OAuthDotnet.Tests.Unit;

public class OAuthConfigTests
{
    private readonly Uri _validTestUri = new("https://example.com");

    [Fact]
    public void GivenValidConsumerKeyAndConsumerSecretReturnsNewInstance()
    {
        var createAction =
            () => OAuthConfig.Create(
                "consumerKey",
                "consumerSecret",
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        createAction
            .Should()
            .NotThrow("given valid parameters, a new instance should be created");
    }

    [Fact]
    public void GivenNullConsumerKeyOrConsumerSecretThrowsArgumentNullException()
    {
        var createWithNullKey =
            () => OAuthConfig.Create(
                null!,
                "consumerSecret",
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        var createWithNullSecret =
            () => OAuthConfig.Create(
                "consumerKey",
                null!,
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        createWithNullKey
            .Should()
            .ThrowExactly<ArgumentNullException>("consumer key should not be null");

        createWithNullSecret
            .Should()
            .ThrowExactly<ArgumentNullException>("consumer secret should not be null");
    }

    [Fact]
    public void GivenEmptyConsumerKeyOrConsumerSecretThrowsArgumentException()
    {
        var createWithEmptyKey =
            () => OAuthConfig.Create(
                string.Empty,
                "consumerSecret",
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        var createWithEmptySecret =
            () => OAuthConfig.Create(
                "consumerKey",
                string.Empty,
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        createWithEmptyKey
            .Should()
            .ThrowExactly<ArgumentException>("consumer key should not be empty");

        createWithEmptySecret
            .Should()
            .ThrowExactly<ArgumentException>("consumer secret should not be empty");
    }

    [Fact]
    public void GivenWhitespaceConsumerKeyOrConsumerSecretThrowsArgumentException()
    {
        var createWithWhitespaceKey =
            () => OAuthConfig.Create(
                "    ",
                "consumerSecret",
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        var createWithWhitespaceSecret =
            () => OAuthConfig.Create(
                "consumerKey",
                "    ",
                OAuthSignatureMethod.HmacSha1,
                _validTestUri,
                _validTestUri,
                _validTestUri
            );

        createWithWhitespaceKey
            .Should()
            .ThrowExactly<ArgumentException>("consumer key should not be whitespace");

        createWithWhitespaceSecret
            .Should()
            .ThrowExactly<ArgumentException>("consumer secret should not be whitespace");
    }

    public void GivenNullSignatureMethodThrowsArgumentNullException()
    {
        var createWithNullSignatureMethod = () => OAuthConfig.Create(
            "consumerKey",
            "consumerSecret",
            null!,
            _validTestUri,
            _validTestUri,
            _validTestUri
        );

        createWithNullSignatureMethod
            .Should()
            .ThrowExactly<ArgumentNullException>("signature method should not be null");
    }
}