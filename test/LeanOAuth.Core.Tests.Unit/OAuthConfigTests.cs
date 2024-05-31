using FluentAssertions;

namespace LeanOAuth.Core.Tests.Unit;

public class OAuthConfigTests
{
    private readonly Uri _validTestUri = new("https://example.com");

    [Fact]
    public void CreateShouldCreateConfigWhenAllParametersAreValid()
    {
        var config = OAuthConfig.Create(
            "consumerKey",
            "consumerSecret",
            OAuthSignatureMethod.HmacSha1,
            _validTestUri,
            _validTestUri,
            _validTestUri,
            "realm"
        );

        config
            .Should()
            .NotBeNull("given valid parameters, a new instance should be created");

        config
            .ConsumerKey
            .Should()
            .Be("consumerKey");

        config
            .ConsumerSecret
            .Should()
            .Be("consumerSecret");

        config
            .SignatureMethod
            .Should()
            .Be(OAuthSignatureMethod.HmacSha1);

        Uri[] urls = [config.RequestTokenUrl, config.AccessTokenUrl, config.CallbackUrl];

        foreach (var url in urls)
        {
            url
                .Should()
                .Be(_validTestUri);
        }

        config
            .Realm
            .Should()
            .NotBeNull()
            .And
            .Be("realm");
    }

    [Fact]
    public void CreateShouldThrowArgumentNullExceptionWhenConsumerKeyOrConsumerSecretAreNull()
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
    public void CreateShouldThrowArgumentExceptionWhenConsumerKeyOrConsumerSecretAreEmpty()
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
    public void CreateShouldThrowArgumentExceptionWhenConsumerKeyOrConsumerSecretAreWhitespace()
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

    [Fact]
    public void CreateShouldThrowArgumentNullExceptionWhenSignatureMethodIsNull()
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