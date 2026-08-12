using System.Reflection;
using LeanOAuth.Core.Credentials;
using Shouldly;

namespace LeanOAuth.Core.Tests.Unit;

public class ClientCredentialsTests
{
    [Fact]
    public void ClientCredentials_HasNoPublicConstructor()
    {
        var constructors = typeof(ClientCredentials).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance
        );

        constructors.ShouldBeEmpty();
    }

    [Fact]
    public void ClientCredentials_DomainConstructorIsPrivateProtected()
    {
        var domainConstructor = typeof(ClientCredentials)
            .GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(c => c.GetParameters() is [{ ParameterType.Name: nameof(String) }]);

        domainConstructor.IsFamilyAndAssembly.ShouldBeTrue();
    }

    [Fact]
    public void HmacSha1ClientCredentials_ExposesConsumerKeyAndSecret()
    {
        var credentials = new HmacSha1ClientCredentials("key", "secret");

        credentials.ConsumerKey.ShouldBe("key");
        credentials.ConsumerSecret.ShouldBe("secret");
    }

    [Fact]
    public void PlainTextClientCredentials_ExposesConsumerKeyAndSecret()
    {
        var credentials = new PlainTextClientCredentials("key", "secret");

        credentials.ConsumerKey.ShouldBe("key");
        credentials.ConsumerSecret.ShouldBe("secret");
    }
}
