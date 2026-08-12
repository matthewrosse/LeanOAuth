using Shouldly;

namespace LeanOAuth.Http.Tests.Unit;

public class OAuthCallbackTests
{
    [Fact]
    public void OutOfBand_IsTheSameInstanceEveryTime() =>
        OAuthCallback.OutOfBand.ShouldBeSameAs(OAuthCallback.OutOfBand);

    [Fact]
    public void For_ThrowsOnNullUri() =>
        Should.Throw<ArgumentNullException>(() => OAuthCallback.For(null!));

    [Fact]
    public void For_ProducesADifferentValueThanOutOfBand()
    {
        var uriCallback = OAuthCallback.For(new Uri("https://client.example/callback"));

        uriCallback.ShouldNotBe(OAuthCallback.OutOfBand);
    }

    [Fact]
    public void For_WithTheSameUriProducesEqualCallbacks()
    {
        var uri = new Uri("https://client.example/callback");

        OAuthCallback.For(uri).ShouldBe(OAuthCallback.For(uri));
    }
}
