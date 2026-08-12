namespace LeanOAuth.AspNetCore.Tests.Unit.Testing;

internal sealed class StubHttpMessageHandler(
    Func<HttpRequestMessage, HttpResponseMessage> respond
) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    ) => Task.FromResult(respond(request));
}
