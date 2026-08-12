namespace LeanOAuth.Http.Tests.Unit.Testing;

internal sealed class StubHttpMessageHandler(
    Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond
) : HttpMessageHandler
{
    public HttpRequestMessage? LastRequest { get; private set; }

    public StubHttpMessageHandler(HttpResponseMessage response)
        : this((_, _) => Task.FromResult(response)) { }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        LastRequest = request;
        return await respond(request, cancellationToken).ConfigureAwait(false);
    }
}
