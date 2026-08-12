using System.Linq;
using System.Net;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;

namespace LeanOAuth.Http;

/// <summary>
/// A <see cref="DelegatingHandler"/> that signs every outbound request with OAuth 1.0a and
/// composes with the standard <c>IHttpClientFactory</c> registration pattern
/// (<c>AddHttpMessageHandler</c>).
/// </summary>
/// <remarks>
/// Must sit inside any retry handler in the pipeline — closer to the transport — because each
/// retry attempt needs a fresh nonce and timestamp; a signature computed once and replayed across
/// retries is bound to a stale nonce on every attempt after the first. With Polly, register this
/// handler with <c>AddHttpMessageHandler</c> before <c>AddPolicyHandler</c>, so Polly wraps it
/// rather than the other way around.
/// </remarks>
public sealed class OAuthSigningHandler : DelegatingHandler
{
    private static readonly HttpStatusCode[] RedirectStatusCodes =
    [
        HttpStatusCode.MovedPermanently,
        HttpStatusCode.Found,
        HttpStatusCode.SeeOther,
        HttpStatusCode.TemporaryRedirect,
        HttpStatusCode.PermanentRedirect,
    ];

    private readonly ClientCredentials _clientCredentials;
    private readonly OAuthToken? _defaultToken;
    private readonly OAuthSigner _signer;

    /// <summary>
    /// The per-request option key that overrides the handler's default token credential, for
    /// multi-tenant callers that hold one token per user.
    /// </summary>
    public static HttpRequestOptionsKey<OAuthToken> TokenKey { get; } =
        new("LeanOAuth.Http.OAuthSigningHandler.Token");

    /// <summary>Creates a handler that signs every outbound request with <paramref name="clientCredentials"/>.</summary>
    /// <param name="clientCredentials">The client credentials every request is signed with.</param>
    /// <param name="defaultToken">
    /// The token credential used when a request carries no per-request override set via
    /// <see cref="HttpRequestMessageSigningExtensions.WithOAuthToken"/>.
    /// </param>
    /// <param name="signer">The signer to use. Defaults to a new <see cref="OAuthSigner"/>.</param>
    public OAuthSigningHandler(
        ClientCredentials clientCredentials,
        OAuthToken? defaultToken = null,
        OAuthSigner? signer = null
    )
    {
        ArgumentNullException.ThrowIfNull(clientCredentials);
        _clientCredentials = clientCredentials;
        _defaultToken = defaultToken;
        _signer = signer ?? new OAuthSigner();
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        ArgumentNullException.ThrowIfNull(request);

        var token = request.Options.TryGetValue(TokenKey, out var perRequestToken)
            ? perRequestToken
            : _defaultToken;

        // Retry handlers (e.g. Polly) reuse the same HttpRequestMessage across attempts, so a
        // signature this handler attached on a prior attempt must be cleared before re-signing
        // with a fresh nonce and timestamp. A caller-supplied Authorization header (any other
        // scheme) is left alone so SignAsync still rejects it below.
        if (
            request.Headers.TryGetValues("Authorization", out var existingAuthorizationValues)
            && existingAuthorizationValues.All(value => value.StartsWith("OAuth ", StringComparison.Ordinal))
        )
        {
            request.Headers.Remove("Authorization");
        }

        await request
            .SignAsync(_clientCredentials, token, _signer, cancellationToken)
            .ConfigureAwait(false);

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        if (Array.IndexOf(RedirectStatusCodes, response.StatusCode) >= 0)
        {
            var statusCode = response.StatusCode;
            response.Dispose();

            throw new InvalidOperationException(
                $"The request to '{request.RequestUri}' received an unexpected redirect "
                    + $"({(int)statusCode} {statusCode}). OAuthSigningHandler "
                    + "signs the request URI; a redirect the runtime follows automatically "
                    + "re-sends to a different URI the signature was never bound to and always "
                    + "fails at the provider. Configure the primary HTTP handler with "
                    + "AllowAutoRedirect = false and handle redirects explicitly."
            );
        }

        return response;
    }

    /// <inheritdoc />
    /// <exception cref="NotSupportedException">Always. Signing a form-encoded body requires asynchronous buffering.</exception>
    protected override HttpResponseMessage Send(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    ) =>
        throw new NotSupportedException(
            "OAuthSigningHandler only supports asynchronous sending, because signing a "
                + "form-encoded body requires buffering it asynchronously. Use SendAsync."
        );
}
