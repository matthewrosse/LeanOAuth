using System.Net;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;

namespace LeanOAuth.Http;

/// <summary>
/// Signs an <see cref="HttpRequestMessage"/> in place. For callers that will not send the request
/// through <see cref="OAuthSigningHandler"/>.
/// </summary>
public static class HttpRequestMessageSigningExtensions
{
    private const string FormUrlEncodedMediaType = "application/x-www-form-urlencoded";

    /// <summary>
    /// Signs <paramref name="request"/> and attaches the resulting "Authorization" header.
    /// A form-encoded body participates in the signature per RFC 5849 §3.4.1.3.1 and is buffered
    /// so it remains readable and sendable afterwards; a body of any other content type is left
    /// unread and unbuffered.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="request"/> has no <see cref="HttpRequestMessage.RequestUri"/>, or already
    /// carries an "Authorization" header.
    /// </exception>
    public static async Task SignAsync(
        this HttpRequestMessage request,
        ClientCredentials clientCredentials,
        OAuthToken? token,
        OAuthSigner signer,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clientCredentials);
        ArgumentNullException.ThrowIfNull(signer);

        if (request.RequestUri is null)
        {
            throw new InvalidOperationException("The request has no RequestUri to sign.");
        }

        if (request.Headers.Contains("Authorization"))
        {
            throw new InvalidOperationException(
                "The request already carries an 'Authorization' header; signing would overwrite it."
            );
        }

        var bodyParameters = await ReadFormBodyParametersAsync(request.Content, cancellationToken)
            .ConfigureAwait(false);

        var signature = signer.Sign(
            request.Method,
            request.RequestUri,
            clientCredentials,
            token,
            bodyParameters
        );

        request.Headers.TryAddWithoutValidation(
            "Authorization",
            signature.AuthorizationHeaderValue
        );
    }

    /// <summary>
    /// Overrides the token credential <see cref="OAuthSigningHandler"/> signs this request with,
    /// for callers holding one token per user that cannot mint an <see cref="HttpClient"/> per user.
    /// </summary>
    public static HttpRequestMessage WithOAuthToken(this HttpRequestMessage request, OAuthToken token)
    {
        ArgumentNullException.ThrowIfNull(request);
        request.Options.Set(OAuthSigningHandler.TokenKey, token);
        return request;
    }

    private static async Task<IReadOnlyList<OAuthParameter>?> ReadFormBodyParametersAsync(
        HttpContent? content,
        CancellationToken cancellationToken
    )
    {
        if (content?.Headers.ContentType?.MediaType != FormUrlEncodedMediaType)
        {
            return null;
        }

#pragma warning disable CA2016 // LoadIntoBufferAsync has no CancellationToken overload on net8.0; the ReadAsStringAsync call below still observes it.
        await content.LoadIntoBufferAsync().ConfigureAwait(false);
#pragma warning restore CA2016
        var body = await content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return ParseFormBody(body);
    }

    private static List<OAuthParameter> ParseFormBody(string body)
    {
        var parameters = new List<OAuthParameter>();

        if (body.Length == 0)
        {
            return parameters;
        }

        foreach (var pair in body.Split('&'))
        {
            if (pair.Length == 0)
            {
                continue;
            }

            var separatorIndex = pair.IndexOf('=');
            var key = separatorIndex < 0 ? pair : pair[..separatorIndex];
            var value = separatorIndex < 0 ? string.Empty : pair[(separatorIndex + 1)..];

            parameters.Add(
                new OAuthParameter(WebUtility.UrlDecode(key), WebUtility.UrlDecode(value))
            );
        }

        return parameters;
    }
}
