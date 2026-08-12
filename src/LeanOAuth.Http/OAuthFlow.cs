using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.PercentEncoding;

namespace LeanOAuth.Http;

/// <summary>
/// The three-legged flow (RFC 5849 §2): request temporary credentials, send the resource owner
/// to the authorization URI, exchange the returned verifier for token credentials. No web
/// framework, no browser, no test host — built for a console application or daemon.
/// </summary>
/// <remarks>
/// Endpoints and client credentials belong to a provider instance and are supplied once, at
/// construction. Temporary credentials, the verifier, and token credentials belong to a resource
/// owner and are supplied per call. One <see cref="OAuthFlow"/> instance therefore serves every
/// user of one provider.
/// </remarks>
public sealed class OAuthFlow
{
    private const int ResponseExcerptMaxLength = 500;

    private readonly HttpClient _httpClient;
    private readonly OAuthProviderEndpoints _endpoints;
    private readonly ClientCredentials _clientCredentials;
    private readonly OAuthSigner _signer;
    private readonly bool _allowUnconfirmedCallback;

    /// <param name="httpClient">Used to call the provider's endpoints. Not owned; the caller disposes it.</param>
    /// <param name="endpoints">The provider's three endpoints.</param>
    /// <param name="clientCredentials">The client credentials every request in the flow is signed with.</param>
    /// <param name="signer">The signer to use. Defaults to a new <see cref="OAuthSigner"/>.</param>
    /// <param name="options">Flow options. Defaults to enforcing callback confirmation.</param>
    public OAuthFlow(
        HttpClient httpClient,
        OAuthProviderEndpoints endpoints,
        ClientCredentials clientCredentials,
        OAuthSigner? signer = null,
        OAuthFlowOptions? options = null
    )
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(clientCredentials);

        _httpClient = httpClient;
        _endpoints = endpoints;
        _clientCredentials = clientCredentials;
        _signer = signer ?? new OAuthSigner();
        _allowUnconfirmedCallback = options?.AllowUnconfirmedCallback ?? false;
    }

    /// <summary>
    /// Requests temporary credentials from <see cref="OAuthProviderEndpoints.TemporaryCredentialRequest"/>.
    /// </summary>
    /// <exception cref="OAuthProtocolException">
    /// The response is missing "oauth_token" or "oauth_token_secret"; or the provider did not
    /// confirm the callback and <see cref="OAuthFlowOptions.AllowUnconfirmedCallback"/> is false.
    /// </exception>
    /// <exception cref="OAuthRequestFailedException">The endpoint returned a non-success status.</exception>
    public async Task<TemporaryCredentials> RequestTemporaryCredentialsAsync(
        OAuthCallback callback,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(callback);

        var parameters = await SendAsync(
                _endpoints.TemporaryCredentialRequest,
                token: null,
                [new OAuthParameter("oauth_callback", callback.Value)],
                cancellationToken
            )
            .ConfigureAwait(false);

        var token = RequireParameter(parameters, "oauth_token");
        var tokenSecret = RequireParameter(parameters, "oauth_token_secret");
        var callbackConfirmed = ResolveCallbackConfirmed(parameters);

        return new TemporaryCredentials(token, tokenSecret, callbackConfirmed);
    }

    /// <summary>
    /// Builds the URI the resource owner is sent to, carrying <paramref name="temporaryCredentials"/>'s
    /// token in "oauth_token".
    /// </summary>
    public Uri BuildAuthorizationUri(TemporaryCredentials temporaryCredentials)
    {
        ArgumentNullException.ThrowIfNull(temporaryCredentials);

        var builder = new UriBuilder(_endpoints.ResourceOwnerAuthorization);
        var existingQuery = builder.Query.Length > 1 ? $"{builder.Query[1..]}&" : string.Empty;
        builder.Query =
            $"{existingQuery}oauth_token={PercentEncoder.Encode(temporaryCredentials.Token)}";

        return builder.Uri;
    }

    /// <summary>
    /// Exchanges <paramref name="temporaryCredentials"/> and the verifier the provider returned
    /// for token credentials, via <see cref="OAuthProviderEndpoints.TokenRequest"/>.
    /// </summary>
    /// <exception cref="OAuthProtocolException">The response is missing "oauth_token" or "oauth_token_secret".</exception>
    /// <exception cref="OAuthRequestFailedException">The endpoint returned a non-success status.</exception>
    public async Task<TokenCredentials> ExchangeAsync(
        TemporaryCredentials temporaryCredentials,
        string verifier,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(temporaryCredentials);
        ArgumentException.ThrowIfNullOrEmpty(verifier);

        var token = new OAuthToken(temporaryCredentials.Token, temporaryCredentials.TokenSecret);
        var parameters = await SendAsync(
                _endpoints.TokenRequest,
                token,
                [new OAuthParameter("oauth_verifier", verifier)],
                cancellationToken
            )
            .ConfigureAwait(false);

        var accessToken = RequireParameter(parameters, "oauth_token");
        var accessTokenSecret = RequireParameter(parameters, "oauth_token_secret");

        return new TokenCredentials(accessToken, accessTokenSecret);
    }

    private bool ResolveCallbackConfirmed(IReadOnlyDictionary<string, string> parameters)
    {
        if (
            !parameters.TryGetValue("oauth_callback_confirmed", out var value)
            || !string.Equals(value, "true", StringComparison.Ordinal)
        )
        {
            if (_allowUnconfirmedCallback)
            {
                return false;
            }

            throw new OAuthProtocolException(
                "The provider's temporary credentials response did not confirm the callback "
                    + "(\"oauth_callback_confirmed\" was missing or not \"true\"). This provider is "
                    + "running the OAuth 1.0 flow without the session-fixation fix that OAuth 1.0a "
                    + "adds. Set OAuthFlowOptions.AllowUnconfirmedCallback to accept it anyway."
            );
        }

        return true;
    }

    private async Task<IReadOnlyDictionary<string, string>> SendAsync(
        Uri endpoint,
        OAuthToken? token,
        IReadOnlyList<OAuthParameter> additionalParameters,
        CancellationToken cancellationToken
    )
    {
        var signature = _signer.Sign(
            HttpMethod.Post,
            endpoint,
            _clientCredentials,
            token,
            additionalParameters
        );

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            signature.AuthorizationHeaderValue
        );

        using var response = await _httpClient
            .SendAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var body = await response
            .Content.ReadAsStringAsync(cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new OAuthRequestFailedException(response.StatusCode, Truncate(body));
        }

        return ParseFormEncodedBody(body);
    }

    private static string RequireParameter(
        IReadOnlyDictionary<string, string> parameters,
        string name
    )
    {
        if (!parameters.TryGetValue(name, out var value) || value.Length == 0)
        {
            throw new OAuthProtocolException(
                $"The provider's response is missing the required '{name}' parameter."
            );
        }

        return value;
    }

    private static string? Truncate(string value) =>
        value.Length == 0 ? null : value[..Math.Min(value.Length, ResponseExcerptMaxLength)];

    private static Dictionary<string, string> ParseFormEncodedBody(string body)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var (key, value) in FormUrlEncodedBody.Parse(body))
        {
            parameters[key] = value;
        }

        return parameters;
    }
}
