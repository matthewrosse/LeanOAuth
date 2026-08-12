using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Core.PercentEncoding;

namespace LeanOAuth.Core;

/// <summary>
/// Signs OAuth 1.0a requests. Has exactly one signing method, with no knowledge of which leg of
/// the three-legged flow it is signing — legs differ only in which protocol parameters they
/// carry, supplied through the additional-parameters argument of <see cref="Sign"/>.
/// </summary>
public sealed class OAuthSigner
{
    private readonly OAuthSigningOptions _options;

    /// <summary>Creates a signer with default options.</summary>
    public OAuthSigner()
        : this(new OAuthSigningOptions()) { }

    /// <summary>Creates a signer with the given options.</summary>
    /// <param name="options">The nonce generator, clock, and parameter hook to sign with.</param>
    public OAuthSigner(OAuthSigningOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <summary>
    /// Signs a request, returning the "Authorization" header value, the signature base string,
    /// and the parameters that were signed.
    /// </summary>
    /// <param name="method">The HTTP method of the request being signed.</param>
    /// <param name="requestUri">The absolute request URI. Must use the "http" or "https" scheme and carry no userinfo.</param>
    /// <param name="clientCredentials">The client credentials; their type determines the signature method.</param>
    /// <param name="token">The temporary or token credentials, or null when none are held yet (as in a temporary credentials request).</param>
    /// <param name="additionalParameters">Parameters beyond the client/token pair: leg-specific protocol parameters (e.g. "oauth_callback", "oauth_verifier"), query-string parameters, and form-body parameters.</param>
    /// <param name="realm">The optional realm to include in the header value.</param>
    public OAuthSignature Sign(
        HttpMethod method,
        Uri requestUri,
        ClientCredentials clientCredentials,
        OAuthToken? token = null,
        IReadOnlyList<OAuthParameter>? additionalParameters = null,
        string? realm = null
    )
    {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(requestUri);
        ArgumentNullException.ThrowIfNull(clientCredentials);

        var (normalizedUri, queryParameters) = NormalizeUri(requestUri);
        var extraParameters = additionalParameters ?? [];

        var protocolParameters = BuildProtocolParameters(clientCredentials, token);

        var allParameters = new List<OAuthParameter>(
            protocolParameters.Count + queryParameters.Count + extraParameters.Count
        );
        allParameters.AddRange(protocolParameters);
        allParameters.AddRange(queryParameters);
        allParameters.AddRange(extraParameters);

        IReadOnlyList<OAuthParameter> signedParameters = _options.ParameterHook is { } hook
            ? hook(allParameters)
            : allParameters;

        var normalizedParameterString = BuildNormalizedParameterString(signedParameters);
        var baseString =
            $"{method.Method.ToUpperInvariant()}&{PercentEncoder.Encode(normalizedUri)}&{PercentEncoder.Encode(normalizedParameterString)}";

        var signature = ComputeSignature(clientCredentials, token, baseString);

        var headerOAuthParameters = ExcludeQueryParameters(signedParameters, queryParameters)
            .Where(p => p.Key.StartsWith("oauth_", StringComparison.Ordinal))
            .ToList();
        var header = BuildAuthorizationHeader(headerOAuthParameters, signature, realm);

        return new OAuthSignature(header, baseString, signedParameters);
    }

    private List<OAuthParameter> BuildProtocolParameters(
        ClientCredentials clientCredentials,
        OAuthToken? token
    )
    {
        var timestamp = _options
            .Clock.UtcNow.ToUnixTimeSeconds()
            .ToString(CultureInfo.InvariantCulture);
        var nonce = _options.NonceGenerator.GenerateNonce();

        var parameters = new List<OAuthParameter>(6)
        {
            new("oauth_consumer_key", clientCredentials.ConsumerKey),
            new("oauth_signature_method", GetSignatureMethodName(clientCredentials)),
            new("oauth_timestamp", timestamp),
            new("oauth_nonce", nonce),
            new("oauth_version", "1.0"),
        };

        if (token is { } t)
        {
            parameters.Insert(1, new OAuthParameter("oauth_token", t.Token));
        }

        return parameters;
    }

    private static string GetSignatureMethodName(ClientCredentials credentials) =>
        credentials switch
        {
            HmacSha1ClientCredentials => "HMAC-SHA1",
            RsaSha1ClientCredentials => "RSA-SHA1",
            PlainTextClientCredentials => "PLAINTEXT",
            _
                => throw new NotSupportedException(
                    $"Unsupported client credentials type '{credentials.GetType()}'."
                ),
        };

    private static string ComputeSignature(
        ClientCredentials credentials,
        OAuthToken? token,
        string baseString
    ) =>
        credentials switch
        {
            HmacSha1ClientCredentials hmac
                => Convert.ToBase64String(ComputeHmacSha1Signature(hmac, token, baseString)),
            RsaSha1ClientCredentials rsa
                => Convert.ToBase64String(rsa.Sign(Encoding.UTF8.GetBytes(baseString))),
            PlainTextClientCredentials plainText => ComputePlainTextSignature(plainText, token),
            _
                => throw new NotSupportedException(
                    $"Unsupported client credentials type '{credentials.GetType()}'."
                ),
        };

#pragma warning disable CA5350 // HMAC-SHA1 is the RFC 5849 signature method, not a discretionary crypto choice.
    private static byte[] ComputeHmacSha1Signature(
        HmacSha1ClientCredentials credentials,
        OAuthToken? token,
        string baseString
    )
    {
        var key = BuildSharedSecretKey(credentials.ConsumerSecret, token);
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(baseString));
    }
#pragma warning restore CA5350

    private static string ComputePlainTextSignature(
        PlainTextClientCredentials credentials,
        OAuthToken? token
    ) => BuildSharedSecretKey(credentials.ConsumerSecret, token);

    private static string BuildSharedSecretKey(string consumerSecret, OAuthToken? token) =>
        $"{PercentEncoder.Encode(consumerSecret)}&{PercentEncoder.Encode(token?.TokenSecret ?? string.Empty)}";

    private static (string NormalizedUri, List<OAuthParameter> QueryParameters) NormalizeUri(
        Uri requestUri
    )
    {
        if (!requestUri.IsAbsoluteUri)
        {
            throw new ArgumentException("Request URI must be absolute.", nameof(requestUri));
        }

        if (requestUri.Scheme != Uri.UriSchemeHttp && requestUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException(
                $"Request URI scheme '{requestUri.Scheme}' is not supported; only 'http' and 'https' are allowed.",
                nameof(requestUri)
            );
        }

        if (!string.IsNullOrEmpty(requestUri.UserInfo))
        {
            throw new ArgumentException(
                "Request URI must not contain userinfo.",
                nameof(requestUri)
            );
        }

        var scheme = requestUri.Scheme.ToLowerInvariant();
        var host = requestUri.Host.ToLowerInvariant();
        var isDefaultPort =
            (scheme == "http" && requestUri.Port == 80)
            || (scheme == "https" && requestUri.Port == 443);
        var authority = isDefaultPort
            ? host
            : $"{host}:{requestUri.Port.ToString(CultureInfo.InvariantCulture)}";

        var normalizedUri = $"{scheme}://{authority}{requestUri.AbsolutePath}";
        var queryParameters = ParseQueryParameters(requestUri.Query);

        return (normalizedUri, queryParameters);
    }

    private static List<OAuthParameter> ParseQueryParameters(string query)
    {
        var parameters = new List<OAuthParameter>();
        var trimmed = query.TrimStart('?');

        if (trimmed.Length == 0)
        {
            return parameters;
        }

        foreach (var pair in trimmed.Split('&'))
        {
            if (pair.Length == 0)
            {
                continue;
            }

            var separatorIndex = pair.IndexOf('=');
            if (separatorIndex < 0)
            {
                parameters.Add(new OAuthParameter(Uri.UnescapeDataString(pair), string.Empty));
            }
            else
            {
                var key = Uri.UnescapeDataString(pair[..separatorIndex]);
                var value = Uri.UnescapeDataString(pair[(separatorIndex + 1)..]);
                parameters.Add(new OAuthParameter(key, value));
            }
        }

        return parameters;
    }

    /// <summary>
    /// Removes query-string parameters from a post-hook parameter list, one-for-one, so query
    /// parameters never surface in the Authorization header even when their key happens to start
    /// with "oauth_". Parameters added or left untouched by the hook are unaffected.
    /// </summary>
    private static List<OAuthParameter> ExcludeQueryParameters(
        IReadOnlyList<OAuthParameter> parameters,
        IReadOnlyList<OAuthParameter> queryParameters
    )
    {
        var remainingQueryParameters = new List<OAuthParameter>(queryParameters);
        var result = new List<OAuthParameter>(parameters.Count);

        foreach (var parameter in parameters)
        {
            var index = remainingQueryParameters.IndexOf(parameter);
            if (index >= 0)
            {
                remainingQueryParameters.RemoveAt(index);
                continue;
            }

            result.Add(parameter);
        }

        return result;
    }

    private static string BuildNormalizedParameterString(IReadOnlyList<OAuthParameter> parameters)
    {
        var encoded = parameters
            .Select(p => (Key: PercentEncoder.Encode(p.Key), Value: PercentEncoder.Encode(p.Value)))
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ThenBy(p => p.Value, StringComparer.Ordinal);

        return string.Join('&', encoded.Select(p => $"{p.Key}={p.Value}"));
    }

    private static string BuildAuthorizationHeader(
        IReadOnlyList<OAuthParameter> oAuthParameters,
        string signature,
        string? realm
    )
    {
        var builder = new StringBuilder("OAuth ");
        var isFirst = true;

        if (realm is not null)
        {
            builder.Append("realm=\"").Append(EscapeQuotedString(realm)).Append('"');
            isFirst = false;
        }

        foreach (var parameter in oAuthParameters)
        {
            if (!isFirst)
            {
                builder.Append(", ");
            }

            isFirst = false;
            builder
                .Append(parameter.Key)
                .Append("=\"")
                .Append(PercentEncoder.Encode(parameter.Value))
                .Append('"');
        }

        if (!isFirst)
        {
            builder.Append(", ");
        }

        builder.Append("oauth_signature=\"").Append(PercentEncoder.Encode(signature)).Append('"');

        return builder.ToString();
    }

    private static string EscapeQuotedString(string value) =>
        value
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
