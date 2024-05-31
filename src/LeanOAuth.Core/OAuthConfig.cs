namespace LeanOAuth.Core;

/// <summary>
/// Represents OAuthConfig data.
/// </summary>
public record OAuthConfig
{
    public string ConsumerKey { get; init; }
    public string ConsumerSecret { get; init; }
    public OAuthSignatureMethod SignatureMethod { get; init; }
    public Uri RequestTokenUrl { get; init; }
    public Uri AccessTokenUrl { get; init; }
    public Uri CallbackUrl { get; init; }
    public string? Realm { get; init; }
    public string Version => "1.0";

    /// <summary>
    /// Creates a new <see cref="OAuthConfig"/> instance.
    /// </summary>
    /// <param name="consumerKey">Consumer key</param>
    /// <param name="consumerSecret">Consumer secret</param>
    /// <param name="signatureMethod">Signature method</param>
    /// <param name="requestTokenUri">Request token uri</param>
    /// <param name="accessTokenUri">AccessTokenUri</param>
    /// <param name="callbackUri">CallbackUri</param>
    /// <param name="realm">Realm</param>
    /// <exception cref="ArgumentNullException">When either a <see cref="ConsumerKey"/> or a <see cref="ConsumerSecret"/> are null.</exception>
    /// <exception cref="ArgumentException">When either a <see cref="ConsumerKey"/> or a <see cref="ConsumerSecret"/> are empty or whitespace.</exception>
    /// <returns>A new <see cref="OAuthConfig"/> instance.</returns>
    public static OAuthConfig Create(
        string consumerKey,
        string consumerSecret,
        OAuthSignatureMethod signatureMethod,
        Uri requestTokenUri,
        Uri accessTokenUri,
        Uri callbackUri,
        string? realm = null
    )
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(consumerKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(consumerSecret);
        ArgumentNullException.ThrowIfNull(signatureMethod);

        return new OAuthConfig(
            consumerKey,
            consumerSecret,
            signatureMethod,
            requestTokenUri,
            accessTokenUri,
            callbackUri,
            realm
        );
    }

    private OAuthConfig(
        string consumerKey,
        string consumerSecret,
        OAuthSignatureMethod signatureMethod,
        Uri requestTokenUrl,
        Uri accessTokenUrl,
        Uri callbackUrl,
        string? realm
    )
    {
        ConsumerKey = consumerKey;
        ConsumerSecret = consumerSecret;
        SignatureMethod = signatureMethod;
        RequestTokenUrl = requestTokenUrl;
        AccessTokenUrl = accessTokenUrl;
        CallbackUrl = callbackUrl;
        Realm = realm;
    }
}