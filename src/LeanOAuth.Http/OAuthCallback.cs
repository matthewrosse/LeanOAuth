namespace LeanOAuth.Http;

/// <summary>
/// The callback a client registers when requesting temporary credentials: either out-of-band or
/// a URI. Closed rather than a nullable string, because RFC 5849 §2.1 requires the literal
/// "oob" when there is no callback, and a nullable string invites both a typo and a forgotten
/// argument. This hierarchy is closed and cannot be extended from outside the package.
/// </summary>
public abstract record OAuthCallback
{
    private protected OAuthCallback() { }

    /// <summary>No callback is registered; the provider displays the verifier for the resource owner to paste.</summary>
    public static OAuthCallback OutOfBand { get; } = new OutOfBandCallback();

    /// <summary>The provider redirects the resource owner to <paramref name="uri"/> with the verifier attached.</summary>
    public static OAuthCallback For(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        return new UriCallback(uri);
    }

    /// <summary>The value sent as "oauth_callback": the literal "oob", or the callback URI.</summary>
    internal abstract string Value { get; }
}
