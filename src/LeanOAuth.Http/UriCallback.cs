namespace LeanOAuth.Http;

internal sealed record UriCallback(Uri Uri) : OAuthCallback
{
    internal override string Value => Uri.AbsoluteUri;
}
