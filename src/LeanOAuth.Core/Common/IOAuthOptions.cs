namespace LeanOAuth.Core.Common;

public interface IOAuthOptions
{
    public string ConsumerKey { get; }
    public string ConsumerSecret { get; }
    public Uri RequestTokenEndpoint { get; }
    public Uri AuthorizationEndpoint { get; }
    public Uri AccessTokenEndpoint { get; }
    public Uri CallbackEndpoint { get; }
    public string Realm { get; }
}
