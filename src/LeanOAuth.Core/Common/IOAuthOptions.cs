namespace LeanOAuth.Core.Common;

public interface IOAuthOptions
{
    string ConsumerKey { get; }
    string ConsumerSecret { get; }
    Uri RequestTokenEndpoint { get; }
    Uri AuthorizationEndpoint { get; }
    Uri AccessTokenEndpoint { get; }
    string Realm { get; }
    ICollection<string> Scopes { get; }
    string ScopeParameterName { get; }
    char ScopeParameterSeparator { get; }
}
