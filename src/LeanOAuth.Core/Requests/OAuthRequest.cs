using LeanOAuth.Core.Requests.Common;
using LeanOAuth.Core.Requests.Signatures;

namespace LeanOAuth.Core.Requests;

public abstract class OAuthRequest
{
    public required OAuthRequestMethod RequestMethod { get; init; }
    public required string ConsumerKey { get; init; }
    public required OAuthSignatureMethod SignatureMethod { get; init; }
    public required long Timestamp { get; init; }
    public required string Nonce { get; init; }

    public string Version => "1.0";

    public IDictionary<string, string> AdditionalParameters { get; init; } =
        new Dictionary<string, string>();

    public abstract string GetAuthorizationHeader();

    public abstract string GetAuthorizationQuery();
}
