using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Signatures;

public record OAuthSignatureCreationContext(
    HttpMethod HttpMethod,
    Uri RequestBaseUrl,
    IList<OAuthParameter> RequestParameters,
    string ConsumerSecret,
    string TokenSecret
);
