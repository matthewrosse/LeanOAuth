namespace LeanOAuth.Core.Signatures;

public record OAuthSignatureCreationContext(
    HttpMethod HttpMethod,
    Uri RequestBaseUrl,
    IDictionary<string, string> RequestParameters,
    string ConsumerSecret,
    string TokenSecret
);
