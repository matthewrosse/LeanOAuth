using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Abstractions;

public interface IOAuthHeaderFactory<TOAuthOptions>
    where TOAuthOptions : IOAuthOptions
{
    string CreateRequestTokenRequestHeader(HttpMethod httpMethod, Uri callbackUrl);

    string CreateRequestTokenRequestHeader(
        HttpMethod httpMethod,
        Uri callbackUrl,
        IDictionary<string, string> additionalParameters
    );

    string CreateAccessTokenRequestHeader(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier
    );

    string CreateAccessTokenRequestHeader(
        HttpMethod httpMethod,
        string token,
        string tokenSecret,
        string verifier,
        IDictionary<string, string> additionalParameters
    );
}
