using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Abstractions;

public interface IOAuthHeaderFactory<TOAuthOptions>
    where TOAuthOptions : IOAuthOptions
{
    string CreateRequestTokenHeader(HttpMethod httpMethod, Uri callbackUrl);

    string CreateRequestTokenHeader(
        HttpMethod httpMethod,
        Uri callbackUrl,
        IDictionary<string, string> additionalParameters
    );
}
