using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Abstractions;

public interface IOAuthHeaderFactory<TOAuthOptions>
    where TOAuthOptions : IOAuthOptions
{
    string CreateRequestTokenHeader(
        HttpMethod httpMethod,
        IDictionary<string, string> additionalParameters
    );
}
