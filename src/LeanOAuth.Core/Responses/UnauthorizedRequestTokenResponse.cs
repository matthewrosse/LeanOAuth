using System.Text.Json.Serialization;
using LeanOAuth.Core.Common;

namespace LeanOAuth.Core.Responses;

public record UnauthorizedRequestTokenResponse(
    [property: JsonPropertyName(OAuthConstants.Responses.UnauthorizedRequestToken.Token)]
        string Token,
    [property: JsonPropertyName(OAuthConstants.Responses.UnauthorizedRequestToken.TokenSecret)]
        string TokenSecret,
    [property: JsonPropertyName(
        OAuthConstants.Responses.UnauthorizedRequestToken.CallbackConfirmed
    )]
        bool CallbackConfirmed
);
