using System.Text.Json.Serialization;

namespace LeanOAuth.Core.Responses;

public record UnauthorizedRequestTokenResponse(
    [property: JsonPropertyName("oauth_token")] string Token,
    [property: JsonPropertyName("oauth_token_secret")] string TokenSecret,
    [property: JsonPropertyName("oauth_callback_confirmed")] bool CallbackConfirmed
);
