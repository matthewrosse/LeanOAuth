namespace LeanOAuth.Core.Responses;

public record UnauthorizedRequestTokenResponse(
    string Token,
    string TokenSecret,
    bool CallbackConfirmed
);
