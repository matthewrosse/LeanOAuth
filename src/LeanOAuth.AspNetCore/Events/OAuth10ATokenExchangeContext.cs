using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore.Events;

public record OAuth10ATokenExchangeContext(
    AuthenticationProperties Properties,
    string Token,
    string TokenSecret,
    string Verifier
);
