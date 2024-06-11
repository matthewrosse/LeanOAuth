using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore;

public record OAuth10ATokenExchangeContext(
    AuthenticationProperties Properties,
    string Token,
    string TokenSecret,
    string Verifier
);
