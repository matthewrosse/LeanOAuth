using Microsoft.Extensions.Logging;

namespace LeanOAuth.AspNetCore;

/// <summary>
/// Log messages for <see cref="OAuth10AHandler"/>. Carries scheme names and exception type names
/// only — never a parameter value, secret, or signature.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "Requesting temporary credentials from the provider for scheme '{Scheme}'."
    )]
    public static partial void RequestingTemporaryCredentials(ILogger logger, string scheme);

    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "Redirecting to the authorization endpoint for scheme '{Scheme}'."
    )]
    public static partial void RedirectingToAuthorizationEndpoint(ILogger logger, string scheme);

    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Exchanging the verifier for token credentials failed for scheme '{Scheme}'."
    )]
    public static partial void TokenExchangeFailed(ILogger logger, string scheme);

    [LoggerMessage(Level = LogLevel.Debug, Message = "OAuth 1.0a sign-in succeeded for scheme '{Scheme}'.")]
    public static partial void SignInSucceeded(ILogger logger, string scheme);
}
