namespace LeanOAuth.AspNetCore.Exceptions;

/// <summary>
/// Used to throw when there was an unsuccessful attempt to obtain a request token. Mostly caused by providing invalid credentials.
/// </summary>
public sealed class UnauthorizedTemporaryCredentialsRequestException : Exception
{
    public UnauthorizedTemporaryCredentialsRequestException() { }

    public UnauthorizedTemporaryCredentialsRequestException(string message)
        : base(message) { }

    public UnauthorizedTemporaryCredentialsRequestException(string message, Exception inner)
        : base(message, inner) { }
}
