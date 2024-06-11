namespace LeanOAuth.AspNetCore.Exceptions;

public sealed class UnauthorizedTemporaryCredentialsRequestException : Exception
{
    public UnauthorizedTemporaryCredentialsRequestException() { }

    public UnauthorizedTemporaryCredentialsRequestException(string message)
        : base(message) { }

    public UnauthorizedTemporaryCredentialsRequestException(string message, Exception inner)
        : base(message, inner) { }
}
