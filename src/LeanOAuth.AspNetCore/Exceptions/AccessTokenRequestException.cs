namespace LeanOAuth.AspNetCore.Exceptions;

public sealed class AccessTokenRequestException : Exception
{
    public AccessTokenRequestException() { }

    public AccessTokenRequestException(string message)
        : base(message) { }

    public AccessTokenRequestException(string message, Exception inner)
        : base(message, inner) { }
}
