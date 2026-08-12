namespace LeanOAuth.Http;

internal sealed record OutOfBandCallback : OAuthCallback
{
    internal override string Value => "oob";
}
