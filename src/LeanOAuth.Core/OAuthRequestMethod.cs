namespace LeanOAuth.Core;

public sealed class OAuthRequestMethod : Enumeration<OAuthRequestMethod>
{
    public static readonly OAuthRequestMethod Get = new(1, "GET");
    public static readonly OAuthRequestMethod Post = new(2, "POST");

    private OAuthRequestMethod(int value, string name)
        : base(value, name) { }
}
