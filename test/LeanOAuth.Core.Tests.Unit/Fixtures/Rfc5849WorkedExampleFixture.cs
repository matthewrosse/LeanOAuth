namespace LeanOAuth.Core.Tests.Unit.Fixtures;

/// <summary>
/// The worked example from RFC 5849 §1.2, carried forward from the v1 test suite.
/// The golden vector later tickets assert their signer output against.
/// </summary>
public static class Rfc5849WorkedExampleFixture
{
    public const string ConsumerKey = "dpf43f3p2l4k3l03";
    public const string ConsumerSecret = "kd94hf93k423kf44";
    public const string Token = "nnch734d00sl2jdk";
    public const string TokenSecret = "pfkkdhi9sl3r4s00";
    public const string Nonce = "kllo9940pd9333jh";
    public const string Timestamp = "1191242096";

    public static readonly HttpMethod HttpMethod = HttpMethod.Get;
    public static readonly Uri RequestUri = new("http://photos.example.net/photos");

    public static readonly IReadOnlyList<KeyValuePair<string, string>> RequestParameters = new[]
    {
        new KeyValuePair<string, string>("file", "vacation.jpg"),
        new KeyValuePair<string, string>("size", "original"),
    };

    public const string ExpectedSignature = "tR3+Ty81lMeYAr/Fid0kMTYa/WM=";
}
