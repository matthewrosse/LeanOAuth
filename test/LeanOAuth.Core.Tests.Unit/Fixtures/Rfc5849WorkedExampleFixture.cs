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

    public const string ExpectedSignatureBaseString =
        "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal";

    public const string ExpectedAuthorizationHeaderValue =
        "OAuth oauth_consumer_key=\"dpf43f3p2l4k3l03\", oauth_token=\"nnch734d00sl2jdk\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1191242096\", oauth_nonce=\"kllo9940pd9333jh\", oauth_version=\"1.0\", oauth_signature=\"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D\"";
}
