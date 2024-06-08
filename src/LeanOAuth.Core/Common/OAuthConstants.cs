namespace LeanOAuth.Core.Common;

public static class OAuthConstants
{
    public const string AuthorizationHeader = "Authorization";
    public const string Version = "1.0";

    public static class ParameterNames
    {
        public const string ConsumerKey = "oauth_consumer_key";
        public const string Nonce = "oauth_nonce";
        public const string Timestamp = "oauth_timestamp";
        public const string SignatureMethod = "oauth_signature_method";
        public const string Signature = "oauth_signature_method";
        public const string Version = "oauth_version";
        public const string Callback = "oauth_callback";
        public const string Token = "oauth_token";
        public const string TokenSecret = "oauth_token_secret";
        public const string Verifier = "oauth_verifier";
    }

    public static class Responses
    {
        public static class UnauthorizedRequestToken
        {
            public const string Token = "oauth_token";
            public const string TokenSecret = "oauth_token_secret";
            public const string CallbackConfirmed = "oauth_callback_confirmed";
        }
    }

    public static class SignatureMethods
    {
        public const string HmacSha1 = "HMAC-SHA1";
        public const string PlainText = "PLAINTEXT";
    }
}
