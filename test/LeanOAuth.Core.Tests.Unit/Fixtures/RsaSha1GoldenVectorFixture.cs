namespace LeanOAuth.Core.Tests.Unit.Fixtures;

/// <summary>
/// A fixed RSA key and its RSA-SHA1 signature over a fixed OAuth 1.0a base string, computed
/// independently with `openssl dgst -sha1 -sign`. The golden vector RSA-SHA1 signing tests
/// assert their signer output against.
/// </summary>
public static class RsaSha1GoldenVectorFixture
{
    public const string ConsumerKey = "consumer-key";
    public const string Nonce = "abcdef1234567890";
    public const string Timestamp = "1000000000";

    public static readonly HttpMethod HttpMethod = HttpMethod.Get;
    public static readonly Uri RequestUri = new("http://example.com/resource");

    public const string ExpectedSignatureBaseString =
        "GET&http%3A%2F%2Fexample.com%2Fresource&oauth_consumer_key%3Dconsumer-key%26oauth_nonce%3Dabcdef1234567890%26oauth_signature_method%3DRSA-SHA1%26oauth_timestamp%3D1000000000%26oauth_version%3D1.0";

    public const string ExpectedSignature =
        "boLH0bRDnxwixIr96sR24kdfG1p5at+HchDbVKSdqbES2xpV174jPV2RvKTXkuFIdUhXD1PYNnpEA68HmDQADCu7gZMcACNdCCzT1vC10jld/Q7PfSuyjBLvASiAL0+wi+SI2/lmlnKrU6R5egzpr2tX76Ol1ariTjS9V03AD3MZDVmDGGwaeHSH5oY/tCB9pkyXhiKyhAVkW1f7biwCQNQLNzGGYXhwSzaZiR6ZdYwpmL/whLk1Qu7sVg/OZMUsq3Pz7t6pNmHysfCfZFz42FFWLgziuWLOkTHlYouGX7+ztmQ94L/8pnv4MDMZVnUd75fN3ijXZhI8l7sNUkeKIA==";

    public const string PrivateKeyPem = """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCn9s1fQbrOi0i8
        E4aWmMsO7woEV5cOVPg4aStwR7KO6buu9YdfAIxlFkiepUNNn/qhcQIDT4ruL0Vd
        xk3ral3FXpRI/gNbthzbiNHL6NQkbKbqjWdJmnbWnuiZ+1KGyYrkg1/n3o0yvsPG
        G1jB4qTk7n469LJP0Bn3bCpIukMNq/wDd2CsdSZQXHLC1YAzOY/KidrLLAgl4tUF
        FnZdcV5TA7fhDqJojP0w/D6euvsSQkQMsMTN8rT9q5jlhuA39CS7KRbPY3xxPVDW
        VsAKUAxyivywDd5YWn9CgKGMp27vtAqZvkxmGhG/9ppUV7vR5653wSxEZIZPlhOP
        cR0IKWcBAgMBAAECggEAItsegPlauzCf6jnSGRABuaplBYQoypZbAZffphgW5739
        DyCQVGiAehze+p84oZQEtrqFLKs13Vptdnmn42YKKiKHusMN7tsSz4Mr6Hk7hwiO
        NggcqmNV7JGDGytS07pg6q2RukROwHxik8rKh0fRqNmOVA1CMLpynQwzFS8kKaKT
        0iG+Tn5j5h4l7GcWaoaGHb650V57m2BMlg/hIhdLWH6iqHn15f6WYcj8EZwunyaR
        +15C8F8NhzZwDkbqmYMZPBlLOFMuSCBNbndmIeEXefN9FUU8X4ycnXDW8fCvVXEm
        u/+3Nc97PNO7795xuI18DvJlCyt/REgjzJji4ZorLQKBgQDopDbCexU979GfjXmz
        3qKyat4A4E+nhiikdbVON2cKy8eUGFz25aE32LlsxK338085o60yFF/rc3m6MPor
        VrZ4x0EKzuMncydSLXZi6P+SwDX9HbwD/LmY86gALP3e+yxVLgKyQaIHZT0DT1Yc
        cMLLvT7+ncs3RWOcwshPV/xxPQKBgQC41CEJ22VjJX9ueHLr0JVdmgHfO7Iwv/RQ
        /rqMlb91UK0gtX8xeN6ido4C/htLbIQfYC01fb1F6LTnCQKBHhB1XdQip0bNOEa1
        RIm1m6RarNm15b9b3FsYcUsiSdRofDxzRMUPwQDr9ph3LtMDwkSRVDgxqK2VH2mg
        6qQnkHxhFQKBgBq+dgUZfTGnliOPcgQ5fd6g5nCXWNDbXWS6m2Mof1IAZyshOd6w
        Oz5eTcKxQYaVk+/+XvS43uYEWmQLKVc+Gq/7yABkFDz+wfByhX+NZYQLUKmOd4TF
        0thAenm6slyl50zLg0fWv7e17bOptS6D0AD3+nvuy+PIuFDXG4vzg3PJAoGASvkB
        TdZJEiarwkvpke5SKF3IVJ0KcuvqVtB9K3my6AuJrrLwnUjCRnSAtoYM3FNwZKnG
        rOQMWsdCWlU1RtrDIlilLEleVvB0/iKHGbvAt2dWCIrhTIneCdQq/gWku51ph/hl
        VzabARxOTEoaHnQ3DBx1ju81OkA7wKJtY/8f9OECgYEA3Lov8U42Nz/+M9nXqOQX
        HglKsUGp6UyZzbS21Dai7HZr12YYzUkdgLKP2F2vlmU0tsuvI0hcubG+pDTQHjJP
        UkbzacBFhvBy9xSoquFPUTEmf+UczBZH6LuixPYDytQj3NLfav+sfqPCYKgh1Dlm
        eITSTd/NB6EDmOouu6K9Q8E=
        -----END PRIVATE KEY-----
        """;
}
