using BenchmarkDotNet.Attributes;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;

namespace LeanOAuth.Benchmarks;

/// <summary>
/// End-to-end signing of a representative request, HMAC-SHA1, single-threaded. Every signed
/// request pays this path regardless of signature method.
/// </summary>
[MemoryDiagnoser]
public class SigningBenchmarks
{
    private static readonly Uri RequestUri = new(
        "https://api.example.com/v1/resources/42?status=active&sort=-created_at"
    );
    private static readonly IReadOnlyList<OAuthParameter> AdditionalParameters =
    [
        new OAuthParameter("field", "name,email,created_at"),
    ];

    private readonly OAuthSigner _signer = new();
    private readonly HmacSha1ClientCredentials _credentials = new(
        "consumer-key",
        "consumer-secret"
    );
    private readonly OAuthToken _token = new("token", "token-secret");

    [Benchmark]
    public OAuthSignature SignRequest() =>
        _signer.Sign(
            HttpMethod.Get,
            RequestUri,
            _credentials,
            _token,
            AdditionalParameters
        );
}
