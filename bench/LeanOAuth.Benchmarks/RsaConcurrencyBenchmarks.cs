using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using LeanOAuth.Core;
using LeanOAuth.Core.Credentials;

namespace LeanOAuth.Benchmarks;

/// <summary>
/// The RSA lock question: <see cref="RsaSha1ClientCredentials"/> locks signing on the private
/// key instance because RSA implementations are not contractually thread-safe. That serializes
/// same-key signing. These benchmarks measure whether that ceiling binds, by signing at several
/// degrees of parallelism through one shared credential (lock contention) versus through one
/// credential per parallel slot (no contention, same total RSA work), so contention cost is
/// distinguishable from raw signing cost.
/// </summary>
[MemoryDiagnoser]
public class RsaConcurrencyBenchmarks
{
    private static readonly Uri RequestUri = new("https://api.example.com/v1/resources/42");

    [Params(1, 2, 4, 8, 16)]
    public int Parallelism { get; set; }

    private RsaSha1ClientCredentials _sharedCredentials = null!;
    private RsaSha1ClientCredentials[] _separateCredentials = null!;
    private OAuthSigner _signer = null!;

    [GlobalSetup]
    public void GlobalSetup()
    {
        _signer = new OAuthSigner();
        _sharedCredentials = new RsaSha1ClientCredentials("consumer-key", CreateKey());
        _separateCredentials = Enumerable
            .Range(0, Parallelism)
            .Select(_ => new RsaSha1ClientCredentials("consumer-key", CreateKey()))
            .ToArray();
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _sharedCredentials.PrivateKey.Dispose();
        foreach (var credentials in _separateCredentials)
        {
            credentials.PrivateKey.Dispose();
        }
    }

    /// <summary>Same key across every parallel slot: signing serializes on the RSA lock.</summary>
    [Benchmark]
    public void SharedKey() =>
        Parallel.For(
            0,
            Parallelism,
            _ => _signer.Sign(HttpMethod.Get, RequestUri, _sharedCredentials)
        );

    /// <summary>One key per parallel slot: no lock contention, same total RSA work.</summary>
    [Benchmark]
    public void SeparateKeys() =>
        Parallel.For(
            0,
            Parallelism,
            i => _signer.Sign(HttpMethod.Get, RequestUri, _separateCredentials[i])
        );

    private static RSA CreateKey() => RSA.Create(2048);
}
