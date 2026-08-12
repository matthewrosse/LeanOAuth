using BenchmarkDotNet.Attributes;
using LeanOAuth.Core.PercentEncoding;

namespace LeanOAuth.Benchmarks;

/// <summary>
/// The percent-encoder in isolation. Every signed parameter, key, and value passes through it,
/// often several times per request.
/// </summary>
[MemoryDiagnoser]
public class PercentEncoderBenchmarks
{
    private const string Value = "https://api.example.com/v1/resources?name=Jane Doe & Co.";

    [Benchmark]
    public string Encode() => PercentEncoder.Encode(Value);
}
