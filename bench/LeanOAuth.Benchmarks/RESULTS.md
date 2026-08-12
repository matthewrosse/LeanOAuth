# Benchmark results

Taken 2026-08-12 on:

- Runtime: .NET 8.0.6 (8.0.6, 8.0.624.26715), Arm64 RyuJIT armv8.0-a
- SDK: .NET SDK 10.0.301
- BenchmarkDotNet: v0.15.8
- Hardware: Apple M2, 8 logical / 8 physical cores, macOS Tahoe 26.5.1 (Darwin 25.5.0)
- Config: `-c Release`, BenchmarkDotNet `DefaultJob`

Reproduce with `dotnet run -c Release` from this directory.

## End-to-end request signing (HMAC-SHA1, single-threaded)

| Method      | Mean     | Allocated |
|------------ |---------:|----------:|
| SignRequest | 5.080 μs |  15.02 KB |

## Percent-encoder in isolation

| Method | Mean     | Allocated |
|------- |---------:|----------:|
| Encode | 246.8 ns |     984 B |

## RSA lock: shared credential vs. separate credentials, by parallelism

Each `SharedKey` row signs through one `RsaSha1ClientCredentials` shared across all parallel
slots (contends on the RSA lock). Each `SeparateKeys` row signs through one credential per
slot, each wrapping its own RSA-2048 key (no contention, identical total RSA work). Both use
`Parallel.For` over the given degree.

| Method       | Parallelism | Mean      | Allocated |
|------------- |------------ |----------:|----------:|
| SharedKey    | 1           |  1.073 ms |   17.9 KB |
| SeparateKeys | 1           |  1.073 ms |  17.89 KB |
| SharedKey    | 2           |  2.147 ms |  34.21 KB |
| SeparateKeys | 2           |  1.114 ms |  34.13 KB |
| SharedKey    | 4           |  4.296 ms |  66.78 KB |
| SeparateKeys | 4           |  1.309 ms |  66.63 KB |
| SharedKey    | 8           |  8.603 ms | 132.03 KB |
| SeparateKeys | 8           |  2.526 ms | 131.48 KB |
| SharedKey    | 16          | 17.219 ms | 262.09 KB |
| SeparateKeys | 16          |  5.711 ms | 259.77 KB |

## Conclusion

The RSA lock binds. `SharedKey` scales linearly with parallelism (1.073 ms → 17.219 ms from 1
to 16, a ~16x increase for a 16x increase in parallel callers), matching full serialization on
the lock: no throughput gain at all from adding concurrent callers signing through the same
key. `SeparateKeys`, doing identical total RSA work with no contention, scales sub-linearly
(1.073 ms → 5.711 ms, ~5.3x) and levels off once parallelism exceeds the machine's 8 physical
cores — the expected shape for CPU-bound work with no lock.

This is the multi-tenant case the library is designed for: a service holding one RSA client
credential and signing concurrently on behalf of many callers gets zero benefit from
parallelism today. **Recommendation: pool.** Give `RsaSha1ClientCredentials` (or its caller) a
small pool of `RSA` instances per key material, round-robin or checked out per signing call,
instead of a single locked instance. That removes the serialization point without widening the
lock's scope, and the `SeparateKeys` numbers above are a reasonable proxy for the ceiling such
a pool could approach.
