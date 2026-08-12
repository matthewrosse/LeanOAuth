using LeanOAuth.Core;

namespace LeanOAuth.Http.Tests.Unit.Testing;

internal sealed class MutableClock(DateTimeOffset utcNow) : IClock
{
    public DateTimeOffset UtcNow { get; set; } = utcNow;
}
