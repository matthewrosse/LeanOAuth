namespace LeanOAuth.Core;

/// <summary>Supplies the current time used for the "oauth_timestamp" parameter. Substitutable in tests.</summary>
public interface IClock
{
    /// <summary>The current time.</summary>
    DateTimeOffset UtcNow { get; }
}
