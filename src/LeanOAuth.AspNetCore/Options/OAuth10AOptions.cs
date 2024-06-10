using LeanOAuth.Core.Common;
using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore.Options;

public class OAuth10AOptions : RemoteAuthenticationOptions, IOAuthOptions
{
    public string ConsumerKey { get; set; } = default!;
    public string ConsumerSecret { get; set; } = default!;
    public Uri RequestTokenEndpoint { get; set; } = default!;
    public Uri AuthorizationEndpoint { get; set; } = default!;
    public Uri AccessTokenEndpoint { get; set; } = default!;
    public string Realm { get; set; } = default!;
    public ICollection<string> Scopes { get; } = new List<string>();
    public string ScopeParameterName { get; set; } = default!;
    public char ScopeParameterSeparator { get; set; }

    /// <summary>
    /// Check that the options are valid. Should throw an exception if things are not ok.
    /// </summary>
    public override void Validate()
    {
        base.Validate();

        ArgumentException.ThrowIfNullOrEmpty(ConsumerKey);
        ArgumentException.ThrowIfNullOrEmpty(ConsumerSecret);
        ArgumentNullException.ThrowIfNull(RequestTokenEndpoint);
        ArgumentNullException.ThrowIfNull(AuthorizationEndpoint);
        ArgumentNullException.ThrowIfNull(AccessTokenEndpoint);
        ArgumentException.ThrowIfNullOrEmpty(Realm);
        ArgumentException.ThrowIfNullOrEmpty(ScopeParameterName);

        if (!CallbackPath.HasValue)
        {
            throw new ArgumentException("CallbackPath must be provided!");
        }
    }

    /// <summary>
    /// Gets or sets the <see cref="OAuth10AEvents"/> used to handle authentication events.
    /// </summary>
    public new OAuth10AEvents Events
    {
        get => (OAuth10AEvents)base.Events;
        set => base.Events = value;
    }

    /// <summary>
    /// Gets or sets the type used to secure data handled by the middleware.
    /// </summary>
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;
}
