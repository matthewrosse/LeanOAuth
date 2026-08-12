using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;
using Microsoft.AspNetCore.Authentication;

namespace LeanOAuth.AspNetCore;

/// <summary>
/// Options for the OAuth 1.0a sign-in handler registered by
/// <see cref="OAuth10AAuthenticationBuilderExtensions.AddOAuth10A"/>.
/// </summary>
public sealed class OAuth10AOptions : RemoteAuthenticationOptions
{
    /// <summary>Creates the options with the default <see cref="OAuth10AEvents"/>.</summary>
    public OAuth10AOptions()
    {
        base.Events = new OAuth10AEvents();
    }

    /// <summary>The client credentials every request in the flow is signed with.</summary>
    public ClientCredentials ClientCredentials { get; set; } = default!;

    /// <summary>The provider's three endpoints.</summary>
    public OAuthProviderEndpoints Endpoints { get; set; } = default!;

    /// <summary>
    /// The realm sent in the "Authorization" header. Optional per RFC 5849 §3.5.1; most providers
    /// do not require it.
    /// </summary>
    public string? Realm { get; set; }

    /// <summary>
    /// The name of the non-standard query parameter some providers use to request a scope on the
    /// temporary credentials request, sent only when <see cref="Scopes"/> is non-empty.
    /// </summary>
    public string ScopeParameterName { get; set; } = "scope";

    /// <summary>The character used to join multiple <see cref="Scopes"/> into one parameter value.</summary>
    public char ScopeParameterSeparator { get; set; } = ',';

    /// <summary>
    /// Scopes to request via <see cref="ScopeParameterName"/>. Empty by default, in which case no
    /// scope parameter is sent — this is a provider extension, not part of RFC 5849.
    /// </summary>
    public ICollection<string> Scopes { get; } = new List<string>();

    /// <summary>The events used to handle the redirect to the authorization endpoint and ticket creation.</summary>
    public new OAuth10AEvents Events
    {
        get => (OAuth10AEvents)base.Events;
        set => base.Events = value;
    }

    /// <summary>Protects the authentication state carried in the cookie between challenge and callback.</summary>
    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;

    /// <inheritdoc />
    public override void Validate()
    {
        base.Validate();

        ArgumentNullException.ThrowIfNull(ClientCredentials);
        ArgumentNullException.ThrowIfNull(Endpoints);
    }
}
