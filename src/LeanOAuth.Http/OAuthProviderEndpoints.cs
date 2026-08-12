namespace LeanOAuth.Http;

/// <summary>
/// The three endpoints a provider exposes for the three-legged flow, per RFC 5849 §2. Belongs
/// per provider instance, unlike temporary and token credentials, which belong per resource owner.
/// </summary>
/// <param name="TemporaryCredentialRequest">Called the "request token URL" in most provider documentation.</param>
/// <param name="ResourceOwnerAuthorization">Where the resource owner is sent to authorize the client.</param>
/// <param name="TokenRequest">Called the "access token URL" in most provider documentation.</param>
public sealed record OAuthProviderEndpoints(
    Uri TemporaryCredentialRequest,
    Uri ResourceOwnerAuthorization,
    Uri TokenRequest
);
