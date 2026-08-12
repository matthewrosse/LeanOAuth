namespace LeanOAuth.Core.Nonce;

/// <summary>Generates the nonce included with every signed request. Substitutable in tests.</summary>
public interface INonceGenerator
{
    /// <summary>Returns a new nonce value.</summary>
    string GenerateNonce();
}
