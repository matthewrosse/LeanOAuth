namespace LeanOAuth.Core;

/// <summary>
/// Runs against the parameter set before the signature is computed, so a caller can add or
/// drop parameters for a non-conformant provider and have the result covered by the signature.
/// </summary>
public delegate IReadOnlyList<OAuthParameter> ParameterHook(
    IReadOnlyList<OAuthParameter> parameters
);
