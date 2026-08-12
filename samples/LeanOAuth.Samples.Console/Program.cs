// Runs the OAuth 1.0a out-of-band flow (RFC 5849 §2) against any provider, named on the command
// line rather than in code. No provider-specific code lives here.
//
// Usage:
//   dotnet run --
//     --temporary-credential-request-uri https://example.com/oauth/request_token
//     --resource-owner-authorization-uri https://example.com/oauth/authorize
//     --token-request-uri https://example.com/oauth/access_token
//     --consumer-key YOUR_CONSUMER_KEY
//     --consumer-secret YOUR_CONSUMER_SECRET
//
// For an RSA-SHA1 provider, pass --rsa-private-key-file path/to/key.pem instead of
// --consumer-secret. For a PLAINTEXT provider, pass --signature-method plaintext alongside
// --consumer-secret.

using System.Security.Cryptography;
using LeanOAuth.Core.Credentials;
using LeanOAuth.Http;

var options = ParseArguments(args);
if (options is null)
{
    return 1;
}

var clientCredentials = BuildClientCredentials(options);
var endpoints = new OAuthProviderEndpoints(
    options.TemporaryCredentialRequestUri,
    options.ResourceOwnerAuthorizationUri,
    options.TokenRequestUri
);

using var httpClient = new HttpClient();
var flow = new OAuthFlow(httpClient, endpoints, clientCredentials);

Console.WriteLine("Requesting temporary credentials...");
var temporaryCredentials = await flow.RequestTemporaryCredentialsAsync(OAuthCallback.OutOfBand);

var authorizationUri = flow.BuildAuthorizationUri(temporaryCredentials);
Console.WriteLine();
Console.WriteLine("Open this URL, authorize the client, and copy the verifier it displays:");
Console.WriteLine(authorizationUri);
Console.WriteLine();
Console.Write("Verifier: ");
var verifier = Console.ReadLine();

if (string.IsNullOrWhiteSpace(verifier))
{
    Console.Error.WriteLine("No verifier entered.");
    return 1;
}

Console.WriteLine("Exchanging the verifier for token credentials...");
var tokenCredentials = await flow.ExchangeAsync(temporaryCredentials, verifier.Trim());

Console.WriteLine();
Console.WriteLine("Token credentials obtained:");
Console.WriteLine($"  oauth_token:        {tokenCredentials.Token}");
Console.WriteLine($"  oauth_token_secret: {tokenCredentials.TokenSecret}");

return 0;

static ClientCredentials BuildClientCredentials(SampleOptions options)
{
    if (options.RsaPrivateKeyFile is { } rsaKeyFile)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(rsaKeyFile));
        return new RsaSha1ClientCredentials(options.ConsumerKey, rsa);
    }

    if (options.ConsumerSecret is null)
    {
        throw new InvalidOperationException(
            "Either --consumer-secret or --rsa-private-key-file is required."
        );
    }

    return options.SignatureMethod switch
    {
        "plaintext"
            => new PlainTextClientCredentials(options.ConsumerKey, options.ConsumerSecret),
        "hmac-sha1"
            => new HmacSha1ClientCredentials(options.ConsumerKey, options.ConsumerSecret),
        var unknown
            => throw new InvalidOperationException($"Unknown --signature-method '{unknown}'."),
    };
}

static SampleOptions? ParseArguments(string[] rawArguments)
{
    var values = new Dictionary<string, string>(StringComparer.Ordinal);

    for (var i = 0; i < rawArguments.Length; i++)
    {
        var argument = rawArguments[i];
        if (!argument.StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        var name = argument[2..];
        if (i + 1 >= rawArguments.Length)
        {
            Console.Error.WriteLine($"Missing value for --{name}.");
            return null;
        }

        values[name] = rawArguments[++i];
    }

    if (
        !TryRequire(values, "temporary-credential-request-uri", out var temporaryCredentialRequestUri)
        || !TryRequire(values, "resource-owner-authorization-uri", out var resourceOwnerAuthorizationUri)
        || !TryRequire(values, "token-request-uri", out var tokenRequestUri)
        || !TryRequire(values, "consumer-key", out var consumerKey)
    )
    {
        PrintUsage();
        return null;
    }

    return new SampleOptions(
        new Uri(temporaryCredentialRequestUri),
        new Uri(resourceOwnerAuthorizationUri),
        new Uri(tokenRequestUri),
        consumerKey,
        values.GetValueOrDefault("consumer-secret"),
        values.GetValueOrDefault("rsa-private-key-file"),
        values.GetValueOrDefault("signature-method", "hmac-sha1")
    );
}

static bool TryRequire(
    Dictionary<string, string> values,
    string name,
    out string value
)
{
    if (values.TryGetValue(name, out var found))
    {
        value = found;
        return true;
    }

    Console.Error.WriteLine($"Missing required --{name}.");
    value = string.Empty;
    return false;
}

static void PrintUsage()
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("Required:");
    Console.Error.WriteLine("  --temporary-credential-request-uri <uri>");
    Console.Error.WriteLine("  --resource-owner-authorization-uri <uri>");
    Console.Error.WriteLine("  --token-request-uri <uri>");
    Console.Error.WriteLine("  --consumer-key <key>");
    Console.Error.WriteLine("Credentials (one of):");
    Console.Error.WriteLine("  --consumer-secret <secret>              (HMAC-SHA1, or PLAINTEXT with --signature-method plaintext)");
    Console.Error.WriteLine("  --rsa-private-key-file <path-to-pem>    (RSA-SHA1)");
}

internal sealed record SampleOptions(
    Uri TemporaryCredentialRequestUri,
    Uri ResourceOwnerAuthorizationUri,
    Uri TokenRequestUri,
    string ConsumerKey,
    string? ConsumerSecret,
    string? RsaPrivateKeyFile,
    string SignatureMethod
);
