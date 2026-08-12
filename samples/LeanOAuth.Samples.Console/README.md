# LeanOAuth.Samples.Console

Runs the OAuth 1.0a out-of-band flow (RFC 5849 §2) against any provider named on the command
line. No provider-specific code.

```sh
dotnet run --project samples/LeanOAuth.Samples.Console -- \
  --temporary-credential-request-uri https://example.com/oauth/request_token \
  --resource-owner-authorization-uri https://example.com/oauth/authorize \
  --token-request-uri https://example.com/oauth/access_token \
  --consumer-key YOUR_CONSUMER_KEY \
  --consumer-secret YOUR_CONSUMER_SECRET
```

For an RSA-SHA1 provider, pass `--rsa-private-key-file path/to/key.pem` instead of
`--consumer-secret`. For a PLAINTEXT provider, add `--signature-method plaintext`.

The program requests temporary credentials, prints the authorization URL to open in a browser,
prompts for the verifier the provider displays, and exchanges it for token credentials.
