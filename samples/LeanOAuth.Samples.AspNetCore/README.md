# LeanOAuth.Samples.AspNetCore

"Sign in with OAuth 1.0a" using `LeanOAuth.AspNetCore`. Provider-neutral — every provider-specific
value comes from configuration, not code.

## Run

Set the provider's endpoints and your client credentials with `dotnet user-secrets`, from this
directory:

```sh
dotnet user-secrets set OAuth10A:ConsumerKey "your-consumer-key"
dotnet user-secrets set OAuth10A:ConsumerSecret "your-consumer-secret"
dotnet user-secrets set OAuth10A:TemporaryCredentialRequestUri "https://example.com/oauth/request_token"
dotnet user-secrets set OAuth10A:ResourceOwnerAuthorizationUri "https://example.com/oauth/authorize"
dotnet user-secrets set OAuth10A:TokenRequestUri "https://example.com/oauth/access_token"
dotnet run
```

The consumer secret configures HMAC-SHA1 credentials; for RSA-SHA1 or PLAINTEXT providers, edit
`Program.cs` to construct the matching `ClientCredentials` type.

Navigate to `/`, sign in, and `/account` shows the claims from the resulting ticket. This sample
does not fetch or expose provider profile data itself — RFC 5849 defines no standard profile
endpoint — see `OAuth10AEvents.OnCreatingTicket` for how a consumer would sign its own request
against `OAuth10ACreatingTicketContext.Backchannel` to fetch one.
