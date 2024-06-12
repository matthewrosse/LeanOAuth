## Table of contents
- [Table of contents](#table-of-contents)
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Usage outside of ASP.NET Core](#usage-outside-of-aspnet-core)
- [Contributing](#contributing)
- [License](#license)
## Introduction

LeanOAuth is an open-source implementation of OAuth1.0A RFC 5849 protocol in .NET. 
It provides a set of robust packages for integration with ASP.NET Core and dependency injection container,
making it easy to add OAuth1.0A authorization to your .NET and ASP.NET Core applications.

Are you trying to integrate with a legacy service that hasn't moved to OAuth2.0/OpenIdConnect yet?

Do you wish there was a way to add OAuth1.0A authorization to your application
in a similar way to OAuth2.0, but all packages have already been archived for a decade?

Then LeanOAuth is the way to go.

## Features

- **OAuth1.0A Implementation**: Provides a robust implementation of OAuth1.0A protocol.
- **Application type ignorance**: If you need to use OAuth1.0A in your console application, or in a WinForms app, the Core package has you covered.
- **ASP.NET Core Integration**: Seamlessly integrates with ASP.NET Core authentication middleware mechanisms.
- *Dependency Injection Support**: Easy to configure using dependency injection extension methods. All you need is to call one method on the ServiceProvider.

## Installation

You can install LeanOAuth via NuGet Package Manager:

- Core package that handles signature generation, etc:
```sh
dotnet add package LeanOAuth.Core
```
- ASP.NET Core package with dependency injection extensions:

```sh
dotnet add package LeanOAuth.AspNetCore
dotnet add package LeanOAuth.AspNetCore.DependencyInjection
```

## Usage
It's almost exactly the same as if you were implementing OAuth2, just call this extension method and set correct options:

```csharp
builder.Services.AddOAuth10A("schema_name", opts => {});
```

More examples:

```csharp
using System.Security.Claims;
using System.Text.Json;
using LeanOAuth.AspNetCore.DependencyInjection;
using LeanOAuth.Core;
using LeanOAuth.Core.Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateBuilder(args);

builder
    .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOAuth10A(
        "scheme_name",
        options =>
        {
            options.Realm = "realm";
            options.ConsumerKey = "consumer_key";
            options.ConsumerSecret = "consumer_secret";
            options.RequestTokenEndpoint = new Uri(
                "https://example.com/request_token"
            );
            options.AuthorizationEndpoint = new Uri(
                "https://example.com/authorize"
            );
            options.AccessTokenEndpoint = new Uri(
                "https://example.com/access_token"
            );
            options.UserInformationEndpoint = new Uri(
                "https://example.com/users"
            );
            options.CallbackPath = "/api/auth/callback";
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Scopes.Add("email");
            options.Scopes.Add("photo");
            options.Scopes.Add("payments");
            options.ScopeParameterName = "scopes";
            options.ScopeParameterSeparator = '|';
            options.SaveTokens = true;
            options.ClaimActions.MapJsonKey("sub", "id");
            options.ClaimActions.MapJsonKey("first_name", "first_name");
            options.ClaimActions.MapJsonKey("last_name", "last_name");
            options.Events.OnCreatingTicket = async ctx =>
            {
                var protectedResourceParameters =
                    ctx.AuthorizationParametersFactory.CreateProtectedResourceRequestParameters(
                        options.UserInformationEndpoint,
                        HttpMethod.Get,
                        ctx.Token,
                        ctx.TokenSecret
                    );

                var authorizationHeaderValue = OAuthTools.GenerateAuthorizationHeaderValue(
                    protectedResourceParameters,
                    options.Realm
                );

                var requestMessage = OAuthRequestHelpers.PrepareGetRequestMessage(
                    options.UserInformationEndpoint,
                    authorizationHeaderValue
                );

                var result = await ctx.Backchannel.SendAsync(requestMessage);

                var user = await result.Content.ReadFromJsonAsync<JsonElement>();

                ctx.RunClaimActions(user);
            };
        }
    );

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", () => "Hello World!");

app.MapGet(
    "/api/auth/auth_provider",
    () =>
        Results.Challenge(
            new AuthenticationProperties { RedirectUri = "http://localhost:8080/api/dashboard" },
            ["scheme_name"]
        )
);

app.MapGet(
    "/api/user",
    (ClaimsPrincipal claimsPrincipal) =>
    {
        var claims = claimsPrincipal.Claims.Select(x => new { x.Type, x.Value }).ToArray();
        return Results.Ok(claims);
    }
);

app.Run();
```

## Usage outside of ASP.NET Core
If you want to use this library outside of ASP.NET Core, you just need to install LeanOAuth.Core package and construct OAuthAuthorizationParametersFactory yourself.

```csharp
// How you set these options is up to you. Something like AzureKeyVault is recommended.

record MyOAuth10AOptions(
    string ConsumerKey,
    string ConsumerSecret,
    Uri RequestTokenEndpoint,
    Uri AuthorizationEndpoint,
    Uri AccessTokenEndpoint,
    string Realm,
    ICollection<string> Scopes,
    string ScopeParameterName,
    char ScopeParameterSeparator
    ) : IOAuthOptions;

var myOAuth10AOptions = new MyOAuth10AOptions();

var authorizationParametersFactory = new OAuthAuthorizationParametersFactory<MyOAuth10AOptions>(myOAuth10AOptions,
    new OAuthHmacSha1SignatureCalculator(), TimeProvider.System, new CryptographicallySecureNonceGenerator());

var parameters = authorizationParametersFactory.CreateRequestTokenRequestParameters(HttpMethod.Post,
    new Uri("https://example.com/callback"));

var authorizationHeader = OAuthTools.GenerateAuthorizationHeaderValue(parameters, "SOME_REALM");
var requestMessage = OAuthRequestHelpers.PreparePostRequestMessage(new Uri("https://example.com/asdf"), authorizationHeader);

// For demonstration purposes only, you should handle HttpClient lifetime either via aspnet core di container or some static variable
// because you risk ending up with sockets starvation.
using var httpClient = new HttpClient();

var response = await httpClient.SendAsync(requestMessage);
```

## Contributing
Contributions are welcome! Please fork the repository and submit pull requests for any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the [a link](https://github.com/matthewrosse/LeanOAuth/blog/main/LICENSE)