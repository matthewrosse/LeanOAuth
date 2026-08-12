using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace LeanOAuth.AspNetCore;

internal sealed class OAuth10APostConfigureOptions(IDataProtectionProvider dataProtectionProvider)
    : IPostConfigureOptions<OAuth10AOptions>
{
    public void PostConfigure(string? name, OAuth10AOptions options)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(options);

        options.DataProtectionProvider ??= dataProtectionProvider;

        if (options.Backchannel is null)
        {
            options.Backchannel = new HttpClient(
                options.BackchannelHttpHandler ?? new HttpClientHandler()
            )
            {
                Timeout = options.BackchannelTimeout,
                MaxResponseContentBufferSize = 10 * 1024 * 1024,
            };
            options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("LeanOAuth");
        }

        if (options.StateDataFormat is null)
        {
            var dataProtector = options.DataProtectionProvider.CreateProtector(
                typeof(OAuth10AHandler).FullName!,
                name,
                "v1"
            );

            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }
    }
}
