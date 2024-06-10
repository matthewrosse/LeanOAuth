using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace LeanOAuth.AspNetCore.Options;

public class OAuth10APostConfigureOptions<TOptions, THandler>(IDataProtectionProvider dp)
    : IPostConfigureOptions<TOptions>
    where TOptions : OAuth10AOptions, new()
    where THandler : OAuth10AHandler<TOptions>
{
    public void PostConfigure(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(name);

        options.DataProtectionProvider ??= dp;

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (options.Backchannel is null)
        {
            options.Backchannel = new HttpClient(
                options.BackchannelHttpHandler ?? new HttpClientHandler()
            );
            options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Microsoft ASP.NET Core OAuth handler"
            );
            options.Backchannel.Timeout = options.BackchannelTimeout;
            options.Backchannel.MaxResponseContentBufferSize = 10485760L;
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (options.StateDataFormat is null)
        {
            var dataProtector = options.DataProtectionProvider.CreateProtector(
                typeof(THandler).FullName!,
                name,
                "v1"
            );

            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }
    }
}
