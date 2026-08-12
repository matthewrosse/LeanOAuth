using System.Net;
using LeanOAuth.Core;

namespace LeanOAuth.Http;

/// <summary>Parses an "application/x-www-form-urlencoded" body into key/value pairs.</summary>
internal static class FormUrlEncodedBody
{
    public static List<OAuthParameter> Parse(string body)
    {
        var parameters = new List<OAuthParameter>();

        if (body.Length == 0)
        {
            return parameters;
        }

        foreach (var pair in body.Split('&'))
        {
            if (pair.Length == 0)
            {
                continue;
            }

            var separatorIndex = pair.IndexOf('=');
            var key = separatorIndex < 0 ? pair : pair[..separatorIndex];
            var value = separatorIndex < 0 ? string.Empty : pair[(separatorIndex + 1)..];

            parameters.Add(
                new OAuthParameter(WebUtility.UrlDecode(key), WebUtility.UrlDecode(value))
            );
        }

        return parameters;
    }
}
