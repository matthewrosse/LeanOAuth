using System.Net;
using Shouldly;

namespace LeanOAuth.Http.Tests.Unit;

public class OAuthExceptionHierarchyTests
{
    [Fact]
    public void OAuthProtocolException_DerivesFromOAuthException() =>
        new OAuthProtocolException("message").ShouldBeAssignableTo<OAuthException>();

    [Fact]
    public void OAuthRequestFailedException_DerivesFromOAuthException() =>
        new OAuthRequestFailedException(HttpStatusCode.BadRequest, null)
            .ShouldBeAssignableTo<OAuthException>();

    [Fact]
    public void CallersCanCatchBothSubtypesByTheCommonBaseType()
    {
        Exception? caught = null;

        try
        {
            throw new OAuthRequestFailedException(HttpStatusCode.Unauthorized, "denied");
        }
        catch (OAuthException ex)
        {
            caught = ex;
        }

        caught.ShouldNotBeNull();
    }
}
