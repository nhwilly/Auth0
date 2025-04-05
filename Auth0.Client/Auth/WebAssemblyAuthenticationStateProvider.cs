using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;

namespace Auth0.Client.Auth;

public class WebAssemblyAuthenticationStateProvider : AuthenticationStateProvider
{
    private ILogger<WebAssemblyAuthenticationStateProvider> _logger;
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        _logger.LogInformation("WebassemblyAuthenticationStateProvider: Getting authentication state");

        // Get the current user from the HttpContext

        // Return unauthenticated state if user is not authenticated
        return await Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

        //// Clone the authenticated user to avoid modifying the original


        //// Enhance the cloned user with permission claims
        //var memberIdentities = await _permissionService.AddAccountMemberIdentities(clonedUser);

        //clonedUser.AddIdentities(memberIdentities);
        // Return the enhanced authentication state

    }
}
