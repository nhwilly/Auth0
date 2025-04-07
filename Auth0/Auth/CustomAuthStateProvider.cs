using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;

namespace Auth0.Auth;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IPermissionService _permissionService;
    private readonly ILogger<CustomAuthStateProvider> _logger;

    public CustomAuthStateProvider(IHttpContextAccessor httpContextAccessor, IPermissionService permissionService, ILogger<CustomAuthStateProvider> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _permissionService = permissionService;
        _logger = logger;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        _logger.LogInformation("Server - CustomAuthStateProvider: Getting authentication state");

        // Get the current user from the HttpContext
        var user = _httpContextAccessor.HttpContext?.User;

        if (user?.Identity?.IsAuthenticated != true)
        {
            // Return unauthenticated state if user is not authenticated
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        // Clone the authenticated user to avoid modifying the original
        var clonedUser = ClearAllIdentitiesExceptAuth0(user);

        // Enhance the cloned user with permission claims
        var memberIdentities = await _permissionService.AddAccountMemberIdentities(clonedUser);

        clonedUser.AddIdentities(memberIdentities);
        // Return the enhanced authentication state
        return new AuthenticationState(clonedUser);
    }
    private ClaimsPrincipal ClearAllIdentitiesExceptAuth0(ClaimsPrincipal user)
    {
        // Create new ClaimsIdentity instances for each identity in the principal
        var auth0Identity = user.Identities.FirstOrDefault(identity => identity.AuthenticationType == "AuthenticationTypes.Federation" && identity.IsAuthenticated);

        if (auth0Identity == null)
        {
            _logger.LogWarning("No Auth0 identity found in the ClaimsPrincipal.");
            return user;
        }

        var clonedIdentity = new ClaimsIdentity(
            auth0Identity.Claims,
            auth0Identity.AuthenticationType,
            auth0Identity.NameClaimType,
            auth0Identity.RoleClaimType);

        // Create a new ClaimsPrincipal with the cloned identities
        return new ClaimsPrincipal(clonedIdentity);
    }

}