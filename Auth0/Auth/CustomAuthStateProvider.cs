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
        _logger.LogInformation("CustomAuthStateProvider: Getting authentication state");

        // Get the current user from the HttpContext
        var user = _httpContextAccessor.HttpContext?.User;

        if (user?.Identity?.IsAuthenticated != true)
        {
            // Return unauthenticated state if user is not authenticated
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        // Clone the authenticated user to avoid modifying the original
        var clonedUser = CloneUser(user);

        // Enhance the cloned user with permission claims
        var permissions = _permissionService.GetMemberPermissions(clonedUser);

        // Return the enhanced authentication state
        return new CustomAuthenticationState(clonedUser) { AccountPermissions = permissions };
    }
    private ClaimsPrincipal CloneUser(ClaimsPrincipal user)
    {
        // Create new ClaimsIdentity instances for each identity in the principal
        var clonedIdentities = user.Identities.Select(identity =>
            new ClaimsIdentity(
                identity.Claims,
                identity.AuthenticationType,
                identity.NameClaimType,
                identity.RoleClaimType));

        // Create a new ClaimsPrincipal with the cloned identities
        return new ClaimsPrincipal(clonedIdentities);
    }

}