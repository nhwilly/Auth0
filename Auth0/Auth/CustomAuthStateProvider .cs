using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;
namespace Auth0.Auth;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly ILogger<CustomAuthStateProvider> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IPermissionService _permissionService;
    private readonly AuthenticationStateProvider _baseAuthenticationStateProvider;

    public CustomAuthStateProvider(ILogger<CustomAuthStateProvider> logger, IHttpContextAccessor httpContextAccessor, IPermissionService permissionService)
    {
        _logger = logger;
        _httpContextAccessor = httpContextAccessor;
        _permissionService = permissionService;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {

        var user = _httpContextAccessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());

        var customState = new CustomAuthenticationState(user);

        // Populate your custom properties
        if (user.Identity?.IsAuthenticated == true)
        {
            try
            {
                // Load permissions using your existing permission service
                customState.AccountPermissions =  _permissionService.GetMemberPermissions(user);

                // Set any other properties
        //        customState.UserRole = user.FindFirstValue(ClaimTypes.Role) ?? "Guest";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading user permissions");
            }
        }

        return customState;
        //if (user?.Identity?.IsAuthenticated != true)
        //{
        //    // Return unauthenticated state if user is not authenticated
        //    _logger.LogInformation("User is not authenticated, returning unauthenticated state");
        //    return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        //}

        //// Clone the authenticated user to avoid modifying the original
        //var clonedUser = CloneUser(user);
        //_logger.LogInformation("Getting custom authentication state");

        //// Enhance the cloned user with permission claims
        //await _permissionService.AddPermissionClaimsAsync(clonedUser);

        //// Return the enhanced authentication state
        //return new AuthenticationState(clonedUser);
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

