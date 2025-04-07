using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

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

        var user = _httpContextAccessor.HttpContext?.User;

        if (user?.Identity?.IsAuthenticated != true)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var clonedUser = ClearAllIdentitiesExceptAuth0(user);

        var memberIdentities = await _permissionService.AddAccountMemberIdentities(clonedUser);

        clonedUser.AddIdentities(memberIdentities);
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