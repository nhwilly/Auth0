using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;
namespace Auth0.Auth;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly ILogger<CustomAuthStateProvider> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IPermissionService _permissionService;
    //private readonly AuthenticationStateProvider _baseAuthenticationStateProvider;

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

        if (user.Identity?.IsAuthenticated == true)
        {
            try
            {
                customState.AccountPermissions = _permissionService.GetMemberPermissions(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading account member permissions");
            }
        }

        return await Task.FromResult(customState);
    }
}

