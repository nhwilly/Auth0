using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using System.Security.Claims;

namespace Auth0.Auth;

/// <summary>
/// Auth state provider that enhances Auth0's authentication with custom permission claims
/// </summary>
public class Auth0EnhancedAuthStateProvider : RevalidatingServerAuthenticationStateProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IPermissionService _permissionService;
    private readonly ILogger<Auth0EnhancedAuthStateProvider> _logger;
    public Auth0EnhancedAuthStateProvider(
        ILoggerFactory loggerFactory,

        IHttpContextAccessor httpContextAccessor,
        IPermissionService permissionService,
        ILogger<Auth0EnhancedAuthStateProvider> logger)
        : base(loggerFactory)
    {
        _httpContextAccessor = httpContextAccessor;
        _permissionService = permissionService;
        _logger = logger;
    }

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState,
    CancellationToken cancellationToken)
    {
        _logger.LogInformation("Validating authentication state");
        // Extract the user from the current authentication state
        var user = authenticationState.User;

        // Check if the user is still authenticated
        if (user.Identity is not { IsAuthenticated: true })
        {
            return false; // User is not authenticated, no need to revalidate
        }

        // Example: Check if the user's claims are still valid (e.g., via a database or external service)
        var isStillValid = await CheckUserValidityAsync(user, cancellationToken);

        return isStillValid; // Return true if valid, false if not
    }
    private async Task<bool> CheckUserValidityAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Checking authentication state validity");
        // Implement your custom logic here to validate the user's state
        // For example: Query a database or call an external service

        // Simulated check (replace with real logic)
        await Task.Delay(1000, cancellationToken); // Simulate a delay
        return true; // Assume the user is still valid
    }
    /// <summary>
    /// Gets the authentication state with enhanced permissions
    /// </summary>
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        _logger.LogInformation("Getting authentication state");

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
        await _permissionService.AddPermissionClaimsAsync(clonedUser);

        // Return the enhanced authentication state
        return new AuthenticationState(clonedUser);
    }

    /// <summary>
    /// Determines if the authentication state should be revalidated
    /// </summary>
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    /// <summary>
    /// Validates the authentication state to ensure it's still valid
    /// </summary>
    //protected override Task<bool> ValidateAuthenticationStateAsync(
    //    AuthenticationState authenticationState, CancellationToken cancellationToken)
    //{
    //    // If the user is not authenticated, no validation is needed
    //    var user = authenticationState.User;
    //    if (!user.Identity?.IsAuthenticated ?? true)
    //    {
    //        return Task.FromResult(false);
    //    }

    //    // For basic implementation, just return true if authenticated
    //    return Task.FromResult(true);
    //}

    /// <summary>
    /// Creates a clone of the user to avoid modifying the original
    /// </summary>
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