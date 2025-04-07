using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace Auth0.Auth;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<CustomAuthStateProvider> _logger;
    private readonly IAccountMemberService _accountMemberService;

    public CustomAuthStateProvider(IHttpContextAccessor httpContextAccessor,
      ILogger<CustomAuthStateProvider> logger, IAccountMemberService accountMemberService)
    {
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
        _accountMemberService = accountMemberService;
    }
    private static (string userId, string identityProvider) GetUserIdAndIdentityProviderFromAuth0Identity(
  ClaimsIdentity identity)
    {
        var claimValue = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        var parts = claimValue.Split('|');
        var identityProvider = parts[0];
        var userId = parts[1];
        return (userId, identityProvider);
    }

    private static (string userId, string identityProvider, ClaimsIdentity?) GetAuth0Identity(ClaimsPrincipal user)
    {
        var auth0Identity = user.Identities.FirstOrDefault(identity =>
          identity is { AuthenticationType: "AuthenticationTypes.Federation", IsAuthenticated: true });
        if (auth0Identity is null) return ("", "", null);

        var (userId, providerId) = GetUserIdAndIdentityProviderFromAuth0Identity(auth0Identity);
        var claims = auth0Identity.Claims.ToList();
        claims.Add(new(type: "idp", providerId));
        claims.Add(new Claim(type: "sub", userId));
        var clonedIdentity = new ClaimsIdentity(
          claims,
          auth0Identity.AuthenticationType,
          auth0Identity.NameClaimType,
          auth0Identity.RoleClaimType);

        return (userId, providerId, clonedIdentity);
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        _logger.LogInformation("Server - CustomAuthStateProvider: Getting authentication state");

        // Get the current user from the HttpContext
        var principal = _httpContextAccessor.HttpContext?.User;

        if (principal?.Identity?.IsAuthenticated != true)
        {
            // Return unauthenticated state if user is not authenticated
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var (userId, providerId, auth0Identity) = GetAuth0Identity(principal);
        if (auth0Identity is null || auth0Identity.IsAuthenticated == false)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        if (string.IsNullOrWhiteSpace(userId))
        {
            _logger.LogWarning("User ID is null or empty");
            return new AuthenticationState(new ClaimsPrincipal(auth0Identity));
        }

        try
        {
            List<ClaimsIdentity> identities = [auth0Identity];

            var memberPermissions = await _accountMemberService.GetAccountMemberPermissionsAsync(userId);

            // turn the permissions into identities
            foreach (var amp in memberPermissions)
            {
                var claims = amp.Claims.Select(c => new Claim(c.Type, c.Value)).ToList();
                claims.Add(new Claim(ClaimTypes.Name, amp.AccountId.ToString()));
                var identity = new ClaimsIdentity(claims, "Sezami") { Label = amp.AccountName };
                identities.Add(identity);
            }

            var enhancedPrincipal = new ClaimsPrincipal(identities);

            return new AuthenticationState(enhancedPrincipal);
        }
        catch (Exception ex)
        {
            // Log the exception but don't fail the persistence
            // This ensures that even if getting additional identities fails, the basic auth still works
            _logger.LogError(ex, "Error while retrieving additional identities for user {UserId}", userId);
        }
        return new AuthenticationState(new ClaimsPrincipal(auth0Identity));

    }

    // private ClaimsPrincipal ClearAllIdentitiesExceptAuth0(ClaimsPrincipal user)
    // {
    //   // Create new ClaimsIdentity instances for each identity in the principal
    //   var auth0Identity = user.Identities.FirstOrDefault(identity =>
    //     identity.AuthenticationType == "AuthenticationTypes.Federation" && identity.IsAuthenticated);
    //
    //   if (auth0Identity == null)
    //   {
    //     _logger.LogWarning("No Auth0 identity found in the ClaimsPrincipal.");
    //     return user;
    //   }
    //
    //   var clonedIdentity = new ClaimsIdentity(
    //     auth0Identity.Claims,
    //     auth0Identity.AuthenticationType,
    //     auth0Identity.NameClaimType,
    //     auth0Identity.RoleClaimType);
    //
    //   // Create a new ClaimsPrincipal with the cloned identities
    //   return new ClaimsPrincipal(clonedIdentity);
    // }

}