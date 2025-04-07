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

  /// <summary>
  /// Retrieve the user ID and identity provider from the Auth0 identity claim.
  /// </summary>
  /// <param name="identity"></param>
  /// <returns></returns>
  private (string userId, string identityProvider) GetUserIdAndIdentityProviderFromAuth0Identity(
    ClaimsIdentity identity)
  {
    var claimValue = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
    if (string.IsNullOrWhiteSpace(claimValue))
    {
      _logger.LogError("Claim value is null or empty");
      throw new Exception("Claim value is null or empty");
    }

    var parts = claimValue.Split('|');
    if (parts.Length != 2)
    {
      _logger.LogError($"Unable to parse NameIdentifier claim from Auth0 {0}");
      throw new Exception($"Unable to parse NameIdentifier claim from Auth0 {0}");
    }

    return (parts[1], parts[0]);
  }

  /// <summary>
  /// Retrieve the Auth0 identity from the ClaimsPrincipal as well as the user ID and identity provider.
  /// This allows us to create a new ClaimsIdentity with the necessary claims for the user, as opposed
  /// to the account membership.
  /// </summary>
  /// <param name="user"></param>
  /// <returns></returns>
  private (string userId, string identityProvider, ClaimsIdentity?) GetAuth0Identity(ClaimsPrincipal user)
  {
    var auth0Identity = user.Identities.FirstOrDefault(identity =>
      identity is { AuthenticationType: "AuthenticationTypes.Federation", IsAuthenticated: true });
    if (auth0Identity is null)
    {
      _logger.LogWarning("No Auth0 identity found in the ClaimsPrincipal.");
      return ("", "", null);
    }

    var (userId, providerId) = GetUserIdAndIdentityProviderFromAuth0Identity(auth0Identity);
    var claims = auth0Identity.Claims.ToList();
    claims.Add(new Claim(type: "idp", providerId));
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
    _logger.LogInformation("Server - GetAuthenticationStateAsync");

    // Get the current user from the HttpContext
    var principal = _httpContextAccessor.HttpContext?.User;

    if (principal?.Identity?.IsAuthenticated != true)
    {
      _logger.LogInformation("User is not authenticated");
      return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    var (userId, providerId, auth0Identity) = GetAuth0Identity(principal);
    if (auth0Identity is null || auth0Identity.IsAuthenticated == false)
    {
      _logger.LogWarning("User is authenticated but Auth0 identity not found.");
      return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
    }

    if (string.IsNullOrWhiteSpace(userId))
    {
      _logger.LogWarning("User ID is null or empty");
      return new AuthenticationState(new ClaimsPrincipal(auth0Identity));
    }

    List<ClaimsIdentity> identities = [auth0Identity];
    try
    {
      var memberPermissions = await _accountMemberService.GetAccountMemberPermissionsAsync(userId);

      // turn the permissions into identities
      foreach (var p in memberPermissions)
      {
        var claims = p.Claims.Select(c => new Claim(c.Type, c.Value, "", "https://sezami.io")).ToList();
        claims.Add(new Claim(ClaimTypes.Name, p.AccountName, "", "https://sezami.io"));
        claims.Add(new Claim("account.name", p.AccountName, "", "https://sezami.io"));
        claims.Add(new Claim("account.id", p.AccountId.ToString(), "", "https://sezami.io"));
        var identity = new ClaimsIdentity(claims, "Sezami") ;
        identities.Add(identity);
      }

      var enhancedPrincipal = new ClaimsPrincipal(identities);

      return new AuthenticationState(enhancedPrincipal);
    }
    catch (Exception ex)
    {
      // This ensures that even if getting additional identities fails, the basic auth still works
      _logger.LogError(ex, "Error while retrieving additional identities for user {UserId}", userId);
    }

    return new AuthenticationState(new ClaimsPrincipal(identities));
  }
}