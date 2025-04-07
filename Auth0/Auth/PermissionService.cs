using System.Security.AccessControl;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using SharedAuth;


namespace Auth0.Auth;

public class PermissionService : IPermissionService
{
    private readonly ILogger<PermissionService> _logger;
    private readonly IAccountMemberService _accountMemberService;
    public PermissionService(
        ILogger<PermissionService> logger,
        IAccountMemberService accountMemberService)
    {
        _logger = logger;
        _accountMemberService = accountMemberService;
    }

    public async Task<List<ClaimsIdentity>> AddAccountMemberIdentities(ClaimsPrincipal claimsPrincipal)
    {
        List<ClaimsIdentity> accountMemberIdentities = [];

        try
        {
            // try to find the Auth0 identity
            var identity = claimsPrincipal.Identities.FirstOrDefault(i =>
                i.AuthenticationType == "AuthenticationTypes.Federation" &&
                i.IsAuthenticated);

            if (identity == null)
            {
                _logger.LogWarning("Unable to add member identities - AuthenticationTypes.Federation not found in claimsPrincipal");
                return [];
            }

            // Get the user ID from Auth0 claims in the Auth0 identity
            var userId = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Unable to add member identities: User ID not found in Auth0 claims");
                return [];
            }

            var permissions = await _accountMemberService.GetAccountMemberPermissionsAsync(userId);

            foreach (var memberPermissions in permissions)
            {
                var identityName = $"{memberPermissions.AccountName}|{memberPermissions.AccountName}";
                var memberIdentity = new ClaimsIdentity(memberPermissions.Claims, $"SezamiAuthorization.{memberPermissions.AccountName}")
                {
                    Label = identityName
                };
                accountMemberIdentities.Add(memberIdentity);
            }
            return accountMemberIdentities;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding permission claims");
        }
        return [];
    }

}
