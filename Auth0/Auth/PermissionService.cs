using System.Security.AccessControl;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using SharedAuth;


namespace Auth0.Auth;

public class PermissionService : IPermissionService
{
    //private readonly IMemoryCache _cache;
    private readonly ILogger<PermissionService> _logger;
    private readonly IAccountMemberService _accountMemberService;
    public PermissionService(
        //IMemoryCache cache,
        ILogger<PermissionService> logger,
        IAccountMemberService accountMemberService)
    {
        //_cache = cache;
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

    //public List<AccountMemberPermissions> GetMemberPermissions(ClaimsPrincipal user)
    //{
    //    var accountPermissionsList = new List<AccountMemberPermissions>();
    //    try
    //    {
    //        // Get the user ID from Auth0 claims
    //        var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    //        if (string.IsNullOrEmpty(userId))
    //        {
    //            _logger.LogWarning("Unable to add permissions: User ID not found in claims");
    //            return accountPermissionsList;
    //        }

    //        // Get the first identity
    //        var identity = user.Identities.FirstOrDefault(i => i.AuthenticationType == "AuthenticationTypes.Federation" && i.IsAuthenticated);
    //        if (identity == null)
    //        {
    //            return accountPermissionsList;
    //        }

    //        // Create a cache key using the user ID
    //        string cacheKey = $"user_permissions_{userId}";

    //        // Try to get permissions from cache
    //        if (!_cache.TryGetValue(cacheKey, out List<string> permissions))
    //        {
    //            _logger.LogInformation("Cache miss for user {UserId}, loading permissions from database", userId);

    //            permissions = [];

    //            permissions.Add("some account claim");
    //            var cacheOptions = new MemoryCacheEntryOptions()
    //                .SetSlidingExpiration(TimeSpan.FromSeconds(5));

    //            _cache.Set(cacheKey, permissions.Distinct().ToList(), cacheOptions);

    //            _logger.LogInformation("Cached permissions for user {UserId}", userId);
    //        }
    //        else
    //        {
    //            _logger.LogInformation("Using cache permissions for user {UserId}", userId);
    //        }

    //        accountPermissionsList.Add(AddAccountPermissions("MotivAthletics", "Open.doors"));
    //        accountPermissionsList.Add(AddAccountPermissions("Ginger Gaucho", "Guest.passes"));
    //        return accountPermissionsList;
    //    }
    //    catch (Exception ex)
    //    {
    //        _logger.LogError(ex, "Error adding permission claims");
    //    }
    //    return accountPermissionsList;
    //}

    //public AccountMemberPermissions AddAccountPermissions(string accountName, string permissionValue)
    //{
    //    var accountPermissions = new AccountMemberPermissions()
    //    {
    //        AccountId = Guid.NewGuid(),
    //        Name = accountName,
    //        Claims = new List<Claim> { new Claim("permission", permissionValue) }
    //    };
    //    return accountPermissions;
    //}
    //private ClaimsIdentity CreateIdentity(string accountName, string permissionValue)
    //{
    //    var name = $"{Guid.NewGuid().ToString()}|{accountName}";
    //    var claimsList = new List<Claim>();
    //    // Add permission claims to the identity
    //    claimsList.Add(new Claim("permission", permissionValue));
    //    var accountPermissionsIdentity = new ClaimsIdentity(claimsList, "AuthenticationTypes.SezamiAuthorization") { Label = name };
    //    return accountPermissionsIdentity;
    //}

}
