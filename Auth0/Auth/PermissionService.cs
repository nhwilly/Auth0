using System.Security.AccessControl;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using SharedAuth;


namespace Auth0.Auth;

public class PermissionService : IPermissionService
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<PermissionService> _logger;

    public PermissionService(
        IMemoryCache cache,
        ILogger<PermissionService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public async Task AddPermissionClaimsAsync(ClaimsPrincipal user)
    {
        try
        {
            // Get the user ID from Auth0 claims
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Unable to add permissions: User ID not found in claims");
                return;
            }

            // Get the first identity
            var identity = user.Identities.FirstOrDefault(i => i.AuthenticationType == "AuthenticationTypes.Federation" && i.IsAuthenticated);
            if (identity == null)
            {
                return;
            }

            // Create a cache key using the user ID
            string cacheKey = $"user_permissions_{userId}";

            // Try to get permissions from cache
            if (!_cache.TryGetValue(cacheKey, out List<string> permissions))
            {
                _logger.LogInformation("Cache miss for user {UserId}, loading permissions from database", userId);

                permissions = [];

                permissions.Add("some account claim");
                var cacheOptions = new MemoryCacheEntryOptions()
                    .SetSlidingExpiration(TimeSpan.FromSeconds(5));

                _cache.Set(cacheKey, permissions.Distinct().ToList(), cacheOptions);

                _logger.LogInformation("Cached permissions for user {UserId}", userId);
            }
            else
            {
                _logger.LogInformation("Using cache permissions for user {UserId}", userId);
            }

            user.AddIdentity(CreateIdentity("MotivAthletics", "Open.doors"));
            user.AddIdentity(CreateIdentity("Ginger Gaucho", "Guest.passes"));

            //var name = $"{Guid.NewGuid().ToString()}|Motiv Athletics";
            //var claimsList = new List<Claim>();
            //// Add permission claims to the identity
            //foreach (var permission in permissions)
            //{
            //    claimsList.Add(new Claim("permission", permission));
            //}
            //var accountPermissionsIdentity = new ClaimsIdentity(claimsList, "AuthenticationTypes.SezamiAuthorization") { Label=name };
            //user.AddIdentity(accountPermissionsIdentity);
            await Task.CompletedTask;

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding permission claims");
        }
    }

    public List<AccountMemberPermissions> GetMemberPermissions(ClaimsPrincipal user)
    {
        var accountPermissionsList = new List<AccountMemberPermissions>();
        try
        {
            // Get the user ID from Auth0 claims
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("Unable to add permissions: User ID not found in claims");
                return accountPermissionsList;
            }

            // Get the first identity
            var identity = user.Identities.FirstOrDefault(i => i.AuthenticationType == "AuthenticationTypes.Federation" && i.IsAuthenticated);
            if (identity == null)
            {
                return accountPermissionsList;
            }

            // Create a cache key using the user ID
            string cacheKey = $"user_permissions_{userId}";

            // Try to get permissions from cache
            if (!_cache.TryGetValue(cacheKey, out List<string> permissions))
            {
                _logger.LogInformation("Cache miss for user {UserId}, loading permissions from database", userId);

                permissions = [];

                permissions.Add("some account claim");
                var cacheOptions = new MemoryCacheEntryOptions()
                    .SetSlidingExpiration(TimeSpan.FromSeconds(5));

                _cache.Set(cacheKey, permissions.Distinct().ToList(), cacheOptions);

                _logger.LogInformation("Cached permissions for user {UserId}", userId);
            }
            else
            {
                _logger.LogInformation("Using cache permissions for user {UserId}", userId);
            }

            accountPermissionsList.Add(AddAccountPermissions("MotivAthletics", "Open.doors"));
            accountPermissionsList.Add(AddAccountPermissions("Ginger Gaucho", "Guest.passes"));
            return accountPermissionsList;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding permission claims");
        }
            return accountPermissionsList;
    }

    public AccountMemberPermissions AddAccountPermissions(string accountName, string permissionValue)
    {
        var accountPermissions = new AccountMemberPermissions()
        {
            Id = Guid.NewGuid(),
            Name = accountName,
            Permissions = new List<Claim> { new Claim("permission", permissionValue) }
        };
        return accountPermissions;
    }
    private ClaimsIdentity CreateIdentity(string accountName, string permissionValue)
    {
        var name = $"{Guid.NewGuid().ToString()}|{accountName}";
        var claimsList = new List<Claim>();
        // Add permission claims to the identity
        claimsList.Add(new Claim("permission", permissionValue));
        var accountPermissionsIdentity = new ClaimsIdentity(claimsList, "AuthenticationTypes.SezamiAuthorization") { Label = name };
        return accountPermissionsIdentity;
    }

}
