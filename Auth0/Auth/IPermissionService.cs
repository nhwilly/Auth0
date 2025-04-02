using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;


namespace Auth0.Auth;

public interface IPermissionService
{/// <summary>
 /// Adds permission claims to the user principal
 /// </summary>
    Task AddPermissionClaimsAsync(ClaimsPrincipal user);
}

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
            var identity = user.Identities.FirstOrDefault(i => i.IsAuthenticated);
            if (identity == null)
            {
                return;
            }

            // Create a cache key using the user ID
            string cacheKey = $"user_permissions_{userId}";

            // Try to get permissions from cache
            if (!_cache.TryGetValue(cacheKey, out List<string> permissions ))
            {
                _logger.LogInformation("Cache miss for user {UserId}, loading permissions from database", userId);

                permissions = [];

                permissions.Add("a claim i made up");
                var cacheOptions = new MemoryCacheEntryOptions()
                    .SetSlidingExpiration(TimeSpan.FromSeconds(5));

                _cache.Set(cacheKey, permissions.Distinct().ToList(), cacheOptions);

                _logger.LogInformation("Cached permissions for user {UserId}", userId);
            }
            else
            {
                _logger.LogInformation("Using cache permissions for user {UserId}", userId);
            }

            // Add permission claims to the identity
            foreach (var permission in permissions)
            {
                identity.AddClaim(new Claim("permission", permission));
            }

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding permission claims");
        }
    }
}
