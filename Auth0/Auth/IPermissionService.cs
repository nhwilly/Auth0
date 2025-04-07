using System.Security.Claims;
using SharedAuth;


namespace Auth0.Auth;

public interface IPermissionService
{/// <summary>
 /// Adds permission claims to the user principal
 /// </summary>
    Task<List<ClaimsIdentity>> AddAccountMemberIdentities(ClaimsPrincipal user);
}
