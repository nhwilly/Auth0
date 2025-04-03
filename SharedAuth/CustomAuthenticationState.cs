using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;

namespace SharedAuth;

// In a shared project or class library
public class CustomAuthenticationState : AuthenticationState
{
    private readonly IEnumerable<AccountPermissions> _accountPermissions = [];
    public List<AccountPermissions> AccountPermissions { get; set; } = [];
    public CustomAuthenticationState(ClaimsPrincipal user) : base(user) { }

}
public class AccountPermissions
{
    public string Name { get; set; } = string.Empty;
    public Guid Id { get; set; }
    public List<Claim> Claims { get; set; } = [];
}


