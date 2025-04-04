using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Components.Authorization;

namespace SharedAuth;

// In a shared project or class library
[Serializable]
public class CustomAuthenticationState : AuthenticationState
{
    private readonly IEnumerable<AccountMemberPermissions> _accountPermissions = [];
    public List<AccountMemberPermissions> AccountPermissions { get; set; } = [];
    public CustomAuthenticationState(ClaimsPrincipal user) : base(user) { }

}
