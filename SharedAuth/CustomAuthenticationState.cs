using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Components.Authorization;

namespace SharedAuth;

// In a shared project or class library
//[Serializable]
public class CustomAuthenticationState : AuthenticationState
{

}

//public class CustomAuthenticationStateData: AuthenticationStateData
//{
//    public List<AccountMemberPermissions> AccountPermissions { get; set; } = [];    
//}