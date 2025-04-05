using Microsoft.AspNetCore.Components.Authorization;
namespace SharedAuth;

public class CustomAuthenticationStateData //: AuthenticationStateData
{
    public List<IdentityData> Identities { get; set; } = [];
}

public class IdentityData
{
    public required string AuthenticationType { get; set; }
    public bool IsAuthenticated { get; set; }
    public required string Name { get; set; }
    public List<ClaimDto> Claims { get; set; } = [];
}

public class ClaimDto
{
    public required string Type { get; set; }
    public required string Value { get; set; }
}