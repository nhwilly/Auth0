using Microsoft.AspNetCore.Components.Authorization;
namespace SharedAuth;

public class CustomAuthenticationStateData : AuthenticationStateData
{
    public List<IdentityData> Identities { get; set; } = new();
    public  const bool CustomStateData = true;

    // Other custom properties...

    // You might need to override methods from the base class
    // to ensure your identities list is used during deserialization
}

public class IdentityData
{
    public string AuthenticationType { get; set; }
    public bool IsAuthenticated { get; set; }
    public string Name { get; set; }
    public List<ClaimData> Claims { get; set; } = new();
}

public class ClaimData
{
    public string Type { get; set; }
    public string Value { get; set; }
    public string ValueType { get; set; }
    public string Issuer { get; set; }
}