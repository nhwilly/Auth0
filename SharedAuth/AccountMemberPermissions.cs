using System.Security.Claims;

namespace SharedAuth;

[Serializable]
public class AccountMemberPermissions
{
    public string Name { get; set; } = string.Empty;
    public Guid Id { get; set; }
    public List<Claim> Claims { get; set; } = [];
}


