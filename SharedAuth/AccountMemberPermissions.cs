using System.Security.Claims;

namespace SharedAuth;

[Serializable]
public class AccountMemberPermissions
{
    public string AccountName { get; set; } = string.Empty;
    public Guid AccountId { get; set; }
    public List<Claim> Permissions { get; set; } = [];
}


