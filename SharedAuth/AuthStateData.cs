namespace SharedAuth;

public class AuthStateData
{
    public string UserName { get; set; } = string.Empty;
    public List<AccountMemberPermissions> AccountPermissions { get; set; } = new();
}