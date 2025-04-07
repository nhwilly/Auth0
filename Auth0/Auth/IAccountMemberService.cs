using SharedAuth;


namespace Auth0.Auth;

public interface IAccountMemberService
{
    Task<List<AccountMemberPermissions>> GetAccountMemberPermissionsAsync(string userId);
}
