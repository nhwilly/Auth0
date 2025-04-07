using SharedAuth;
using System.Security.Claims;

namespace Auth0.Auth
{

    public class AccountMemberService : IAccountMemberService
    {
        public async Task<List<AccountMemberPermissions>> GetAccountMemberPermissionsAsync(string userId)
        {
            // Simulate an asynchronous operation
            // Create a list of AccountMemberPermissions
            var accountMemberPermissions = new List<AccountMemberPermissions>
        {
            new AccountMemberPermissions
            {
                AccountName = "MotivAthletics",
                AccountId = Guid.Parse("88eb6159-75fb-41ae-a22f-b8eacb04e715" ),
                Claims = [new Claim("permission","open.doors")]
            },
            new AccountMemberPermissions
            {
                AccountName = "Ginger Gaucho",
                AccountId = Guid.Parse("7c5902d9-ffb3-4981-a3fc-4de2578c01b4"),
                Claims= [new Claim("permission","invite.members")]
            }
        };
            return await Task.FromResult(accountMemberPermissions);
        }
    }
}
