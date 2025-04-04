using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;

namespace Auth0.Auth
{
    //public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    //{
    //    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    //    {
    //        throw new NotImplementedException();
    //    }
    //}
    public class CustomClaimsTransformation : IClaimsTransformation
    {
        private readonly IConfiguration _configuration;

        public CustomClaimsTransformation(IConfiguration configuration) => _configuration = configuration;

        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal.Identity is ClaimsIdentity identity)
            {
                //string? audience = _configuration["Auth0:Domain"];
                //var roleClaims = identity.FindAll($"{audience}/roles").ToList();

                //foreach (var roleClaim in roleClaims)
                //{
                //    identity.AddClaim(new Claim(ClaimTypes.Role, roleClaim.Value));
                //}
                Console.WriteLine($"CustomClaimsTransformation @ {DateTime.Now}");
            }

            return Task.FromResult(principal);
        }
    }
}
