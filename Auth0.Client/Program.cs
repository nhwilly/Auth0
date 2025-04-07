using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SharedAuth;

namespace Auth0.Client;

class Program
{
    static async Task Main(string[] args)
    {
        var builder = WebAssemblyHostBuilder.CreateDefault(args);
        builder.Services.AddAuthorizationCore();
        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddAuthenticationStateDeserialization(options =>
        {
            options.DeserializationCallback = async (authStateData) =>
            {
                List<ClaimsIdentity> authStateIdentities = [];
                if (authStateData is not null)
                {
                    foreach (var claimData in authStateData?.Claims ?? [])
                    {
                        var identityData = JsonSerializer.Deserialize<IdentityData>(claimData.Value);
                        if (identityData is null) { continue; }
                        ClaimsIdentity identity = new(
                          identityData.Claims.Select(c => new Claim(c.Type, c.Value)),
                          identityData.AuthenticationType,
                          ClaimTypes.Name,
                          ClaimTypes.Role
                        );
                        authStateIdentities.Add(identity);
                    }

                    var authenticatedIdentities = authStateIdentities.Where(i => i.IsAuthenticated).ToList();
                    return new AuthenticationState(new ClaimsPrincipal(authenticatedIdentities));
                }
                return new AuthenticationState(new ClaimsPrincipal(authStateIdentities));
            };
        }
        );

        builder.Services.AddScoped(sp => new HttpClient
        {
            BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
        });
        await builder.Build().RunAsync();
    }
}