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
        foreach (var claimData in authStateData?.Claims.ToList() ?? [])
        {
          var identityData = JsonSerializer.Deserialize<IdentityData>(claimData.Value);
          ClaimsIdentity identity = new ClaimsIdentity(
            (identityData?.Claims ?? []).Select(c => new Claim(c.Type, c.Value)),
            identityData?.AuthenticationType ?? string.Empty,
            ClaimTypes.Name,
            ClaimTypes.Role
          );
          authStateIdentities.Add(identity);
        }

        if (!authStateIdentities.Any(i => i.IsAuthenticated))
          return await Task.FromResult(
            new AuthenticationState(
              new ClaimsPrincipal(
                new ClaimsIdentity()
              )
            )
          );
        // Create a ClaimsPrincipal with the authenticated identities
        var authStateIdentitiesPrincipal = new ClaimsPrincipal(authStateIdentities);
        // Return the authentication state with the authenticated user
        return await Task.FromResult(new AuthenticationState(authStateIdentitiesPrincipal));
      };
    });

    builder.Services.AddScoped(sp => new HttpClient
    {
      BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
    });
    await builder.Build().RunAsync();
  }
}