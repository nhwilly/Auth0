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
    var jsonOptions = new JsonSerializerOptions
    {
      PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
      WriteIndented = true,
      // Add other settings as needed
    };
    builder.Services.AddSingleton(jsonOptions);

    builder.Services.AddAuthorizationCore();
    builder.Services.AddCascadingAuthenticationState();
    builder.Services.AddAuthenticationStateDeserialization(options =>
      {
        options.DeserializationCallback = async (authStateData) =>
        {
          List<ClaimsIdentity> authStateIdentities = [];
          if (authStateData is null)
            return await Task.FromResult(new AuthenticationState(new ClaimsPrincipal(authStateIdentities)));

          foreach (var claimData in authStateData?.Claims ?? [])
          {
            try
            {
              var identityData = JsonSerializer.Deserialize<IdentityData>(claimData.Value, jsonOptions);
              if (identityData is null)
              {
                continue;
              }

              var claims = new List<Claim>();
              foreach (var claimDto in identityData.Claims)
              {
                claims.Add(new Claim(claimDto.Type, claimDto.Value, "", claimDto.Issuer));
              }
              claims.Add(new Claim(ClaimTypes.Name, identityData?.Name ?? ""));
              ClaimsIdentity identity = new(
                claims,
                identityData?.AuthenticationType ?? string.Empty,
                ClaimTypes.Name,
                ClaimTypes.Role
              );
              authStateIdentities.Add(identity);
            }
            catch (JsonException jsonException)
            {
              Console.WriteLine(jsonException);
            }
          }

          var authenticatedIdentities = authStateIdentities.Where(i => i.IsAuthenticated).ToList();
          return await Task.FromResult(new AuthenticationState(new ClaimsPrincipal(authenticatedIdentities)));
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