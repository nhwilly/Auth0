using System.Security.Claims;
using System.Text.Json;
using Auth0.Client.Auth;
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
        builder.Services.AddSingleton<JsonSerializerOptions>(new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new CustomAuthStateJsonConverter(), new CustomAuthStateJsonConverter2() }
        });
        //builder.Services.AddSingleton<AuthenticationStateProvider, WebAssemblyAuthenticationStateProvider>();
        builder.Services.AddAuthenticationStateDeserialization(options =>
        {
            options.DeserializationCallback = async (authStateData) =>
            {
                // Check if the authentication state is of the expected type
                if (authStateData is CustomAuthenticationStateData customState)
                {
                    // Recreate the ClaimsPrincipal with all identities
                    var identities = customState.Identities.Select(id =>
                        new ClaimsIdentity(
                            id.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer)),
                            id.AuthenticationType,
                            ClaimTypes.Name,
                            ClaimTypes.Role
                        )
                    );
                    return await Task.FromResult(new AuthenticationState(new ClaimsPrincipal(identities)));
                }
                return await Task.FromResult(
                    new AuthenticationState(
                        new ClaimsPrincipal(
                            new ClaimsIdentity()
                            )
                        )
                    );
            };
        });
        builder.Services.AddScoped(sp => new HttpClient
        {
            BaseAddress = new Uri(builder.HostEnvironment.BaseAddress),
            
        });
        await builder.Build().RunAsync();
    }
}
