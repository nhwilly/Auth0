using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Authentication;          // 👈 new code
using Microsoft.AspNetCore.Authentication.Cookies;  // 👈 new code
using Microsoft.AspNetCore.Components.Authorization;
using Auth0.Client.Services;
namespace Auth0.Client;

class Program
{
    static async Task Main(string[] args)
    {
        var builder = WebAssemblyHostBuilder.CreateDefault(args);
        builder.Services.AddAuthorizationCore();
        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddAuthenticationStateDeserialization();
        //builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthenticationStateProvider>();

        await builder.Build().RunAsync();
    }
}
