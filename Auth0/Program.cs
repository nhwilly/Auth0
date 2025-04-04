using System.Security.Claims;
using System.Text.Json;
using Auth0.AspNetCore.Authentication;
using Auth0.Auth;
using Auth0.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;

namespace Auth0;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents()
            .AddInteractiveWebAssemblyComponents()
             .AddAuthenticationStateSerialization(
            options =>
            {
                options.SerializeAllClaims = true;
                options.SerializationCallback = async (authState) =>
                {
                    // Get the existing ClaimsPrincipal
                    var user = authState.User;
                    var isAuthenticated = user.Identity?.IsAuthenticated ?? false;
                    if (authState is CustomAuthenticationState customState && isAuthenticated)
                    {
                        //    // Add custom properties to the serialization
                        //    var customData = new Dictionary<string, object>
                        //    {
                        //        { "AccountPermissions", customState.AccountPermissions }
                        //    };
                        //}
                        //if (user.Identity?.IsAuthenticated == true)
                        //{
                        Console.WriteLine("Getting extra claim data...");
                        var claimsData = user.Claims.Select(c => new ClaimData(c.Type, c.Value)).ToList();
                        //claimsData.Add(new ClaimData("blah", "blahValue"));
                        // Create a new AuthenticationStateData object
                        var customStateData = new CustomAuthenticationStateData
                        {
                            Claims = claimsData,
                            AccountPermissions = customState.AccountPermissions
                        };

                        return await Task.FromResult(customStateData);
                    }

                    // Return null for unauthenticated users
                    return null;
                };
            });

        builder.Services.AddAuth0WebAppAuthentication(options =>
        {
            options.Domain = builder.Configuration["Auth0:Domain"] ?? throw new Exception("Missing Auth0:Domain from appsettings.json");
            options.ClientId = builder.Configuration["Auth0:ClientId"] ?? throw new Exception("Missing Auth0:ClientId from appsettings.json");
            options.Scope = "openid profile email";

        });
        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthStateProvider>();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddScoped<IPermissionService, PermissionService>();
        builder.Services.AddMemoryCache();

        var app = builder.Build();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseWebAssemblyDebugging();
        }
        else
        {
            app.UseExceptionHandler("/Error");
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseAntiforgery();
        app.MapGet("/Account/Login", async (HttpContext httpContext, string returnUrl = "/") =>
        {
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                    .WithRedirectUri(returnUrl)
                    .Build();
            authenticationProperties.IsPersistent = true;

            await httpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        });

        app.MapGet("/Account/Logout", async (HttpContext httpContext) =>
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                    .WithRedirectUri("/")
                    .Build();

            await httpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        });

        app.MapStaticAssets();
        app.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode()
            .AddInteractiveWebAssemblyRenderMode()
            .AddAdditionalAssemblies(typeof(Client._Imports).Assembly);

        app.Run();
    }
}
