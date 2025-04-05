using System.Security.Claims;
using System.Text.Json;
using Auth0.AspNetCore.Authentication;
using Auth0.Auth;
using Auth0.Components;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;
using ClaimData = SharedAuth.ClaimData;
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
                options.SerializationCallback = async (authStateData) =>
                {
                    var user = authStateData.User;

                    if (user.Identity?.IsAuthenticated == true)
                    {
                        // Create a custom authentication state data
                        var customStateData = new CustomAuthenticationStateData();

                        // Explicitly serialize all identities
                        var identities = user.Identities.Select(identity => new IdentityData
                        {
                            AuthenticationType = identity?.AuthenticationType ?? string.Empty,
                            IsAuthenticated = identity?.IsAuthenticated ?? false,
                            Name = identity?.Name ?? string.Empty,
                            Claims = [.. (identity?.Claims??[]).Select(c => new ClaimData
                            {
                                Type = c.Type,
                                Value = c.Value,
                                ValueType = c.ValueType,
                                Issuer = c.Issuer
                            })]
                        }).ToList();

                        customStateData.Identities = identities;

                        return await Task.FromResult(customStateData);
                    }

                    return null;
                };
            });
        builder.Services.AddSingleton(new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new CustomAuthStateJsonConverter(), new CustomAuthStateJsonConverter2() }
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
        builder.Services.AddScoped<IAccountMemberService, AccountMemberService>();
        builder.Services.ConfigureHttpJsonOptions(options =>
        {
            options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            options.SerializerOptions.Converters.Add(new CustomAuthStateJsonConverter());
            options.SerializerOptions.Converters.Add(new CustomAuthStateJsonConverter2());
        });

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
