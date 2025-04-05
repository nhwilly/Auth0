using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components;
using System.Security.Claims;
using SharedAuth;

namespace Auth0.Client.Auth;


public class PersistentAuthenticationStateProvider(PersistentComponentState persistentState) : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> _unauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        if (!persistentState.TryTakeFromJson<CustomAuthenticationStateData>(nameof(CustomAuthenticationStateData), out var customAuthenticationStateData) || customAuthenticationStateData is null)
        {
            return _unauthenticatedTask;
        }

        var principal = new ClaimsPrincipal();
        var identities = customAuthenticationStateData.Identities.Select(i =>
            new ClaimsIdentity(i.Claims.Select(c => new Claim(c.Type, c.Value)), i.AuthenticationType));



        return Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(identities)));
    }
}
