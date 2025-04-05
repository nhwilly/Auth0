using Microsoft.AspNetCore.Components.Authorization;
using SharedAuth;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;

namespace Auth0.Client.Auth;

public class MultiIdentityAuthStateProvider : AuthenticationStateProvider
{
    private readonly AuthenticationStateProvider _persistentAuthStateProvider;

    public MultiIdentityAuthStateProvider(AuthenticationStateProvider persistentAuthStateProvider)
    {
        _persistentAuthStateProvider = persistentAuthStateProvider;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        // Get the base authentication state
        var baseAuthState = await _persistentAuthStateProvider.GetAuthenticationStateAsync();

        //// If we have our custom state data, use it to recreate the principal with all identities
        //if (baseAuthState is CustomAuthenticationStateData customState &&
        //    customState.Identities?.Count > 0)
        //{
        //    var identities = customState.Identities.Select(id =>
        //        new ClaimsIdentity(
        //            id.Claims.Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer)),
        //            id.AuthenticationType,
        //            ClaimTypes.Name,
        //            ClaimTypes.Role
        //        )
        //    );

        //    return new AuthenticationState(new ClaimsPrincipal(identities));
        //}

        // Fall back to the base state
        return baseAuthState;
    }
}
