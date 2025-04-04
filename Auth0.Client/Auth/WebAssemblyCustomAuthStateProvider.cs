using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using SharedAuth;
using System.Net.Http.Json;
using System.Security.Claims;

namespace Auth0.Client.Auth
{
    // Location: YourSolution.Client/Authentication/WebAssemblyCustomAuthStateProvider.cs
    public class WebAssemblyCustomAuthStateProvider : AuthenticationStateProvider
    {
        private readonly IJSRuntime _jsRuntime;
        private readonly HttpClient _httpClient;
        private AuthenticationState _currentState;

        public WebAssemblyCustomAuthStateProvider(
            IJSRuntime jsRuntime,
            HttpClient httpClient,
            AuthenticationState initialState) // This will get the standard remoted state
        {
            _jsRuntime = jsRuntime;
            _httpClient = httpClient;
            _currentState = initialState;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (_currentState == null || !_currentState.User.Identity.IsAuthenticated)
            {
                // Use the standard remoting mechanism if not authenticated
                return new CustomAuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            try
            {
                // Fetch the permissions data separately
                var permissions = await _httpClient.GetFromJsonAsync<List<AccountMemberPermissions>>("api/permissions");

                // Create a new CustomAuthenticationState with the original User but with our custom permissions
                return new CustomAuthenticationState(_currentState.User)
                {
                    AccountPermissions = permissions ?? new List<AccountMemberPermissions>()
                };
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error loading permissions: {ex.Message}");
                // Return at least the base authentication state on error
                return new CustomAuthenticationState(_currentState.User);
            }
        }
    }
}
