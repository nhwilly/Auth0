using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Web;
using SharedAuth;

namespace Auth0.Auth;
public class PersistingRevalidatingAuthenticationStateProvider : RevalidatingServerAuthenticationStateProvider
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly PersistentComponentState _state;
    private readonly IdentityOptions _options;
    private readonly IAccountMemberService _accountMemberService;
    private readonly PersistingComponentStateSubscription _subscription;
    private readonly ILogger<PersistingRevalidatingAuthenticationStateProvider> _logger;
    private Task<AuthenticationState>? _authenticationStateTask;

    public PersistingRevalidatingAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory,
        PersistentComponentState state,
        IOptions<IdentityOptions> options,
        IAccountMemberService accountMemberService,
        ILogger<PersistingRevalidatingAuthenticationStateProvider> logger)
        : base(loggerFactory)
    {
        _scopeFactory = scopeFactory;
        _state = state;
        _options = options.Value;

        AuthenticationStateChanged += OnAuthenticationStateChanged;
        _subscription = state.RegisterOnPersisting(OnPersistingAsync, RenderMode.InteractiveWebAssembly);
        _accountMemberService = accountMemberService;
        _logger = logger;
    }

    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(30);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken ct)
    {
        // Get the user manager from a new scope to ensure it fetches fresh data
        await using var scope = _scopeFactory.CreateAsyncScope();
        return ValidateSecurityStampAsync(authenticationState.User);
    }

    private bool ValidateSecurityStampAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated is false)
        {
            return false;
        }
        return true;
    }

    private void OnAuthenticationStateChanged(Task<AuthenticationState> authenticationStateTask)
    {
        _authenticationStateTask = authenticationStateTask;
    }

    private ClaimsIdentity? GetAuth0Identity(ClaimsPrincipal user)
    {
        var auth0Identity = user.Identities.FirstOrDefault(identity =>
            identity.AuthenticationType == "AuthenticationTypes.Federation" &&
            identity.IsAuthenticated);

        return auth0Identity;
    }

    private IdentityData CreateAuth0IdentityData(ClaimsIdentity auth0Identity)
    {
        var auth0Data = new IdentityData
        {
            AuthenticationType = auth0Identity?.AuthenticationType ?? string.Empty,
            IsAuthenticated = auth0Identity?.IsAuthenticated ?? false,
            Name = auth0Identity?.Name ?? string.Empty,
            Claims = [.. (auth0Identity?.Claims ?? []).Select(c => new ClaimDto { Type = c.Type, Value = c.Value })]
        };

        return auth0Data;
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return base.GetAuthenticationStateAsync();
    }

    private async Task OnPersistingAsync()
    {
        if (_authenticationStateTask is null)
        {
            throw new UnreachableException($"Authentication state not set in {nameof(RevalidatingServerAuthenticationStateProvider)}.{nameof(OnPersistingAsync)}().");
        }

        var authenticationState = await _authenticationStateTask;
        var principal = authenticationState.User;


        var auth0Identity = GetAuth0Identity(principal);

        if (auth0Identity is null) { return; }

        (var userId, var identityProvider) = GetUserIdAndIdentityProvider(auth0Identity);

        var auth0Data = CreateAuth0IdentityData(auth0Identity);
        var authStateData = new CustomAuthenticationStateData
        {
            Identities = [auth0Data],
        };

        if (userId != null)
        {
            List<AccountMemberPermissions> memberPermissions = await _accountMemberService.GetAccountMemberPermissionsAsync(userId);
            var memberIdentityData = memberPermissions.Select(m =>
                new IdentityData
                {
                    AuthenticationType = "Sezami",
                    IsAuthenticated = true,
                    Name = m.AccountName,
                    Claims = [.. (m.Claims ?? []).Select(c => new ClaimDto { Type = c.Type, Value = c.Value })]
                }
            );

            authStateData.Identities.AddRange(memberIdentityData);
            _state.PersistAsJson(nameof(CustomAuthenticationStateData), authStateData);
        }
    }

    private (string userId, string identityProvider) GetUserIdAndIdentityProvider(ClaimsIdentity identity)
    {
        var claimValue = identity.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? string.Empty;
        var parts = claimValue.Split('|');
        var identityProvider = parts[0];
        var userId = parts[1];
        return (userId, identityProvider);
    }
    protected override void Dispose(bool disposing)
    {
        _subscription.Dispose();
        AuthenticationStateChanged -= OnAuthenticationStateChanged;
        base.Dispose(disposing);
    }
}