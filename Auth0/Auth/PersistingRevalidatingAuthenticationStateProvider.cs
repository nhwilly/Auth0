using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
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
        _logger.LogInformation("Validating authentication state...");

        await using var scope = _scopeFactory.CreateAsyncScope();
        return ValidateSecurityStampAsync(authenticationState.User);
    }

    private bool ValidateSecurityStampAsync(ClaimsPrincipal principal)
    {
        _logger.LogInformation("ValidateSecurityStampAsync...");
        if (principal.Identity?.IsAuthenticated is false)
        {
            return false;
        }
        return true;
    }

    private async Task<List<ClaimsIdentity>> GetAccountMemberIdentities(string userId)
    {
        _logger.LogInformation("GetAccountMemberIdentities...");
        List<ClaimsIdentity> memberIdentities = [];

        var memberPermissions = await _accountMemberService.GetAccountMemberPermissionsAsync(userId);
        memberIdentities = [.. memberPermissions.Select(m =>
           new ClaimsIdentity(m.Claims.Select(c => new Claim(c.Type, c.Value)), m.AccountName) { Label = m.AccountId.ToString() })];

        return memberIdentities;
    }
    private ClaimsIdentity? GetAuth0Identity(ClaimsPrincipal user)
    {
        var auth0Identity = user.Identities.FirstOrDefault(identity =>
            identity.AuthenticationType == "AuthenticationTypes.Federation" &&
            identity.IsAuthenticated);

        return auth0Identity;
    }
    private void OnAuthenticationStateChanged(Task<AuthenticationState> authenticationStateTask)
    {
        _logger.LogInformation("OnAuthenticationStateChanged...");
        var authenticationState = authenticationStateTask.GetAwaiter().GetResult();
        var principal = authenticationState.User;
        foreach (var identity in principal.Identities)
        {
            _logger.LogInformation($"\t\t\tIdentity: {identity.AuthenticationType}, IsAuthenticated: {identity.IsAuthenticated}, Name: {identity.Name}");

        }
        _authenticationStateTask = authenticationStateTask;
    }
    private async Task OnPersistingAsync()
    {
        _logger.LogInformation("OnPersistingAsync...");
        if (_authenticationStateTask is null)
        {

            throw new UnreachableException($"Authentication state not set in {nameof(RevalidatingServerAuthenticationStateProvider)}.{nameof(OnPersistingAsync)}().");
        }

        // hello...

        var authenticationState = await _authenticationStateTask;
        var principal = authenticationState.User;

        if (principal.Identity?.IsAuthenticated == true)
        {
            var auth0Identity = GetAuth0Identity(principal);
            if (auth0Identity is null || auth0Identity.IsAuthenticated == false) { return; }
            (var userId, var identityProvider) = GetUserIdAndIdentityProvider(auth0Identity);
            if (!string.IsNullOrWhiteSpace(userId))
            {
                try
                {
                    var memberIdentities = await GetAccountMemberIdentities(userId);
                    memberIdentities.Add(auth0Identity);

                    var enhancedPrincipal = new ClaimsPrincipal(memberIdentities);

                    var newAuthState = new AuthenticationState(enhancedPrincipal);
                    _authenticationStateTask = Task.FromResult(newAuthState);

                    NotifyAuthenticationStateChanged(_authenticationStateTask);

                    principal = enhancedPrincipal;
                }
                catch (Exception ex)
                {
                    // Log the exception but don't fail the persistence
                    // This ensures that even if getting additional identities fails, the basic auth still works
                    var logger = _scopeFactory.CreateScope().ServiceProvider.GetService<ILogger<PersistingRevalidatingAuthenticationStateProvider>>();
                    logger?.LogError(ex, "Error while retrieving additional identities for user {UserId}", userId);
                }

                var identities = principal.Identities.Select(mi => new IdentityData
                {
                    AuthenticationType = mi?.AuthenticationType ?? string.Empty,
                    IsAuthenticated = mi?.IsAuthenticated == false,
                    Name = mi?.Name ?? string.Empty,
                    Claims = [.. (mi?.Claims ?? []).Select(c => new ClaimDto { Type = c.Type, Value = c.Value })]
                }).ToList();

                var authStateData = new CustomAuthenticationStateData
                {
                    Identities = identities,
                };

                _state.PersistAsJson(nameof(CustomAuthenticationStateData), authStateData);
            }

        }
    }
    // get member permissions method
    // create identities method
    // map identity to identitydata method

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