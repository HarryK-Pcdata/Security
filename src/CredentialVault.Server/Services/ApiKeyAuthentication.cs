using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CredentialVault.Server.Services;

/// <summary>
/// Simple API key authentication handler.
/// Validates the X-Api-Key header against a list of configured valid API keys.
/// Each key is associated with a role: either "Application" or "ServiceDepartment".
/// </summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "ApiKey";
    public const string HeaderName = "X-Api-Key";

    private readonly ApiKeyRegistry _registry;

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ApiKeyRegistry registry)
        : base(options, logger, encoder)
    {
        _registry = registry;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderName, out var apiKeyValues))
            return Task.FromResult(AuthenticateResult.Fail("Missing X-Api-Key header."));

        string? providedKey = apiKeyValues.FirstOrDefault();
        if (string.IsNullOrEmpty(providedKey))
            return Task.FromResult(AuthenticateResult.Fail("Empty X-Api-Key header."));

        var keyEntry = _registry.FindByKey(providedKey);
        if (keyEntry is null)
            return Task.FromResult(AuthenticateResult.Fail("Invalid API key."));

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, keyEntry.Name),
            new Claim(ClaimTypes.Role, keyEntry.Role)
        };
        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

/// <summary>
/// Registry of valid API keys loaded from configuration.
/// </summary>
public sealed class ApiKeyRegistry
{
    private readonly List<ApiKeyEntry> _keys;

    public ApiKeyRegistry(List<ApiKeyEntry> keys)
    {
        _keys = keys;
    }

    public ApiKeyEntry? FindByKey(string key)
    {
        return _keys.FirstOrDefault(k => string.Equals(k.Key, key, StringComparison.Ordinal));
    }
}

/// <summary>Represents a configured API key with its name and role.</summary>
public sealed class ApiKeyEntry
{
    public string Name { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;

    /// <summary>Either "Application" or "ServiceDepartment".</summary>
    public string Role { get; init; } = "Application";
}
