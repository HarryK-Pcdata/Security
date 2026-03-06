using System.Security.Claims;
using System.Text.Encodings.Web;
using CredentialManager.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace CredentialManager.Server.Auth;

/// <summary>
/// ASP.NET Core authentication handler that validates API keys supplied via
/// the <c>Authorization: ApiKey &lt;key&gt;</c> header.
/// </summary>
public sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiKeyAuthService authService)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "ApiKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? authHeader = Request.Headers.Authorization;

        if (string.IsNullOrWhiteSpace(authHeader) ||
            !authHeader.StartsWith(SchemeName + " ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        string rawKey = authHeader[(SchemeName.Length + 1)..].Trim();
        var record = authService.Validate(rawKey);

        if (record is null)
        {
            return Task.FromResult(
                AuthenticateResult.Fail("Invalid or inactive API key."));
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, record.Label),
            new("api_key_label", record.Label)
        };
        foreach (string role in record.Roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var identity = new ClaimsIdentity(claims, SchemeName);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
