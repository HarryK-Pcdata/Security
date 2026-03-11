using System;
using System.Collections.Generic;
using System.Text;
using CredentialVault.Core.Encryption;
using CredentialVault.Server.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Vault key setup
// ---------------------------------------------------------------------------
// The vault key can be provided as a Base64 string via the VAULT_KEY environment
// variable (recommended for production/CI), or derived from a master password in
// configuration. Never commit the key or master password to source control.
//
// To generate a key: run `dotnet run --project src/CredentialVault.ConfigMigrator -- generate-key`
// ---------------------------------------------------------------------------

byte[] vaultKey;
string? vaultKeyBase64 = builder.Configuration["VaultKey"]
    ?? Environment.GetEnvironmentVariable("VAULT_KEY");

if (!string.IsNullOrEmpty(vaultKeyBase64))
{
    vaultKey = Convert.FromBase64String(vaultKeyBase64);
}
else
{
    // Derive key from master password + salt stored in configuration.
    // In production prefer the VAULT_KEY environment variable.
    string masterPassword = builder.Configuration["MasterPassword"]
        ?? throw new InvalidOperationException(
            "Either the VAULT_KEY environment variable or MasterPassword configuration must be set.");

    string saltBase64 = builder.Configuration["MasterPasswordSalt"]
        ?? throw new InvalidOperationException("MasterPasswordSalt configuration is required when using MasterPassword.");

    byte[] salt = Convert.FromBase64String(saltBase64);
    vaultKey = SecretKeyDerivation.DeriveKey(masterPassword, salt);
}

// ---------------------------------------------------------------------------
// API key registry - loaded from configuration
// ---------------------------------------------------------------------------
var apiKeys = builder.Configuration
    .GetSection("ApiKeys")
    .Get<List<ApiKeyEntry>>() ?? [];

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------
builder.Services.AddControllers();
builder.Services.AddSingleton(new VaultStore(vaultKey));
builder.Services.AddSingleton(new ApiKeyRegistry(apiKeys));

builder.Services.AddAuthentication(ApiKeyAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(
        ApiKeyAuthenticationHandler.SchemeName, _ => { });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiKeyPolicy", policy =>
        policy.RequireAuthenticatedUser());
});

// ---------------------------------------------------------------------------
// HTTP pipeline
// ---------------------------------------------------------------------------
var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

/// <summary>Marker for integration testing.</summary>
public partial class Program { }
