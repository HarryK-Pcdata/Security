using CredentialManager.Encryption;
using CredentialManager.Server.Models;
using CredentialManager.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace CredentialManager.Server.Endpoints;

/// <summary>
/// Minimal-API endpoint registration for the Credential Vault REST API.
/// </summary>
internal static class SecretEndpoints
{
    internal static void MapSecretEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/secrets")
            .RequireAuthorization("ApiKeyPolicy");

        // List all secret names
        group.MapGet("/", async (ISecretStore store, CancellationToken ct) =>
        {
            var names = await store.ListNamesAsync(ct);
            return Results.Ok(names);
        });

        // Get a specific secret (decrypted)
        group.MapGet("/{name}", async (
            string name,
            ISecretStore store,
            IEncryptor encryptor,
            CancellationToken ct) =>
        {
            var entry = await store.GetAsync(name, ct);
            if (entry is null)
                return Results.NotFound();

            string plaintext = encryptor.Decrypt(entry.EncryptedValue);
            return Results.Ok(new { entry.Name, Value = plaintext, entry.Description, entry.UpdatedAt });
        });

        // Create or update a secret (accepts plaintext; server encrypts it)
        group.MapPut("/{name}", async (
            string name,
            [FromBody] UpsertSecretRequest request,
            ISecretStore store,
            IEncryptor encryptor,
            CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(request.Value))
                return Results.BadRequest("Secret value must not be empty.");

            string encrypted = encryptor.Encrypt(request.Value);
            var entry = new SecretEntry
            {
                Name = name,
                EncryptedValue = encrypted,
                Description = request.Description,
                UpdatedAt = DateTimeOffset.UtcNow
            };

            await store.UpsertAsync(entry, ct);
            return Results.Ok(new { entry.Name, entry.Description, entry.UpdatedAt });
        }).RequireAuthorization("AdminPolicy");

        // Delete a secret
        group.MapDelete("/{name}", async (
            string name,
            ISecretStore store,
            CancellationToken ct) =>
        {
            bool deleted = await store.DeleteAsync(name, ct);
            return deleted ? Results.NoContent() : Results.NotFound();
        }).RequireAuthorization("AdminPolicy");
    }

    // Endpoint to return the master key (read role only; used by VaultKeyProvider)
    internal static void MapKeyEndpoint(this WebApplication app)
    {
        app.MapGet("/api/key", (IEncryptor _, IConfiguration config) =>
        {
            // Return the Base64 master key so that remote applications can
            // decrypt their own config files using VaultKeyProvider.
            string? masterKeyB64 = config["Vault:MasterKeyBase64"];
            if (string.IsNullOrWhiteSpace(masterKeyB64))
                return Results.Problem("Master key is not configured on the server.");

            return Results.Ok(new { Key = masterKeyB64 });
        }).RequireAuthorization("ApiKeyPolicy");
    }

    internal sealed class UpsertSecretRequest
    {
        public required string Value { get; init; }
        public string? Description { get; init; }
    }
}
