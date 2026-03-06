using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using CredentialVault.Core.Models;

namespace CredentialVault.Client.Http;

/// <summary>
/// HTTP client for communicating with the Credential Vault REST API.
/// Use this in legacy C# applications to replace plain-text config reads with
/// vault-backed credential retrieval.
/// </summary>
public sealed class VaultHttpClient : IVaultClient
{
    private readonly HttpClient _httpClient;

    /// <param name="httpClient">
    /// An <see cref="HttpClient"/> with BaseAddress set to the vault server URL
    /// and the X-Api-Key default header set.
    /// </param>
    public VaultHttpClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    /// <inheritdoc/>
    public async Task<string?> GetCredentialAsync(
        string application,
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(application);
        ArgumentException.ThrowIfNullOrEmpty(key);

        var response = await _httpClient.GetAsync(
            $"api/credentials/{Uri.EscapeDataString(application)}/{Uri.EscapeDataString(key)}",
            cancellationToken);

        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return null;

        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<CredentialResponse>(cancellationToken);
        return result?.Value;
    }

    /// <inheritdoc/>
    public async Task StoreCredentialAsync(
        string application,
        string key,
        string value,
        string? description = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(application);
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(value);

        var request = new StoreCredentialRequest
        {
            Application = application,
            Key = key,
            PlainTextValue = value,
            Description = description
        };

        var response = await _httpClient.PutAsJsonAsync("api/credentials", request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
