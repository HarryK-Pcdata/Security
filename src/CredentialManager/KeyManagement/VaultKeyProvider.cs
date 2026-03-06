using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using CredentialManager.Encryption;

namespace CredentialManager.KeyManagement;

/// <summary>
/// Retrieves the master key from the central Credential Vault server.
/// The vault server is the preferred key source for production deployments
/// because a single service account grants the service department access
/// across all customer installations without per-customer credentials.
/// </summary>
public sealed class VaultKeyProvider : IKeyProvider
{
    private readonly HttpClient _httpClient;
    private readonly string _vaultBaseUrl;
    private readonly string _apiKey;

    /// <param name="vaultBaseUrl">Base URL of the Credential Vault server (e.g. <c>https://vault.company.local</c>).</param>
    /// <param name="apiKey">API key issued by the vault for this installation.</param>
    /// <param name="httpClient">Optional pre-configured <see cref="HttpClient"/>; one is created if not supplied.</param>
    public VaultKeyProvider(string vaultBaseUrl, string apiKey, HttpClient? httpClient = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(vaultBaseUrl);
        ArgumentException.ThrowIfNullOrEmpty(apiKey);

        _vaultBaseUrl = vaultBaseUrl.TrimEnd('/');
        _apiKey = apiKey;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    }

    /// <inheritdoc />
    public async Task<byte[]> GetKeyAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{_vaultBaseUrl}/api/key");
        request.Headers.Authorization = new AuthenticationHeaderValue("ApiKey", _apiKey);

        HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<KeyResponse>(
            cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Vault returned an empty response.");

        if (string.IsNullOrWhiteSpace(result.Key))
            throw new InvalidOperationException("Vault returned an empty key value.");

        byte[] key;
        try
        {
            key = Convert.FromBase64String(result.Key.Trim());
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Vault returned a key that is not valid Base64.", ex);
        }

        if (key.Length != AesGcmEncryptor.KeySizeBytes)
            throw new InvalidOperationException(
                $"Vault key must decode to exactly {AesGcmEncryptor.KeySizeBytes} bytes.");

        return key;
    }

    private sealed class KeyResponse
    {
        public string? Key { get; init; }
    }
}
