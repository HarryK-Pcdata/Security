using System;
using System.Net.Http;
using System.Net.Http.Headers;
using CredentialVault.Client.Http;
using Microsoft.Extensions.DependencyInjection;

namespace CredentialVault.Client;

/// <summary>
/// Extension methods for registering the vault client with Microsoft DI.
/// </summary>
public static class VaultClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="IVaultClient"/> with a typed <see cref="HttpClient"/>
    /// configured to communicate with the Credential Vault server.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="vaultBaseUrl">The base URL of the Credential Vault server.</param>
    /// <param name="apiKey">The API key to use for authentication (X-Api-Key header).</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddCredentialVaultClient(
        this IServiceCollection services,
        string vaultBaseUrl,
        string apiKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(vaultBaseUrl);
        ArgumentException.ThrowIfNullOrEmpty(apiKey);

        services.AddHttpClient<IVaultClient, VaultHttpClient>(client =>
        {
            client.BaseAddress = new Uri(vaultBaseUrl.TrimEnd('/') + "/");
            client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
            client.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
        });

        return services;
    }
}
