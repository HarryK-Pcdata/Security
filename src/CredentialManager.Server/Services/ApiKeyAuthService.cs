using System.Security.Cryptography;
using System.Text;
using CredentialManager.Server.Models;

namespace CredentialManager.Server.Services;

/// <summary>
/// Validates API keys against the configured set of authorised keys.
/// Keys are stored as SHA-256 hashes so the raw key material is never
/// persisted in configuration files.
/// </summary>
public sealed class ApiKeyAuthService
{
    private readonly Dictionary<string, ApiKeyRecord> _keyMap;

    public ApiKeyAuthService(IEnumerable<ApiKeyRecord> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        _keyMap = keys.ToDictionary(k => k.HashedKey, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns the <see cref="ApiKeyRecord"/> for the given raw API key,
    /// or <c>null</c> if it is unknown or inactive.
    /// </summary>
    public ApiKeyRecord? Validate(string rawApiKey)
    {
        if (string.IsNullOrWhiteSpace(rawApiKey))
            return null;

        string hash = HashKey(rawApiKey);
        _keyMap.TryGetValue(hash, out ApiKeyRecord? record);
        return record is { IsActive: true } ? record : null;
    }

    /// <summary>
    /// Computes the SHA-256 hash of a raw API key, returned as a lowercase hex string.
    /// Use this when registering new API keys in configuration.
    /// </summary>
    public static string HashKey(string rawApiKey)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawApiKey);
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawApiKey));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
