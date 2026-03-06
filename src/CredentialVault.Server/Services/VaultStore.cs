using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;

namespace CredentialVault.Server.Services;

/// <summary>
/// In-memory vault store for credential entries.
/// In production, replace with a database-backed implementation (e.g. SQL Server, PostgreSQL).
/// All values are stored AES-256-GCM encrypted; the vault key never leaves the server process.
/// </summary>
public sealed class VaultStore
{
    private readonly ConcurrentDictionary<Guid, CredentialEntry> _store = new();
    private readonly byte[] _vaultKey;

    public VaultStore(byte[] vaultKey)
    {
        if (vaultKey.Length != AesGcmEncryptor.KeySize)
            throw new ArgumentException($"Vault key must be {AesGcmEncryptor.KeySize} bytes.", nameof(vaultKey));
        _vaultKey = vaultKey;
    }

    /// <summary>Stores a credential, encrypting the plaintext value with AES-256-GCM.</summary>
    public CredentialEntry Store(string application, string key, string plainTextValue, string? description = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(application);
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(plainTextValue);

        byte[] encryptedBytes = AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(plainTextValue), _vaultKey);

        var entry = new CredentialEntry
        {
            Application = application,
            Key = key,
            EncryptedValue = Convert.ToBase64String(encryptedBytes),
            Description = description
        };

        // Remove any existing entry with the same application+key before inserting
        var existing = FindEntry(application, key);
        if (existing is not null)
            _store.TryRemove(existing.Id, out _);

        _store[entry.Id] = entry;
        return entry;
    }

    /// <summary>Retrieves and decrypts a credential value.</summary>
    /// <returns>The decrypted plaintext value, or null if not found.</returns>
    public string? Retrieve(string application, string key)
    {
        var entry = FindEntry(application, key);
        if (entry is null)
            return null;

        byte[] decrypted = AesGcmEncryptor.Decrypt(Convert.FromBase64String(entry.EncryptedValue), _vaultKey);
        return Encoding.UTF8.GetString(decrypted);
    }

    /// <summary>Deletes a credential entry.</summary>
    /// <returns>True if the entry was found and deleted.</returns>
    public bool Delete(string application, string key)
    {
        var entry = FindEntry(application, key);
        if (entry is null)
            return false;

        return _store.TryRemove(entry.Id, out _);
    }

    /// <summary>Lists all credential entries for an application (without decrypted values).</summary>
    public IReadOnlyList<CredentialEntry> ListByApplication(string application)
    {
        return _store.Values
            .Where(e => string.Equals(e.Application, application, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Key)
            .ToList();
    }

    /// <summary>Lists all credential entries across all applications (without decrypted values).</summary>
    public IReadOnlyList<CredentialEntry> ListAll()
    {
        return _store.Values
            .OrderBy(e => e.Application)
            .ThenBy(e => e.Key)
            .ToList();
    }

    private CredentialEntry? FindEntry(string application, string key)
    {
        return _store.Values.FirstOrDefault(e =>
            string.Equals(e.Application, application, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(e.Key, key, StringComparison.OrdinalIgnoreCase));
    }
}
