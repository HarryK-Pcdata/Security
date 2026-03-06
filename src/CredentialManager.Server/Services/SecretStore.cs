using System.Security.Cryptography;
using System.Text;
using CredentialManager.Encryption;
using CredentialManager.Server.Models;
using Microsoft.Extensions.Caching.Memory;

namespace CredentialManager.Server.Services;

/// <summary>
/// In-memory secret store backed by the file system.
/// Secrets are stored on disk as a JSON file whose values are encrypted
/// with the master key so the file itself is safe to back up.
/// </summary>
public sealed class SecretStore : ISecretStore
{
    private readonly IEncryptor _encryptor;
    private readonly string _storePath;
    private readonly IMemoryCache _cache;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private static readonly MemoryCacheEntryOptions CacheOptions =
        new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(5));

    public SecretStore(IEncryptor encryptor, IMemoryCache cache, string storePath)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        ArgumentNullException.ThrowIfNull(cache);
        ArgumentException.ThrowIfNullOrEmpty(storePath);

        _encryptor = encryptor;
        _cache = cache;
        _storePath = storePath;
    }

    /// <inheritdoc />
    public async Task<SecretEntry?> GetAsync(string name, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (_cache.TryGetValue(name, out SecretEntry? cached))
            return cached;

        var all = await LoadAllAsync(ct);
        all.TryGetValue(name, out SecretEntry? entry);

        if (entry is not null)
            _cache.Set(name, entry, CacheOptions);

        return entry;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken ct = default)
    {
        var all = await LoadAllAsync(ct);
        return [.. all.Keys];
    }

    /// <inheritdoc />
    public async Task UpsertAsync(SecretEntry entry, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        await _lock.WaitAsync(ct);
        try
        {
            var all = await LoadAllAsync(ct);
            all[entry.Name] = entry;
            await PersistAsync(all, ct);
            _cache.Remove(entry.Name);
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(string name, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        await _lock.WaitAsync(ct);
        try
        {
            var all = await LoadAllAsync(ct);
            bool removed = all.Remove(name);
            if (removed)
            {
                await PersistAsync(all, ct);
                _cache.Remove(name);
            }
            return removed;
        }
        finally
        {
            _lock.Release();
        }
    }

    // --- private helpers --------------------------------------------------

    private async Task<Dictionary<string, SecretEntry>> LoadAllAsync(CancellationToken ct)
    {
        if (!File.Exists(_storePath))
            return new Dictionary<string, SecretEntry>(StringComparer.OrdinalIgnoreCase);

        string json = await File.ReadAllTextAsync(_storePath, ct);
        var entries = System.Text.Json.JsonSerializer.Deserialize<List<SecretEntry>>(json)
                      ?? [];

        return entries.ToDictionary(e => e.Name, StringComparer.OrdinalIgnoreCase);
    }

    private async Task PersistAsync(Dictionary<string, SecretEntry> all, CancellationToken ct)
    {
        string json = System.Text.Json.JsonSerializer.Serialize(
            all.Values.ToList(),
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        string dir = Path.GetDirectoryName(_storePath)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // Write atomically via a temp file.
        string tmp = _storePath + ".tmp";
        await File.WriteAllTextAsync(tmp, json, ct);
        File.Move(tmp, _storePath, overwrite: true);
    }
}
