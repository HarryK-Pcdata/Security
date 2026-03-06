using CredentialManager.Encryption;

namespace CredentialManager.Configuration;

/// <summary>
/// Encrypts and decrypts credential values inside INI files (commonly used by
/// legacy Delphi applications).
/// </summary>
/// <remarks>
/// INI format handled: <c>key=value</c> pairs under optional <c>[section]</c>
/// headers, with <c>;</c> or <c>#</c> comment lines.
/// A key is considered a credential if its name matches one of the
/// <see cref="CredentialKeyPatterns"/> (case-insensitive substring match).
/// </remarks>
public sealed class IniFileProcessor
{
    /// <summary>
    /// Key name substrings that identify credential values.
    /// </summary>
    public static readonly IReadOnlyList<string> CredentialKeyPatterns = new[]
    {
        "password", "passwd", "pwd", "secret", "apikey", "api_key",
        "token", "connectionstring", "credentials", "credential",
        "wachtwoord", "kennwort"   // common Dutch/German variants
    };

    private readonly IEncryptor _encryptor;

    public IniFileProcessor(IEncryptor encryptor)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        _encryptor = encryptor;
    }

    /// <summary>
    /// Encrypts all credential values in the INI file and saves it in-place.
    /// Already-encrypted values are left unchanged.
    /// </summary>
    /// <param name="filePath">Path to the .ini file.</param>
    /// <returns>The number of values that were newly encrypted.</returns>
    public int EncryptFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        string[] lines = File.ReadAllLines(filePath);
        (string[] result, int count) = ProcessLines(lines, encrypt: true);
        if (count > 0)
            File.WriteAllLines(filePath, result);
        return count;
    }

    /// <summary>
    /// Decrypts all encrypted values in the INI file and saves it in-place.
    /// </summary>
    /// <param name="filePath">Path to the .ini file.</param>
    /// <returns>The number of values that were decrypted.</returns>
    public int DecryptFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        string[] lines = File.ReadAllLines(filePath);
        (string[] result, int count) = ProcessLines(lines, encrypt: false);
        if (count > 0)
            File.WriteAllLines(filePath, result);
        return count;
    }

    // --- internal helpers -------------------------------------------------

    public (string[] Lines, int Count) ProcessLines(string[] lines, bool encrypt)
    {
        var result = new string[lines.Length];
        int count = 0;

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            result[i] = line;

            // Skip blank lines, section headers, and comment lines.
            string trimmed = line.TrimStart();
            if (trimmed.Length == 0 || trimmed[0] == '[' || trimmed[0] == ';' || trimmed[0] == '#')
                continue;

            int eq = line.IndexOf('=');
            if (eq < 0)
                continue;

            string key = line[..eq].Trim();
            string value = line[(eq + 1)..];

            if (encrypt)
            {
                if (IsCredentialKey(key) && !_encryptor.IsEncrypted(value))
                {
                    result[i] = $"{key}={_encryptor.Encrypt(value)}";
                    count++;
                }
            }
            else
            {
                if (_encryptor.IsEncrypted(value))
                {
                    result[i] = $"{key}={_encryptor.Decrypt(value)}";
                    count++;
                }
            }
        }

        return (result, count);
    }

    private static bool IsCredentialKey(string key) =>
        CredentialKeyPatterns.Any(p =>
            key.Contains(p, StringComparison.OrdinalIgnoreCase));
}
