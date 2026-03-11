using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using CredentialVault.Core.Encryption;

// ---------------------------------------------------------------------------
// CredentialVault.ConfigMigrator
//
// A command-line tool to help migrate legacy .config and .ini files from
// plain-text credentials to AES-256-GCM encrypted values.
//
// Commands:
//   generate-key              - Generate a new random AES-256 key (Base64)
//   generate-api-key          - Generate a random API key string
//   encrypt <file> <key>      - Encrypt credential values in a .config/.ini file
//   decrypt <file> <key>      - Decrypt credential values in a .config/.ini file
//   encrypt-value <value> <key> - Encrypt a single value
//   decrypt-value <value> <key> - Decrypt a single Base64 value
// ---------------------------------------------------------------------------

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

return args[0].ToLowerInvariant() switch
{
    "generate-key"     => GenerateKey(),
    "generate-api-key" => GenerateApiKey(),
    "encrypt"          => EncryptFile(args),
    "decrypt"          => DecryptFile(args),
    "encrypt-value"    => EncryptValue(args),
    "decrypt-value"    => DecryptValue(args),
    _                  => PrintUsageAndError($"Unknown command: {args[0]}")
};

// ---------------------------------------------------------------------------

static int GenerateKey()
{
    byte[] key = AesGcmEncryptor.GenerateKey();
    Console.WriteLine("AES-256 Key (Base64) - store this securely, e.g. as VAULT_KEY env var:");
    Console.WriteLine(Convert.ToBase64String(key));
    Console.WriteLine();
    Console.WriteLine("PBKDF2 salt for master-password derivation (Base64):");
    Console.WriteLine(Convert.ToBase64String(SecretKeyDerivation.GenerateSalt()));
    return 0;
}

static int GenerateApiKey()
{
    byte[] bytes = RandomNumberGenerator.GetBytes(32);
    string apiKey = Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    Console.WriteLine("Generated API Key:");
    Console.WriteLine(apiKey);
    return 0;
}

static int EncryptFile(string[] args)
{
    if (args.Length < 3)
        return PrintUsageAndError("Usage: encrypt <file> <base64-key>");

    string filePath = args[1];
    string keyBase64 = args[2];

    if (!File.Exists(filePath))
        return PrintUsageAndError($"File not found: {filePath}");

    byte[] key;
    try { key = Convert.FromBase64String(keyBase64); }
    catch { return PrintUsageAndError("Invalid Base64 key."); }

    if (key.Length != AesGcmEncryptor.KeySize)
        return PrintUsageAndError($"Key must be {AesGcmEncryptor.KeySize} bytes when Base64-decoded.");

    string extension = Path.GetExtension(filePath).ToLowerInvariant();
    string content = File.ReadAllText(filePath, Encoding.UTF8);
    (string encrypted, int count) = extension == ".ini"
        ? ProcessIniFile(content, key, encrypt: true)
        : ProcessConfigFile(content, key, encrypt: true);

    string backupPath = filePath + ".backup";
    File.Copy(filePath, backupPath, overwrite: true);
    File.WriteAllText(filePath, encrypted, Encoding.UTF8);

    Console.WriteLine($"Encrypted {count} credential value(s) in '{filePath}'.");
    Console.WriteLine($"Original backed up to '{backupPath}'.");
    return 0;
}

static int DecryptFile(string[] args)
{
    if (args.Length < 3)
        return PrintUsageAndError("Usage: decrypt <file> <base64-key>");

    string filePath = args[1];
    string keyBase64 = args[2];

    if (!File.Exists(filePath))
        return PrintUsageAndError($"File not found: {filePath}");

    byte[] key;
    try { key = Convert.FromBase64String(keyBase64); }
    catch { return PrintUsageAndError("Invalid Base64 key."); }

    if (key.Length != AesGcmEncryptor.KeySize)
        return PrintUsageAndError($"Key must be {AesGcmEncryptor.KeySize} bytes when Base64-decoded.");

    string extension = Path.GetExtension(filePath).ToLowerInvariant();
    string content = File.ReadAllText(filePath, Encoding.UTF8);
    (string decrypted, int count) = extension == ".ini"
        ? ProcessIniFile(content, key, encrypt: false)
        : ProcessConfigFile(content, key, encrypt: false);

    File.WriteAllText(filePath, decrypted, Encoding.UTF8);
    Console.WriteLine($"Decrypted {count} credential value(s) in '{filePath}'.");
    return 0;
}

static int EncryptValue(string[] args)
{
    if (args.Length < 3)
        return PrintUsageAndError("Usage: encrypt-value <plaintext> <base64-key>");

    string plaintext = args[1];
    byte[] key;
    try { key = Convert.FromBase64String(args[2]); }
    catch { return PrintUsageAndError("Invalid Base64 key."); }

    byte[] encrypted = AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(plaintext), key);
    Console.WriteLine("ENC:" + Convert.ToBase64String(encrypted));
    return 0;
}

static int DecryptValue(string[] args)
{
    if (args.Length < 3)
        return PrintUsageAndError("Usage: decrypt-value <ENC:base64> <base64-key>");

    string encValue = args[1];
    if (encValue.StartsWith("ENC:", StringComparison.Ordinal))
        encValue = encValue[4..];

    byte[] key;
    try { key = Convert.FromBase64String(args[2]); }
    catch { return PrintUsageAndError("Invalid Base64 key."); }

    try
    {
        byte[] decrypted = AesGcmEncryptor.Decrypt(Convert.FromBase64String(encValue), key);
        Console.WriteLine(Encoding.UTF8.GetString(decrypted));
        return 0;
    }
    catch (CryptographicException)
    {
        Console.Error.WriteLine("Decryption failed: invalid key or tampered data.");
        return 2;
    }
}

// ---------------------------------------------------------------------------
// File processors
// ---------------------------------------------------------------------------

/// <summary>
/// Processes .config (XML app.config/web.config) files.
/// Encrypts/decrypts values for attributes named password, pwd, secret, or connectionString.
/// </summary>
static (string result, int count) ProcessConfigFile(string content, byte[] key, bool encrypt)
{
    int count = 0;
    string result;

    if (encrypt)
    {
        result = Regex.Replace(content,
            @"((?:password|pwd|secret|connectionString)\s*=\s*"")((?!ENC:)[^""]*)("")",
            match =>
            {
                string prefix = match.Groups[1].Value;
                string val = match.Groups[2].Value;
                string suffix = match.Groups[3].Value;
                string encVal = "ENC:" + Convert.ToBase64String(
                    AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(val), key));
                count++;
                return prefix + encVal + suffix;
            },
            RegexOptions.IgnoreCase);
    }
    else
    {
        result = Regex.Replace(content,
            @"((?:password|pwd|secret|connectionString)\s*=\s*"")(ENC:[A-Za-z0-9+/=]+)("")",
            match =>
            {
                string prefix = match.Groups[1].Value;
                string encPart = match.Groups[2].Value[4..]; // strip ENC:
                string suffix = match.Groups[3].Value;
                try
                {
                    byte[] decrypted = AesGcmEncryptor.Decrypt(Convert.FromBase64String(encPart), key);
                    count++;
                    return prefix + Encoding.UTF8.GetString(decrypted) + suffix;
                }
                catch
                {
                    Console.Error.WriteLine("Warning: could not decrypt a value - skipping.");
                    return match.Value;
                }
            },
            RegexOptions.IgnoreCase);
    }

    return (result, count);
}

/// <summary>
/// Processes .ini files, encrypting/decrypting values for credential keys.
/// INI format: key=value (values prefixed with ENC: are treated as encrypted).
/// </summary>
static (string result, int count) ProcessIniFile(string content, byte[] key, bool encrypt)
{
    int count = 0;
    var credentialKeyPattern = new Regex(
        @"^(password|pwd|secret|apikey|api_key|dbpassword|db_password|connectionstring)\s*=\s*(.*)$",
        RegexOptions.IgnoreCase | RegexOptions.Multiline);

    string result = credentialKeyPattern.Replace(content, match =>
    {
        string iniKey = match.Groups[1].Value;
        string val = match.Groups[2].Value.Trim();

        if (encrypt && !val.StartsWith("ENC:", StringComparison.Ordinal))
        {
            string encVal = "ENC:" + Convert.ToBase64String(
                AesGcmEncryptor.Encrypt(Encoding.UTF8.GetBytes(val), key));
            count++;
            return $"{iniKey}={encVal}";
        }
        else if (!encrypt && val.StartsWith("ENC:", StringComparison.Ordinal))
        {
            try
            {
                string encPart = val[4..];
                byte[] decrypted = AesGcmEncryptor.Decrypt(Convert.FromBase64String(encPart), key);
                count++;
                return $"{iniKey}={Encoding.UTF8.GetString(decrypted)}";
            }
            catch
            {
                Console.Error.WriteLine($"Warning: could not decrypt value for key '{iniKey}' - skipping.");
                return match.Value;
            }
        }

        return match.Value;
    });

    return (result, count);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void PrintUsage()
{
    Console.WriteLine("CredentialVault.ConfigMigrator - Encrypt/decrypt legacy config files");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  generate-key");
    Console.WriteLine("      Generate a new AES-256 key and PBKDF2 salt (printed as Base64).");
    Console.WriteLine();
    Console.WriteLine("  generate-api-key");
    Console.WriteLine("      Generate a random API key for use with the vault server.");
    Console.WriteLine();
    Console.WriteLine("  encrypt <file> <base64-key>");
    Console.WriteLine("      Encrypt credential values in a .config or .ini file.");
    Console.WriteLine("      Creates a .backup copy of the original file.");
    Console.WriteLine();
    Console.WriteLine("  decrypt <file> <base64-key>");
    Console.WriteLine("      Decrypt credential values encrypted with the given key.");
    Console.WriteLine();
    Console.WriteLine("  encrypt-value <plaintext> <base64-key>");
    Console.WriteLine("      Encrypt a single plaintext value. Outputs ENC:<base64>.");
    Console.WriteLine();
    Console.WriteLine("  decrypt-value <ENC:base64> <base64-key>");
    Console.WriteLine("      Decrypt a single ENC: prefixed value.");
    Console.WriteLine();
    Console.WriteLine("Encrypted values use the prefix 'ENC:' followed by Base64-encoded");
    Console.WriteLine("AES-256-GCM ciphertext (nonce + tag + ciphertext).");
}

static int PrintUsageAndError(string error)
{
    Console.Error.WriteLine($"Error: {error}");
    Console.Error.WriteLine("Run without arguments for usage information.");
    return 1;
}
