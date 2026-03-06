using System.CommandLine;
using CredentialManager.Configuration;
using CredentialManager.Encryption;
using CredentialManager.KeyManagement;

// Ensure the System.CommandLine package is available
// dotnet add package System.CommandLine --prerelease
// (added via project file)

namespace CredentialManager.CLI;

internal static class Program
{
    internal static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("credmgr – Credential Manager CLI for legacy application config files.");

        rootCommand.AddCommand(BuildEncryptCommand());
        rootCommand.AddCommand(BuildDecryptCommand());
        rootCommand.AddCommand(BuildGenerateKeyCommand());
        rootCommand.AddCommand(BuildEncryptValueCommand());
        rootCommand.AddCommand(BuildDecryptValueCommand());

        return await rootCommand.InvokeAsync(args);
    }

    // ------------------------------------------------------------------
    // encrypt  –  encrypt credentials inside a config or ini file
    // ------------------------------------------------------------------
    private static Command BuildEncryptCommand()
    {
        var fileArg = new Argument<FileInfo>("file", "Path to the .config or .ini file to encrypt.");
        var keyFileOption = new Option<FileInfo?>("--key-file", "Path to the Base64-encoded AES-256 key file.");
        var vaultUrlOption = new Option<string?>("--vault-url", "URL of the central Credential Vault server.");
        var vaultApiKeyOption = new Option<string?>("--vault-api-key", "API key for the Credential Vault server.");

        var cmd = new Command("encrypt", "Encrypt credential values inside a .config or .ini file.")
        {
            fileArg, keyFileOption, vaultUrlOption, vaultApiKeyOption
        };

        cmd.SetHandler(async (file, keyFile, vaultUrl, vaultApiKey) =>
        {
            IKeyProvider keyProvider = ResolveKeyProvider(keyFile, vaultUrl, vaultApiKey);
            byte[] key = await keyProvider.GetKeyAsync();
            var encryptor = new AesGcmEncryptor(key);

            int count = file.Extension.ToLowerInvariant() switch
            {
                ".ini" => new IniFileProcessor(encryptor).EncryptFile(file.FullName),
                _      => new AppConfigProcessor(encryptor).EncryptFile(file.FullName)
            };

            Console.WriteLine($"Encrypted {count} credential value(s) in '{file.Name}'.");
        }, fileArg, keyFileOption, vaultUrlOption, vaultApiKeyOption);

        return cmd;
    }

    // ------------------------------------------------------------------
    // decrypt  –  decrypt credentials inside a config or ini file
    // ------------------------------------------------------------------
    private static Command BuildDecryptCommand()
    {
        var fileArg = new Argument<FileInfo>("file", "Path to the .config or .ini file to decrypt.");
        var keyFileOption = new Option<FileInfo?>("--key-file", "Path to the Base64-encoded AES-256 key file.");
        var vaultUrlOption = new Option<string?>("--vault-url", "URL of the central Credential Vault server.");
        var vaultApiKeyOption = new Option<string?>("--vault-api-key", "API key for the Credential Vault server.");

        var cmd = new Command("decrypt", "Decrypt credential values inside a .config or .ini file (for troubleshooting).")
        {
            fileArg, keyFileOption, vaultUrlOption, vaultApiKeyOption
        };

        cmd.SetHandler(async (file, keyFile, vaultUrl, vaultApiKey) =>
        {
            IKeyProvider keyProvider = ResolveKeyProvider(keyFile, vaultUrl, vaultApiKey);
            byte[] key = await keyProvider.GetKeyAsync();
            var encryptor = new AesGcmEncryptor(key);

            int count = file.Extension.ToLowerInvariant() switch
            {
                ".ini" => new IniFileProcessor(encryptor).DecryptFile(file.FullName),
                _      => new AppConfigProcessor(encryptor).DecryptFile(file.FullName)
            };

            Console.WriteLine($"Decrypted {count} credential value(s) in '{file.Name}'.");
        }, fileArg, keyFileOption, vaultUrlOption, vaultApiKeyOption);

        return cmd;
    }

    // ------------------------------------------------------------------
    // generate-key  –  generate a new random AES-256 key
    // ------------------------------------------------------------------
    private static Command BuildGenerateKeyCommand()
    {
        var outFileOption = new Option<FileInfo?>("--out", "Write the key to this file instead of stdout.");
        var fromPasswordOption = new Option<string?>("--from-password", "Derive the key from a password using PBKDF2.");
        var saltOption = new Option<string?>("--salt", "Base64-encoded salt for PBKDF2 key derivation (min 16 bytes).");

        var cmd = new Command("generate-key", "Generate a new AES-256 key (or derive one from a password).")
        {
            outFileOption, fromPasswordOption, saltOption
        };

        cmd.SetHandler(async (outFile, password, saltBase64) =>
        {
            byte[] key;

            if (!string.IsNullOrWhiteSpace(password))
            {
                byte[] salt;
                if (!string.IsNullOrWhiteSpace(saltBase64))
                {
                    salt = Convert.FromBase64String(saltBase64);
                }
                else
                {
                    // Generate a random salt and print it so the caller can store it.
                    salt = new byte[32];
                    System.Security.Cryptography.RandomNumberGenerator.Fill(salt);
                    Console.WriteLine($"Generated salt (store this): {Convert.ToBase64String(salt)}");
                }

                key = AesGcmEncryptor.DeriveKeyFromPassword(password, salt);
            }
            else
            {
                key = AesGcmEncryptor.GenerateKey();
            }

            string base64Key = Convert.ToBase64String(key);

            if (outFile is not null)
            {
                await File.WriteAllTextAsync(outFile.FullName, base64Key);
                Console.WriteLine($"Key written to '{outFile.FullName}'.");
                Console.WriteLine("Protect this file: restrict read access to the service account only.");
            }
            else
            {
                Console.WriteLine(base64Key);
            }
        }, outFileOption, fromPasswordOption, saltOption);

        return cmd;
    }

    // ------------------------------------------------------------------
    // encrypt-value  –  encrypt a single value (for scripting)
    // ------------------------------------------------------------------
    private static Command BuildEncryptValueCommand()
    {
        var valueArg = new Argument<string>("value", "Plaintext value to encrypt.");
        var keyFileOption = new Option<FileInfo?>("--key-file", "Path to the Base64-encoded AES-256 key file.");

        var cmd = new Command("encrypt-value", "Encrypt a single plaintext credential value.")
        {
            valueArg, keyFileOption
        };

        cmd.SetHandler(async (value, keyFile) =>
        {
            IKeyProvider keyProvider = ResolveKeyProvider(keyFile, null, null);
            byte[] key = await keyProvider.GetKeyAsync();
            var encryptor = new AesGcmEncryptor(key);
            Console.WriteLine(encryptor.Encrypt(value));
        }, valueArg, keyFileOption);

        return cmd;
    }

    // ------------------------------------------------------------------
    // decrypt-value  –  decrypt a single encrypted value (for scripting)
    // ------------------------------------------------------------------
    private static Command BuildDecryptValueCommand()
    {
        var valueArg = new Argument<string>("value", "Encrypted value to decrypt.");
        var keyFileOption = new Option<FileInfo?>("--key-file", "Path to the Base64-encoded AES-256 key file.");

        var cmd = new Command("decrypt-value", "Decrypt a single encrypted credential value.")
        {
            valueArg, keyFileOption
        };

        cmd.SetHandler(async (value, keyFile) =>
        {
            IKeyProvider keyProvider = ResolveKeyProvider(keyFile, null, null);
            byte[] key = await keyProvider.GetKeyAsync();
            var encryptor = new AesGcmEncryptor(key);
            Console.WriteLine(encryptor.Decrypt(value));
        }, valueArg, keyFileOption);

        return cmd;
    }

    // ------------------------------------------------------------------
    // Helper: resolve the key provider based on CLI options
    // ------------------------------------------------------------------
    private static IKeyProvider ResolveKeyProvider(
        FileInfo? keyFile,
        string? vaultUrl,
        string? vaultApiKey)
    {
        if (keyFile is not null)
            return new FileKeyProvider(keyFile.FullName);

        if (!string.IsNullOrWhiteSpace(vaultUrl) && !string.IsNullOrWhiteSpace(vaultApiKey))
            return new VaultKeyProvider(vaultUrl, vaultApiKey);

        // Fall back to environment variable
        return new EnvironmentKeyProvider();
    }
}
