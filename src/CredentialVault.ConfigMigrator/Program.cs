using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;
using CredentialVault.Core.Providers;

// ---------------------------------------------------------------------------
// CredentialVault.ConfigMigrator
// A small CLI that manages the 'distribconnection' Windows environment
// variable used by the Delphi SetDBParams procedure.
//
// Commands
//   set   – write connection parameters to the environment variable
//   get   – read and display the current connection parameters
//   test  – verify the environment variable is set and can be parsed
// ---------------------------------------------------------------------------

if (args.Length == 0)
{
    PrintUsage();
    return 1;
}

var command = args[0].ToLowerInvariant();
var passphrase = GetArg(args, "--passphrase");
AesGcmEncryptor? encryptor = passphrase is not null
    ? AesGcmEncryptor.FromPassphrase(passphrase)
    : null;

switch (command)
{
    case "set":
        return RunSet(args, encryptor);
    case "get":
        return RunGet(encryptor);
    case "test":
        return RunTest(encryptor);
    default:
        Console.Error.WriteLine($"Unknown command: {command}");
        PrintUsage();
        return 1;
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

static int RunSet(string[] args, AesGcmEncryptor? encryptor)
{
    var parameters = new ConnectionParameters
    {
        Password    = GetArg(args, "--password")    ?? string.Empty,
        Database    = GetArg(args, "--database")    ?? string.Empty,
        UserName    = GetArg(args, "--username")    ?? string.Empty,
        DriverId    = GetArg(args, "--driver-id")   ?? "Ora",
        CharacterSet = GetArg(args, "--charset")    ?? "UTF8",
        VendorLib   = GetArg(args, "--vendor-lib")  ?? string.Empty,
        TnsAdmin    = GetArg(args, "--tns-admin")   ?? string.Empty,
    };

    if (string.IsNullOrWhiteSpace(parameters.Database))
    {
        Console.Error.WriteLine("Error: --database is required.");
        return 1;
    }

    var scopeArg = GetArg(args, "--scope")?.ToLowerInvariant();
    var target = scopeArg switch
    {
        "machine" => EnvironmentVariableTarget.Machine,
        "user"    => EnvironmentVariableTarget.User,
        _         => EnvironmentVariableTarget.Process,
    };

    var provider = new DistribConnectionProvider(encryptor);
    try
    {
        provider.Write(parameters, target);
    }
    catch (UnauthorizedAccessException)
    {
        Console.Error.WriteLine(
            "Error: writing to Machine-level environment variables requires elevated (Administrator) rights.");
        return 1;
    }

    var encryptionNote = encryptor is not null ? " (password encrypted)" : " (password stored in plain text)";
    Console.WriteLine($"distribconnection written to {target} scope{encryptionNote}.");
    Console.WriteLine($"  Database    : {parameters.Database}");
    Console.WriteLine($"  UserName    : {parameters.UserName}");
    Console.WriteLine($"  DriverId    : {parameters.DriverId}");
    Console.WriteLine($"  CharacterSet: {parameters.CharacterSet}");
    Console.WriteLine($"  VendorLib   : {parameters.VendorLib}");
    Console.WriteLine($"  TnsAdmin    : {parameters.TnsAdmin}");
    return 0;
}

static int RunGet(AesGcmEncryptor? encryptor)
{
    var provider = new DistribConnectionProvider(encryptor);
    var parameters = provider.Read();
    if (parameters is null)
    {
        Console.Error.WriteLine(
            $"Environment variable '{DistribConnectionProvider.EnvironmentVariableName}' is not set.");
        return 1;
    }

    Console.WriteLine($"distribconnection parameters:");
    Console.WriteLine($"  Database    : {parameters.Database}");
    Console.WriteLine($"  UserName    : {parameters.UserName}");
    Console.WriteLine($"  Password    : {"*".PadRight(parameters.Password.Length, '*')}");
    Console.WriteLine($"  DriverId    : {parameters.DriverId}");
    Console.WriteLine($"  CharacterSet: {parameters.CharacterSet}");
    Console.WriteLine($"  VendorLib   : {parameters.VendorLib}");
    Console.WriteLine($"  TnsAdmin    : {parameters.TnsAdmin}");
    return 0;
}

static int RunTest(AesGcmEncryptor? encryptor)
{
    var raw = Environment.GetEnvironmentVariable(
        DistribConnectionProvider.EnvironmentVariableName,
        EnvironmentVariableTarget.Machine)
        ?? Environment.GetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName,
            EnvironmentVariableTarget.User)
        ?? Environment.GetEnvironmentVariable(
            DistribConnectionProvider.EnvironmentVariableName,
            EnvironmentVariableTarget.Process);

    if (raw is null)
    {
        Console.Error.WriteLine(
            $"FAIL: Environment variable '{DistribConnectionProvider.EnvironmentVariableName}' is not set.");
        return 1;
    }

    Console.WriteLine($"Raw value: {raw}");

    var provider = new DistribConnectionProvider(encryptor);
    try
    {
        var parameters = provider.Read();
        Console.WriteLine("OK: Connection parameters parsed successfully.");
        Console.WriteLine($"  Database    : {parameters!.Database}");
        Console.WriteLine($"  UserName    : {parameters.UserName}");
        Console.WriteLine($"  DriverId    : {parameters.DriverId}");
        Console.WriteLine($"  CharacterSet: {parameters.CharacterSet}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"FAIL: {ex.Message}");
        return 1;
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

static string? GetArg(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            return args[i + 1];
    }
    return null;
}

static void PrintUsage()
{
    Console.WriteLine("""
        CredentialVault.ConfigMigrator — manage the 'distribconnection' environment variable

        Commands:
          set   Write connection parameters to the environment variable.
          get   Read and display the current connection parameters.
          test  Verify the environment variable is set and can be parsed.

        Options for 'set':
          --database    <name>    Oracle TNS alias or server name   (required)
          --username    <user>    Database user name
          --password    <pass>    Database password
          --driver-id   <id>      FireDAC driver ID    (default: Ora)
          --charset     <cs>      Oracle character set (default: UTF8)
          --vendor-lib  <path>    Full path to the Oracle client DLL
          --tns-admin   <path>    Directory containing tnsnames.ora
          --scope       <scope>   machine | user | process (default: process)
          --passphrase  <phrase>  Encrypt the password with AES-256-GCM

        Options for 'get' and 'test':
          --passphrase  <phrase>  Passphrase used to decrypt the password

        Examples:
          set --database MYDB --username scott --password tiger --scope machine --passphrase MySecret
          get --passphrase MySecret
          test
        """);
}
