using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;
using CredentialVault.Core.Providers;

// ---------------------------------------------------------------------------
// CredentialVault.ConfigMigrator
// Manages the 'distribconnection' Windows environment variable used as a
// replacement for the Delphi application's DISTRIB.INI file.
//
// Commands
//   migrate  – one-shot: read DISTRIB.INI → write distribconnection env var
//   set      – write individual parameters to the environment variable
//   get      – read and display the current environment variable
//   test     – verify the environment variable is set and can be parsed
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

return command switch
{
    "migrate" => RunMigrate(args, encryptor),
    "set"     => RunSet(args, encryptor),
    "get"     => RunGet(encryptor),
    "test"    => RunTest(encryptor),
    _         => UnknownCommand(command),
};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

static int RunMigrate(string[] args, AesGcmEncryptor? encryptor)
{
    var iniPath = GetArg(args, "--ini-file");
    if (iniPath is null)
    {
        Console.Error.WriteLine("Error: --ini-file is required for the migrate command.");
        return 1;
    }

    var scopeArg = GetArg(args, "--scope")?.ToLowerInvariant();
    var target = ParseScope(scopeArg);

    ConnectionParameters parameters;
    try
    {
        var reader = new IniFileReader(iniPath);
        parameters = reader.Read();
    }
    catch (FileNotFoundException ex)
    {
        Console.Error.WriteLine($"Error: {ex.Message}");
        return 1;
    }

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

    var encNote = encryptor is not null ? " (password encrypted with AES-256-GCM)" : " (password stored in plain text — consider using --passphrase)";
    Console.WriteLine($"Migration complete: DISTRIB.INI → distribconnection [{target}]{encNote}");
    PrintParameters(parameters);
    return 0;
}

static int RunSet(string[] args, AesGcmEncryptor? encryptor)
{
    var parameters = new ConnectionParameters
    {
        ServerName   = GetArg(args, "--server-name")  ?? "XE",
        UserName     = GetArg(args, "--username")      ?? "DISTRIB",
        Password     = GetArg(args, "--password")      ?? string.Empty,
        OracleDllPath = GetArg(args, "--oracle-dll")  ?? "oci.dll",
        TnsAdmin     = GetArg(args, "--tns-admin")     ?? string.Empty,
        History      = GetArg(args, "--history")       ?? "DISTRIB_HIS",
        DriverId     = GetArg(args, "--driver-id")     ?? "Ora",
        CharacterSet = GetArg(args, "--charset")       ?? "UTF8",
        Language     = GetArg(args, "--language")      ?? "NL",
        LanguageEx   = GetArg(args, "--language-ex")   ?? "NLD",
        Company      = int.TryParse(GetArg(args, "--company"),  out var co) ? co : 1,
        Station      = int.TryParse(GetArg(args, "--station"),  out var st) ? st : 1,
        UserId       = int.TryParse(GetArg(args, "--user-id"),  out var ui) ? ui : 0,
    };

    if (string.IsNullOrWhiteSpace(parameters.ServerName))
    {
        Console.Error.WriteLine("Error: --server-name is required.");
        return 1;
    }

    var target = ParseScope(GetArg(args, "--scope")?.ToLowerInvariant());
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

    var encNote = encryptor is not null ? " (password encrypted)" : " (password in plain text)";
    Console.WriteLine($"distribconnection written to {target} scope{encNote}.");
    PrintParameters(parameters);
    return 0;
}

static int RunGet(AesGcmEncryptor? encryptor)
{
    var provider = new DistribConnectionProvider(encryptor);
    var p = provider.Read();
    if (p is null)
    {
        Console.Error.WriteLine(
            $"Environment variable '{DistribConnectionProvider.EnvironmentVariableName}' is not set.");
        return 1;
    }

    Console.WriteLine("distribconnection parameters:");
    PrintParameters(p);
    return 0;
}

static int RunTest(AesGcmEncryptor? encryptor)
{
    var raw =
        Environment.GetEnvironmentVariable(DistribConnectionProvider.EnvironmentVariableName, EnvironmentVariableTarget.Machine)
        ?? Environment.GetEnvironmentVariable(DistribConnectionProvider.EnvironmentVariableName, EnvironmentVariableTarget.User)
        ?? Environment.GetEnvironmentVariable(DistribConnectionProvider.EnvironmentVariableName, EnvironmentVariableTarget.Process);

    if (raw is null)
    {
        Console.Error.WriteLine(
            $"FAIL: '{DistribConnectionProvider.EnvironmentVariableName}' is not set in any scope.");
        return 1;
    }

    Console.WriteLine($"Raw value length: {raw.Length} characters");
    try
    {
        var p = new DistribConnectionProvider(encryptor).Read()!;
        Console.WriteLine("OK: Parameters parsed successfully.");
        Console.WriteLine($"  ServerName   : {p.ServerName}");
        Console.WriteLine($"  UserName     : {p.UserName}");
        Console.WriteLine($"  Language     : {p.Language}");
        Console.WriteLine($"  Company      : {p.Company}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"FAIL: {ex.Message}");
        return 1;
    }
}

static int UnknownCommand(string cmd)
{
    Console.Error.WriteLine($"Unknown command: {cmd}");
    PrintUsage();
    return 1;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

static EnvironmentVariableTarget ParseScope(string? scope) => scope switch
{
    "machine" => EnvironmentVariableTarget.Machine,
    "user"    => EnvironmentVariableTarget.User,
    _         => EnvironmentVariableTarget.Process,
};

static string? GetArg(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++)
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            return args[i + 1];
    return null;
}

static void PrintParameters(ConnectionParameters p)
{
    Console.WriteLine($"  [Database]");
    Console.WriteLine($"    ServerName   : {p.ServerName}");
    Console.WriteLine($"    UserName     : {p.UserName}");
    Console.WriteLine($"    Password     : {"".PadRight(Math.Max(p.Password.Length, 1), '*')}");
    Console.WriteLine($"    OracleDllPath: {p.OracleDllPath}");
    Console.WriteLine($"    TnsAdmin     : {p.TnsAdmin}");
    Console.WriteLine($"    History      : {p.History}");
    Console.WriteLine($"    DriverId     : {p.DriverId}");
    Console.WriteLine($"    CharacterSet : {p.CharacterSet}");
    for (int i = 0; i < p.Servers.Length; i++)
        if (!string.IsNullOrEmpty(p.Servers[i]))
            Console.WriteLine($"    Server{i}      : {p.Servers[i]}");
    Console.WriteLine($"  [Language]");
    Console.WriteLine($"    Language     : {p.Language}");
    Console.WriteLine($"    LanguageEx   : {p.LanguageEx}");
    Console.WriteLine($"  [Local]");
    Console.WriteLine($"    Company      : {p.Company}");
    Console.WriteLine($"    Station      : {p.Station}");
    Console.WriteLine($"    UserId       : {p.UserId}");
}

static void PrintUsage()
{
    Console.WriteLine("""
        CredentialVault.ConfigMigrator — replace DISTRIB.INI with the distribconnection env var

        Commands:
          migrate  Read DISTRIB.INI and write all values to the distribconnection environment variable.
          set      Write connection parameters directly (without an INI file).
          get      Read and display the current distribconnection parameters.
          test     Verify the variable is set and can be parsed.

        Options for 'migrate':
          --ini-file    <path>    Path to DISTRIB.INI                        (required)
          --scope       <scope>   machine | user | process  (default: process)
          --passphrase  <phrase>  Encrypt the password with AES-256-GCM

        Options for 'set':
          --server-name <name>    Oracle TNS alias / server name  (default: XE)
          --username    <user>    Database user name              (default: DISTRIB)
          --password    <pass>    Database password
          --oracle-dll  <path>    Path to Oracle client DLL       (default: oci.dll)
          --tns-admin   <path>    Directory containing tnsnames.ora
          --history     <schema>  History schema name             (default: DISTRIB_HIS)
          --driver-id   <id>      FireDAC driver ID               (default: Ora)
          --charset     <cs>      Oracle character set            (default: UTF8)
          --language    <lang>    Two-letter language code        (default: NL)
          --language-ex <lang>    Three-letter language code      (default: NLD)
          --company     <n>       Company identifier              (default: 1)
          --station     <n>       Workstation identifier          (default: 1)
          --user-id     <n>       User identifier                 (default: 0)
          --scope       <scope>   machine | user | process        (default: process)
          --passphrase  <phrase>  Encrypt the password with AES-256-GCM

        Options for 'get' and 'test':
          --passphrase  <phrase>  Passphrase used to decrypt the password

        Examples:
          migrate --ini-file "C:\MyApp\DISTRIB.INI" --scope user --passphrase MySecret
          get --passphrase MySecret
          test
        """);
}

