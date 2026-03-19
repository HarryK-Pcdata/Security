using System.Text;
using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;

namespace CredentialVault.Core.Providers;

/// <summary>
/// Reads and writes Oracle database connection parameters stored in the
/// <c>distribconnection</c> Windows environment variable.
///
/// <para>
/// The environment variable contains a semicolon-separated list of
/// <c>key=value</c> pairs that map directly to the parameters used by the
/// Delphi <c>SetDBParams</c> procedure:
/// </para>
/// <code>
/// Password=secret;Database=MYDB;UserName=scott;DriverId=Ora;CharacterSet=UTF8;VendorLib=C:\oracle\oci.dll;TnsAdmin=C:\oracle\network\admin
/// </code>
/// <para>
/// When an <see cref="AesGcmEncryptor"/> is supplied the <c>Password</c>
/// field is stored as an <c>ENC:…</c> token and decrypted on read.
/// All other fields are stored in plain text.
/// </para>
/// </summary>
public sealed class DistribConnectionProvider
{
    /// <summary>Name of the Windows environment variable.</summary>
    public const string EnvironmentVariableName = "distribconnection";

    private readonly AesGcmEncryptor? _encryptor;

    /// <param name="encryptor">
    /// Optional encryptor used to protect the password field.
    /// When <c>null</c> the password is stored and returned in plain text.
    /// </param>
    public DistribConnectionProvider(AesGcmEncryptor? encryptor = null)
    {
        _encryptor = encryptor;
    }

    // -------------------------------------------------------------------------
    // Read
    // -------------------------------------------------------------------------

    /// <summary>
    /// Reads connection parameters from the <c>distribconnection</c>
    /// environment variable.  The variable is searched in order:
    /// <list type="number">
    ///   <item>Machine-level (<c>HKLM</c>) – requires elevated rights to write.</item>
    ///   <item>User-level (<c>HKCU</c>).</item>
    ///   <item>Process-level (in-memory, useful for tests).</item>
    /// </list>
    /// </summary>
    /// <returns>Parsed <see cref="ConnectionParameters"/>, or <c>null</c> when
    /// the environment variable is not set.</returns>
    public ConnectionParameters? Read()
    {
        var raw = GetRawValue();
        if (raw is null)
            return null;

        var dict = ParseKeyValues(raw);
        var parameters = new ConnectionParameters();

        if (dict.TryGetValue("Password", out var pwd))
            parameters.Password = DecryptIfNeeded(pwd);

        if (dict.TryGetValue("Database", out var db))
            parameters.Database = db;

        if (dict.TryGetValue("UserName", out var user))
            parameters.UserName = user;

        if (dict.TryGetValue("DriverId", out var driver))
            parameters.DriverId = driver;

        if (dict.TryGetValue("CharacterSet", out var cs))
            parameters.CharacterSet = cs;

        if (dict.TryGetValue("VendorLib", out var lib))
            parameters.VendorLib = lib;

        if (dict.TryGetValue("TnsAdmin", out var tns))
            parameters.TnsAdmin = tns;

        return parameters;
    }

    // -------------------------------------------------------------------------
    // Write
    // -------------------------------------------------------------------------

    /// <summary>
    /// Serialises <paramref name="parameters"/> and stores them in the
    /// <c>distribconnection</c> environment variable at the requested
    /// <paramref name="target"/> scope.
    /// </summary>
    /// <param name="parameters">Connection parameters to persist.</param>
    /// <param name="target">
    /// Environment variable target scope.  Defaults to
    /// <see cref="EnvironmentVariableTarget.Process"/> which is useful for
    /// testing without requiring elevated rights.  Use
    /// <see cref="EnvironmentVariableTarget.Machine"/> or
    /// <see cref="EnvironmentVariableTarget.User"/> to make the setting
    /// persistent across process restarts.
    /// </param>
    public void Write(
        ConnectionParameters parameters,
        EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var pwd = _encryptor is not null
            ? _encryptor.Encrypt(parameters.Password)
            : parameters.Password;

        var sb = new StringBuilder();
        AppendPair(sb, "Password", pwd);
        AppendPair(sb, "Database", parameters.Database);
        AppendPair(sb, "UserName", parameters.UserName);
        AppendPair(sb, "DriverId", parameters.DriverId);
        AppendPair(sb, "CharacterSet", parameters.CharacterSet);
        AppendPair(sb, "VendorLib", parameters.VendorLib);
        AppendPair(sb, "TnsAdmin", parameters.TnsAdmin);

        // Remove the trailing semicolon.
        if (sb.Length > 0 && sb[^1] == ';')
            sb.Length--;

        Environment.SetEnvironmentVariable(EnvironmentVariableName, sb.ToString(), target);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string? GetRawValue()
    {
        // Prefer machine-level, fall back to user-level, then process-level.
        return
            Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.Machine)
            ?? Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.User)
            ?? Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.Process);
    }

    private string DecryptIfNeeded(string value) =>
        _encryptor is not null ? _encryptor.Decrypt(value) : value;

    private static void AppendPair(StringBuilder sb, string key, string value)
    {
        if (!string.IsNullOrEmpty(value))
            sb.Append(key).Append('=').Append(value).Append(';');
    }

    /// <summary>
    /// Parses a semicolon-delimited <c>key=value</c> string into a dictionary.
    /// Keys are matched case-insensitively so that existing variables set by
    /// other tools (e.g. <c>PASSWORD</c> vs <c>Password</c>) are handled
    /// correctly.
    /// </summary>
    private static Dictionary<string, string> ParseKeyValues(string raw)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in raw.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = segment.IndexOf('=');
            if (idx <= 0)
                continue;
            var key = segment[..idx].Trim();
            var val = segment[(idx + 1)..];
            if (!string.IsNullOrEmpty(key))
                dict[key] = val;
        }
        return dict;
    }
}
