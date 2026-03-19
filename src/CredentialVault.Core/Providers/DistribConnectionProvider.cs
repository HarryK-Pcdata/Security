using System.Text;
using CredentialVault.Core.Encryption;
using CredentialVault.Core.Models;

namespace CredentialVault.Core.Providers;

/// <summary>
/// Reads and writes the full set of Delphi <c>GlobalReadIni</c> values stored
/// in the <c>distribconnection</c> Windows environment variable.
///
/// <para>
/// The variable contains a semicolon-separated list of <c>key=value</c> pairs
/// covering all three INI sections (Language, Database, Local):
/// </para>
/// <code>
/// ServerName=XE;UserName=DISTRIB;Password=ENC:…;OracleDllPath=oci.dll;
/// TnsAdmin=;History=DISTRIB_HIS;DriverId=Ora;CharacterSet=UTF8;
/// Server0=;Server1=;…;Server9=;
/// Language=NL;LanguageEx=NLD;
/// Company=1;Station=1;UserId=0
/// </code>
/// <para>
/// When an <see cref="AesGcmEncryptor"/> is supplied, the <c>Password</c>
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
    /// Reads all connection parameters from the <c>distribconnection</c>
    /// environment variable, searching Machine → User → Process scope in order.
    /// Returns <c>null</c> when the variable is not set in any scope.
    /// </summary>
    public ConnectionParameters? Read()
    {
        var raw = GetRawValue();
        if (raw is null)
            return null;

        var d = ParseKeyValues(raw);
        var p = new ConnectionParameters();

        // ── Database ──────────────────────────────────────────────────────
        if (d.TryGetValue("ServerName",   out var sn))  p.ServerName    = sn;
        if (d.TryGetValue("UserName",     out var un))  p.UserName      = un;
        if (d.TryGetValue("Password",     out var pwd)) p.Password      = DecryptIfNeeded(pwd);
        if (d.TryGetValue("OracleDllPath",out var dll)) p.OracleDllPath = dll;
        if (d.TryGetValue("TnsAdmin",     out var tns)) p.TnsAdmin      = tns;
        if (d.TryGetValue("History",      out var his)) p.History       = his;
        if (d.TryGetValue("DriverId",     out var did)) p.DriverId      = did;
        if (d.TryGetValue("CharacterSet", out var cs))  p.CharacterSet  = cs;

        for (int i = 0; i < p.Servers.Length; i++)
        {
            if (d.TryGetValue($"Server{i}", out var sv))
                p.Servers[i] = sv;
        }

        // ── Language ──────────────────────────────────────────────────────
        if (d.TryGetValue("Language",   out var lang))  p.Language   = lang;
        if (d.TryGetValue("LanguageEx", out var langx)) p.LanguageEx = langx;

        // ── Local ─────────────────────────────────────────────────────────
        if (d.TryGetValue("Company", out var co) && int.TryParse(co, out var coN)) p.Company = coN;
        if (d.TryGetValue("Station", out var st) && int.TryParse(st, out var stN)) p.Station = stN;
        if (d.TryGetValue("UserId",  out var ui) && int.TryParse(ui, out var uiN)) p.UserId  = uiN;

        return p;
    }

    // -------------------------------------------------------------------------
    // Write
    // -------------------------------------------------------------------------

    /// <summary>
    /// Serialises <paramref name="parameters"/> and stores them in the
    /// <c>distribconnection</c> environment variable at the requested
    /// <paramref name="target"/> scope.
    /// </summary>
    public void Write(
        ConnectionParameters parameters,
        EnvironmentVariableTarget target = EnvironmentVariableTarget.Process)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var pwd = _encryptor is not null
            ? _encryptor.Encrypt(parameters.Password)
            : parameters.Password;

        var sb = new StringBuilder();

        // Database
        Append(sb, "ServerName",    parameters.ServerName);
        Append(sb, "UserName",      parameters.UserName);
        Append(sb, "Password",      pwd);
        Append(sb, "OracleDllPath", parameters.OracleDllPath);
        Append(sb, "TnsAdmin",      parameters.TnsAdmin);
        Append(sb, "History",       parameters.History);
        Append(sb, "DriverId",      parameters.DriverId);
        Append(sb, "CharacterSet",  parameters.CharacterSet);

        for (int i = 0; i < parameters.Servers.Length; i++)
            Append(sb, $"Server{i}", parameters.Servers[i] ?? string.Empty);

        // Language
        Append(sb, "Language",   parameters.Language);
        Append(sb, "LanguageEx", parameters.LanguageEx);

        // Local
        Append(sb, "Company", parameters.Company.ToString());
        Append(sb, "Station", parameters.Station.ToString());
        Append(sb, "UserId",  parameters.UserId.ToString());

        if (sb.Length > 0 && sb[^1] == ';')
            sb.Length--;

        Environment.SetEnvironmentVariable(EnvironmentVariableName, sb.ToString(), target);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string? GetRawValue() =>
        Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.Machine)
        ?? Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.User)
        ?? Environment.GetEnvironmentVariable(EnvironmentVariableName, EnvironmentVariableTarget.Process);

    private string DecryptIfNeeded(string value) =>
        _encryptor is not null ? _encryptor.Decrypt(value) : value;

    private static void Append(StringBuilder sb, string key, string value)
    {
        // Always write the key (even if empty) so all fields are always present
        // in the serialised string, making it easy to locate them with tools.
        sb.Append(key).Append('=').Append(value).Append(';');
    }

    private static Dictionary<string, string> ParseKeyValues(string raw)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in raw.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = segment.IndexOf('=');
            if (idx <= 0) continue;
            var key = segment[..idx].Trim();
            var val = segment[(idx + 1)..].Trim();
            if (!string.IsNullOrEmpty(key))
                dict[key] = val;
        }
        return dict;
    }
}

