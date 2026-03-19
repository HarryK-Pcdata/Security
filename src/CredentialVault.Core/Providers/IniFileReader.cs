using CredentialVault.Core.Models;

namespace CredentialVault.Core.Providers;

/// <summary>
/// Reads the Delphi application's <c>DISTRIB.INI</c> file and returns a
/// <see cref="ConnectionParameters"/> instance that mirrors every value
/// loaded by the <c>GlobalReadIni</c> procedure.
///
/// <para>Expected INI layout:</para>
/// <code>
/// [Language]
/// Language=NL
/// LanguageEx=NLD
///
/// [Database]
/// Server0=
/// Server1=
/// ...
/// Server9=
/// UserName=DISTRIB
/// Password=masterkey
/// OracleDLL=oci.dll
/// TNSAdmin=
/// ServerName=XE
/// History=DISTRIB_HIS
///
/// [Local]
/// Company=1
/// Station=1
/// UserId=0
/// </code>
///
/// <para>
/// <b>Note on <c>TXIniFile</c> encryption:</b> if the Delphi application
/// sets <c>Ini.Encryption</c> the INI values are stored in a proprietary
/// encrypted format.  This reader works with plain-text INI files only.
/// Disable encryption in the Delphi app (or save an unencrypted copy) before
/// running the migration.
/// </para>
/// </summary>
public sealed class IniFileReader
{
    // Section names used in DISTRIB.INI
    private const string SectionLanguage = "Language";
    private const string SectionDatabase = "Database";
    private const string SectionLocal    = "Local";

    private readonly string _filePath;

    /// <param name="filePath">Absolute or relative path to <c>DISTRIB.INI</c>.</param>
    public IniFileReader(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path must not be empty.", nameof(filePath));
        _filePath = filePath;
    }

    /// <summary>
    /// Parses the INI file and returns a fully-populated
    /// <see cref="ConnectionParameters"/>.  Missing keys retain the same
    /// default values that the Delphi <c>GlobalReadIni</c> uses.
    /// </summary>
    /// <exception cref="FileNotFoundException">
    /// Thrown when the INI file does not exist.
    /// </exception>
    public ConnectionParameters Read()
    {
        if (!File.Exists(_filePath))
            throw new FileNotFoundException($"INI file not found: {_filePath}", _filePath);

        // Parse every section into one flat look-up keyed by "Section.Key".
        var values = ParseFile();

        var p = new ConnectionParameters();

        // ── [Language] ────────────────────────────────────────────────────
        p.Language   = Get(values, SectionLanguage, "Language",   p.Language);
        p.LanguageEx = Get(values, SectionLanguage, "LanguageEx", p.LanguageEx);

        // ── [Database] ────────────────────────────────────────────────────
        for (int i = 0; i < p.Servers.Length; i++)
            p.Servers[i] = Get(values, SectionDatabase, $"Server{i}", string.Empty);

        p.UserName     = Get(values, SectionDatabase, "UserName",   p.UserName);
        p.Password     = Get(values, SectionDatabase, "Password",   p.Password);
        p.OracleDllPath = Get(values, SectionDatabase, "OracleDLL", p.OracleDllPath);
        p.TnsAdmin     = Get(values, SectionDatabase, "TNSAdmin",   p.TnsAdmin);
        p.ServerName   = Get(values, SectionDatabase, "ServerName", p.ServerName);
        p.History      = Get(values, SectionDatabase, "History",    p.History);

        // ── [Local] ───────────────────────────────────────────────────────
        p.Company = GetInt(values, SectionLocal, "Company", p.Company);
        p.Station = GetInt(values, SectionLocal, "Station", p.Station);
        p.UserId  = GetInt(values, SectionLocal, "UserId",  p.UserId);

        return p;
    }

    // -------------------------------------------------------------------------
    // Parsing helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Reads all lines from the file and builds a dictionary keyed by
    /// <c>"SectionName\0KeyName"</c> (null-byte separator, case-insensitive).
    /// </summary>
    private Dictionary<string, string> ParseFile()
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var currentSection = string.Empty;

        foreach (var rawLine in File.ReadLines(_filePath))
        {
            var line = rawLine.Trim();

            if (line.Length == 0 || line[0] == ';' || line[0] == '#')
                continue;

            if (line[0] == '[' && line[^1] == ']')
            {
                currentSection = line[1..^1].Trim();
                continue;
            }

            var idx = line.IndexOf('=');
            if (idx <= 0)
                continue;

            var key = line[..idx].Trim();
            var val = line[(idx + 1)..].Trim();
            if (!string.IsNullOrEmpty(key))
                dict[$"{currentSection}\0{key}"] = val;
        }

        return dict;
    }

    private static string Get(
        Dictionary<string, string> d, string section, string key, string defaultValue)
    {
        return d.TryGetValue($"{section}\0{key}", out var v) ? v : defaultValue;
    }

    private static int GetInt(
        Dictionary<string, string> d, string section, string key, int defaultValue)
    {
        return d.TryGetValue($"{section}\0{key}", out var v) && int.TryParse(v, out var n)
            ? n
            : defaultValue;
    }
}

