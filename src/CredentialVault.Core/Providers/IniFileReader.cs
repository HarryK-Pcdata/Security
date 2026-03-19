using CredentialVault.Core.Models;

namespace CredentialVault.Core.Providers;

/// <summary>
/// Reads Oracle database connection parameters from a Windows-style INI file.
///
/// <para>
/// The reader handles the common Delphi / FireDAC INI layout where credentials
/// live under a named section, for example:
/// </para>
/// <code>
/// [Database]
/// Password=tiger
/// Database=MYDB
/// UserName=scott
/// DriverID=Ora
/// CharacterSet=UTF8
/// VendorLib=C:\oracle\oci.dll
/// TnsAdmin=C:\oracle\network\admin
/// </code>
/// <para>
/// When <paramref name="section"/> is <c>null</c> the reader collects
/// key=value lines from the entire file regardless of section headers,
/// which handles flat INI files (no sections).
/// </para>
/// </summary>
public sealed class IniFileReader
{
    private readonly string _filePath;
    private readonly string? _section;

    /// <param name="filePath">Absolute or relative path to the INI file.</param>
    /// <param name="section">
    /// Name of the INI section that holds the credentials (e.g. <c>"Database"</c>).
    /// Pass <c>null</c> to search the whole file.
    /// </param>
    public IniFileReader(string filePath, string? section = null)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path must not be empty.", nameof(filePath));
        _filePath = filePath;
        _section  = section;
    }

    /// <summary>
    /// Reads the INI file and returns a <see cref="ConnectionParameters"/> instance
    /// populated with the values found.  Fields that are absent in the file keep
    /// their default values (<see cref="ConnectionParameters.DriverId"/> = <c>Ora</c>,
    /// <see cref="ConnectionParameters.CharacterSet"/> = <c>UTF8</c>).
    /// </summary>
    /// <exception cref="FileNotFoundException">
    /// Thrown when the INI file does not exist at <see cref="_filePath"/>.
    /// </exception>
    public ConnectionParameters Read()
    {
        if (!File.Exists(_filePath))
            throw new FileNotFoundException(
                $"INI file not found: {_filePath}", _filePath);

        var dict = ParseFile();
        var p = new ConnectionParameters();

        if (dict.TryGetValue("Password",     out var pwd))  p.Password     = pwd;
        if (dict.TryGetValue("Database",     out var db))   p.Database     = db;
        if (dict.TryGetValue("UserName",     out var usr))  p.UserName     = usr;
        // Delphi FireDAC also accepts "User_Name" or "USER_NAME"
        if (string.IsNullOrEmpty(p.UserName) &&
            dict.TryGetValue("User_Name",    out var usr2)) p.UserName     = usr2;
        if (dict.TryGetValue("DriverID",     out var did))  p.DriverId     = did;
        if (dict.TryGetValue("DriverId",     out var did2)) p.DriverId     = did2;
        if (dict.TryGetValue("CharacterSet", out var cs))   p.CharacterSet = cs;
        if (dict.TryGetValue("VendorLib",    out var lib))  p.VendorLib    = lib;
        if (dict.TryGetValue("TnsAdmin",     out var tns))  p.TnsAdmin     = tns;

        return p;
    }

    // -------------------------------------------------------------------------
    // Parsing
    // -------------------------------------------------------------------------

    private Dictionary<string, string> ParseFile()
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        bool   inTargetSection = _section is null; // flat file: always "in section"
        bool   sectionFound    = _section is null;

        foreach (var rawLine in File.ReadLines(_filePath))
        {
            var line = rawLine.Trim();

            // Skip blank lines and comments (; or #).
            if (line.Length == 0 || line[0] == ';' || line[0] == '#')
                continue;

            // Section header: [SectionName]
            if (line[0] == '[' && line[^1] == ']')
            {
                var name = line[1..^1].Trim();
                inTargetSection = _section is null ||
                                  string.Equals(name, _section, StringComparison.OrdinalIgnoreCase);
                if (inTargetSection)
                    sectionFound = true;
                continue;
            }

            if (!inTargetSection)
                continue;

            // Key=Value line.
            var idx = line.IndexOf('=');
            if (idx <= 0)
                continue;

            var key = line[..idx].Trim();
            var val = line[(idx + 1)..].Trim();
            if (!string.IsNullOrEmpty(key))
                dict[key] = val;
        }

        if (_section is not null && !sectionFound)
            throw new InvalidOperationException(
                $"Section '[{_section}]' was not found in '{_filePath}'.");

        return dict;
    }
}
