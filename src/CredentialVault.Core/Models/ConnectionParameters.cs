namespace CredentialVault.Core.Models;

/// <summary>
/// Represents every value read by the Delphi <c>GlobalReadIni</c> procedure
/// from <c>DISTRIB.INI</c>.  All fields map 1-to-1 to the Delphi globals so
/// that a single Windows environment variable can replace the INI file.
/// </summary>
public sealed class ConnectionParameters
{
    // ------------------------------------------------------------------
    // [Database] section
    // ------------------------------------------------------------------

    /// <summary>
    /// Active Oracle server / TNS alias (<c>GlobalServerName</c>, default <c>XE</c>).
    /// Written as <c>Database=</c> in <c>TFDConnection.Params</c>.
    /// </summary>
    public string ServerName { get; set; } = "XE";

    /// <summary>
    /// Up to 10 selectable server entries (<c>GlobalServers[0..9]</c>).
    /// Serialised as <c>Server0=</c> … <c>Server9=</c>.
    /// </summary>
    public string[] Servers { get; set; } = new string[10];

    /// <summary>Database user name (<c>GlobalUserName</c>, default <c>DISTRIB</c>).
    /// Written as <c>USER_NAME=</c> in <c>TFDConnection.Params</c>.</summary>
    public string UserName { get; set; } = "DISTRIB";

    /// <summary>Database password (<c>GlobalPassword</c>, default <c>masterkey</c>).
    /// Written as <c>PASSWORD=</c> in <c>TFDConnection.Params</c>.
    /// Stored encrypted (AES-256-GCM) when a passphrase is supplied.</summary>
    public string Password { get; set; } = "masterkey";

    /// <summary>Full path to the Oracle client DLL (<c>GlobalOracleDLLPath</c>, default <c>oci.dll</c>).
    /// Set on <c>TFDPhysOracleDriverLink.VendorLib</c>.</summary>
    public string OracleDllPath { get; set; } = "oci.dll";

    /// <summary>Directory containing <c>tnsnames.ora</c> (<c>GlobalTNSAdminPath</c>).
    /// Set on <c>TFDPhysOracleDriverLink.TNSAdmin</c>.</summary>
    public string TnsAdmin { get; set; } = string.Empty;

    /// <summary>History schema name (<c>GlobalHistory</c>, default <c>DISTRIB_HIS</c>).</summary>
    public string History { get; set; } = "DISTRIB_HIS";

    /// <summary>FireDAC driver identifier written as <c>DriverID=</c> (default <c>Ora</c>).</summary>
    public string DriverId { get; set; } = "Ora";

    /// <summary>Oracle character set written as <c>CharacterSet=</c> (default <c>UTF8</c>).</summary>
    public string CharacterSet { get; set; } = "UTF8";

    // ------------------------------------------------------------------
    // [Language] section
    // ------------------------------------------------------------------

    /// <summary>Two-letter language code (<c>GlobalLanguage</c>, default <c>NL</c>).</summary>
    public string Language { get; set; } = "NL";

    /// <summary>Three-letter language code (<c>GlobalLanguageEx</c>, default <c>NLD</c>).</summary>
    public string LanguageEx { get; set; } = "NLD";

    // ------------------------------------------------------------------
    // [Local] section
    // ------------------------------------------------------------------

    /// <summary>Company identifier (<c>GlobalCompany</c>, default <c>1</c>).</summary>
    public int Company { get; set; } = 1;

    /// <summary>Workstation identifier (<c>GlobalStation</c>, default <c>1</c>).</summary>
    public int Station { get; set; } = 1;

    /// <summary>User identifier (<c>GlobalUserId</c>, default <c>0</c>).</summary>
    public int UserId { get; set; }
}
