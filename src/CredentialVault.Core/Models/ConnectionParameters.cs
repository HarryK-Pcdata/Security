namespace CredentialVault.Core.Models;

/// <summary>
/// Represents the Oracle database connection parameters used by the Delphi
/// <c>SetDBParams</c> procedure. These values map directly to the keys written
/// into <see cref="TFDConnection.Params"/> and the <c>TFDPhysOracleDriverLink</c>
/// properties.
/// </summary>
public sealed class ConnectionParameters
{
    /// <summary>Database password (written as <c>PASSWORD=</c> in TFDConnection.Params).</summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>Oracle server / TNS alias (written as <c>Database=</c>).</summary>
    public string Database { get; set; } = string.Empty;

    /// <summary>Database user name (written as <c>USER_NAME=</c>).</summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>FireDAC driver identifier (written as <c>DriverID=</c>, default <c>Ora</c>).</summary>
    public string DriverId { get; set; } = "Ora";

    /// <summary>Oracle character set (written as <c>CharacterSet=</c>, default <c>UTF8</c>).</summary>
    public string CharacterSet { get; set; } = "UTF8";

    /// <summary>Full path to the Oracle client DLL (set on <c>TFDPhysOracleDriverLink.VendorLib</c>).</summary>
    public string VendorLib { get; set; } = string.Empty;

    /// <summary>Directory that contains <c>tnsnames.ora</c> (set on <c>TFDPhysOracleDriverLink.TNSAdmin</c>).</summary>
    public string TnsAdmin { get; set; } = string.Empty;
}
