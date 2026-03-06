using System.Xml;
using System.Xml.Linq;
using CredentialManager.Encryption;

namespace CredentialManager.Configuration;

/// <summary>
/// Encrypts and decrypts credential values inside .NET application configuration
/// files (<c>app.config</c> / <c>web.config</c>) in the standard
/// <c>&lt;appSettings&gt;</c> and <c>&lt;connectionStrings&gt;</c> sections.
/// </summary>
/// <remarks>
/// A key is considered a credential if its name matches one of the
/// <see cref="CredentialKeyPatterns"/> (case-insensitive substring match).
/// </remarks>
public sealed class AppConfigProcessor
{
    /// <summary>
    /// Key name substrings that identify credential values.
    /// Any <c>appSettings</c> key whose name contains one of these strings
    /// (case-insensitive) will be encrypted.
    /// </summary>
    public static readonly IReadOnlyList<string> CredentialKeyPatterns = new[]
    {
        "password", "passwd", "pwd", "secret", "apikey", "api_key",
        "token", "connectionstring", "credentials", "credential"
    };

    private readonly IEncryptor _encryptor;

    public AppConfigProcessor(IEncryptor encryptor)
    {
        ArgumentNullException.ThrowIfNull(encryptor);
        _encryptor = encryptor;
    }

    /// <summary>
    /// Encrypts all credential values found in the file and saves it in-place.
    /// Already-encrypted values are left unchanged.
    /// </summary>
    /// <param name="filePath">Path to the .config file.</param>
    /// <returns>The number of values that were newly encrypted.</returns>
    public int EncryptFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        XDocument doc = LoadXml(filePath);
        int count = EncryptDocument(doc);
        if (count > 0)
            SaveXml(doc, filePath);
        return count;
    }

    /// <summary>
    /// Decrypts all encrypted credential values in the file and saves it in-place.
    /// </summary>
    /// <param name="filePath">Path to the .config file.</param>
    /// <returns>The number of values that were decrypted.</returns>
    public int DecryptFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        XDocument doc = LoadXml(filePath);
        int count = DecryptDocument(doc);
        if (count > 0)
            SaveXml(doc, filePath);
        return count;
    }

    // --- internal helpers -------------------------------------------------

    public int EncryptDocument(XDocument doc)
    {
        int count = 0;

        // appSettings section
        foreach (XElement add in doc.Descendants("appSettings").Elements("add"))
        {
            string? key = (string?)add.Attribute("key");
            string? value = (string?)add.Attribute("value");

            if (key is null || value is null)
                continue;
            if (!IsCredentialKey(key))
                continue;
            if (_encryptor.IsEncrypted(value))
                continue;

            add.SetAttributeValue("value", _encryptor.Encrypt(value));
            count++;
        }

        // connectionStrings section – encrypt the full connectionString attribute
        foreach (XElement add in doc.Descendants("connectionStrings").Elements("add"))
        {
            string? cs = (string?)add.Attribute("connectionString");
            if (cs is null || _encryptor.IsEncrypted(cs))
                continue;

            add.SetAttributeValue("connectionString", _encryptor.Encrypt(cs));
            count++;
        }

        return count;
    }

    public int DecryptDocument(XDocument doc)
    {
        int count = 0;

        foreach (XElement add in doc.Descendants("appSettings").Elements("add"))
        {
            string? value = (string?)add.Attribute("value");
            if (value is null || !_encryptor.IsEncrypted(value))
                continue;

            add.SetAttributeValue("value", _encryptor.Decrypt(value));
            count++;
        }

        foreach (XElement add in doc.Descendants("connectionStrings").Elements("add"))
        {
            string? cs = (string?)add.Attribute("connectionString");
            if (cs is null || !_encryptor.IsEncrypted(cs))
                continue;

            add.SetAttributeValue("connectionString", _encryptor.Decrypt(cs));
            count++;
        }

        return count;
    }

    private static bool IsCredentialKey(string key) =>
        CredentialKeyPatterns.Any(p =>
            key.Contains(p, StringComparison.OrdinalIgnoreCase));

    private static XDocument LoadXml(string filePath)
    {
        using var reader = XmlReader.Create(filePath, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static void SaveXml(XDocument doc, string filePath)
    {
        var settings = new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            OmitXmlDeclaration = false
        };
        using var writer = XmlWriter.Create(filePath, settings);
        doc.Save(writer);
    }
}
