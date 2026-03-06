namespace CredentialManager.Encryption;

/// <summary>
/// Defines the contract for encrypting and decrypting credential values.
/// </summary>
public interface IEncryptor
{
    /// <summary>Encrypts the supplied plaintext credential value.</summary>
    /// <param name="plaintext">The plaintext credential value to encrypt.</param>
    /// <returns>A Base64-encoded encrypted string prefixed with <c>ENC:</c>.</returns>
    string Encrypt(string plaintext);

    /// <summary>Decrypts an encrypted credential value.</summary>
    /// <param name="ciphertext">The encrypted value (must start with <c>ENC:</c>).</param>
    /// <returns>The original plaintext credential value.</returns>
    string Decrypt(string ciphertext);

    /// <summary>Returns <c>true</c> when the value looks like it was encrypted by this library.</summary>
    bool IsEncrypted(string value);
}
