using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace CWG.SecureCoding.Core.Services.Common.Security;

/// <summary>
/// Handles secure encryption of payment data using AES-256
/// </summary>
public class PaymentEncryption
{
    private readonly byte[] _key;
    private readonly byte[] _iv;

    public PaymentEncryption(IConfiguration configuration)
    {
        // In production, these would be stored in secure key vault
        _key = Convert.FromBase64String(configuration["Payment:EncryptionKey"]);
        _iv = Convert.FromBase64String(configuration["Payment:EncryptionIV"]);
    }

    public string EncryptCardNumber(string cardNumber)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        using var encryptor = aes.CreateEncryptor();
        byte[] plainText = System.Text.Encoding.UTF8.GetBytes(cardNumber);
        byte[] cipherText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);

        return Convert.ToBase64String(cipherText);
    }

    public string DecryptCardNumber(string encryptedCardNumber)
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;

        using var decryptor = aes.CreateDecryptor();
        byte[] cipherText = Convert.FromBase64String(encryptedCardNumber);
        byte[] plainText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);

        return System.Text.Encoding.UTF8.GetString(plainText);
    }

    public string MaskCardNumber(string cardNumber)
    {
        if (string.IsNullOrWhiteSpace(cardNumber) || cardNumber.Length < 4)
            return "****";

        return $"****-****-****-{cardNumber.Substring(cardNumber.Length - 4)}";
    }
}
