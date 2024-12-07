using System.Security.Cryptography;
using System.Text;

namespace CWG.SecureCoding.Core.Services.Common.Security;

/// <summary>
/// Secure token generation for sessions and reset tokens
/// </summary>
public class TokenGenerator
{
    private const int DefaultTokenSize = 32;

    public string GenerateSecureToken(int size = DefaultTokenSize)
    {
        var randomBytes = new byte[size];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return Convert.ToBase64String(randomBytes);
    }

    public string GenerateSessionToken(string userId, DateTimeOffset expiresAt)
    {
        // Combine user ID, expiration, and random data for session token
        var data = Encoding.UTF8.GetBytes($"{userId}:{expiresAt.Ticks}:{GenerateSecureToken(16)}");
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        return Convert.ToBase64String(hash);
    }

    public string GenerateResetToken()
    {
        // Generate a cryptographically secure reset token
        return GenerateSecureToken(48); // Larger size for reset tokens
    }
}
