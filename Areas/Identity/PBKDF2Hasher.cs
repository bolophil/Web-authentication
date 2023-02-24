using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by PBKDF2.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class PBKDF2Hasher : IPasswordHasher<IdentityUser>
{

    /// <summary>
    /// Hash a password using PBKDF2.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        // todo: Use 100,000 iterations and the PBKDF2 algorithm.
         byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password,  salt, 100000,HashAlgorithmName.SHA256, 32);

        // todo: Encode as "Base64(salt):Base64(digest)"
        return Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        // Get the salt and hash from the hashedPassword string
        string[] parts = hashedPassword.Split(':');
        byte[] salt = Convert.FromBase64String(parts[0]);
        byte[] hash = Convert.FromBase64String(parts[1]);

        // Compute the hash of the provided password with the same salt and iteration count
        byte[] computedHash = new Rfc2898DeriveBytes(providedPassword, salt, 100000, HashAlgorithmName.SHA256).GetBytes(32);

        // Compare the computed hash with the stored hash
        if (hash.SequenceEqual(computedHash))
        {
            return PasswordVerificationResult.Success;
        }
        else
        {
            return PasswordVerificationResult.Failed;
        }
    }

}