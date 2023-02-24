using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser>
{

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        var salt = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        // todo: Use 100,000 iterations and the SHA256 algorithm.
        byte[] hash = new byte[32];
        byte[] passwordBytes = Utils.Encoding.GetBytes(password);
        using (var hasher = SHA256.Create())
        {

            byte[] saltedPasswordBytes = new byte[32 + passwordBytes.Length];
            Buffer.BlockCopy(salt, 0, saltedPasswordBytes, 0, 32);
            Buffer.BlockCopy(passwordBytes, 0, saltedPasswordBytes, 32, passwordBytes.Length);

            hash = hasher.ComputeHash(saltedPasswordBytes);
            for (int i = 1; i < 100000; i++)
            {
                hash = hasher.ComputeHash(hash);

            }
        }

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
        byte[] computedHash = new byte[32];
        byte[] providedPasswordBytes = Utils.Encoding.GetBytes(providedPassword);
        using (var hasher = SHA256.Create())
        {
           
            byte[] saltedPasswordBytes = new byte[32 + providedPasswordBytes.Length];
            Buffer.BlockCopy(salt, 0, saltedPasswordBytes, 0, 32);
            Buffer.BlockCopy(providedPasswordBytes, 0, saltedPasswordBytes, 32, providedPasswordBytes.Length);
            computedHash = hasher.ComputeHash(saltedPasswordBytes);
            for (int i = 1; i < 100000; i++)
            {
                computedHash = hasher.ComputeHash(computedHash);
            }
        }
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