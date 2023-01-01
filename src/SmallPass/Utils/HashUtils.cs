using System.Security.Cryptography;

namespace SmallPass.Utils;

public static class HashUtils
{
    public static byte[] GenerateSecureSalt(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    public static byte[] ComputePbkdf2Hash(byte[] password, byte[] salt)
    {
        // use 1000000 iterations for optimal time / complexity
        var iterationCount = 1000000; // changed to 1000000 iterations
        var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterationCount, HashAlgorithmName.SHA512);
        return deriveBytes.GetBytes(32); // 32 Bytes = 256 bits
    }

    public static byte[] ComputeSha256Hash(byte[] data)
    {
        using var mySha = SHA256.Create();
        var hash = mySha.ComputeHash(data);
        return hash;
    }
}