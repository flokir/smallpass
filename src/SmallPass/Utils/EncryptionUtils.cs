using System.Security.Cryptography;

namespace SmallPass.Utils;

public static class EncryptionUtils
{
    public static byte[] GenerateAesIv()
    {
        using var aesAlgorithm = Aes.Create();
        aesAlgorithm.KeySize = 256;
        aesAlgorithm.GenerateIV();
        return aesAlgorithm.IV;
    }

    public static byte[] EncryptData(byte[] data, byte[] encryptionKey, byte[] iv)
    {
        if (encryptionKey.Length != 256 / 8) throw new ArgumentException("Encryption key must be 256 bits");

        using var aesAlgorithm = Aes.Create();
        aesAlgorithm.KeySize = 256;
        aesAlgorithm.IV = iv;
        aesAlgorithm.Key = encryptionKey;
        aesAlgorithm.Mode = CipherMode.CBC;
        var encryptedData = aesAlgorithm.EncryptCbc(data, iv);
        return encryptedData;
    }

    public static byte[]? DecryptData(byte[] data, byte[] decryptionKey, byte[] iv)
    {
        if (decryptionKey.Length != 256 / 8) throw new ArgumentException("Encryption key must be 256 bits");

        try
        {
            using var aesAlgorithm = Aes.Create();
            aesAlgorithm.KeySize = 256;
            aesAlgorithm.IV = iv;
            aesAlgorithm.Key = decryptionKey;
            aesAlgorithm.Mode = CipherMode.CBC;
            var decryptedData = aesAlgorithm.DecryptCbc(data, iv);
            return decryptedData;
        }
        catch
        {
            Console.WriteLine("An error occured during decryption");
            return null;
        }
    }
    
    public static byte[] PadBytes(byte[] data, int length)
    {
        var paddedBytes = new byte[length];
        for (var i = 0; i < data.Length; i++) paddedBytes[i] = data[i];

        return paddedBytes;
    }
}