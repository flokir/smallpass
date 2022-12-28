namespace SmallPass;

public record Entry(string Id, string EntryName, byte[] PasswordHash, byte[] EncryptedPassword, byte[] Iv, byte[] Salt);