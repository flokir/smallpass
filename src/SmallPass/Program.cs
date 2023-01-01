using System.Text;
using SmallPass.Utils;

namespace SmallPass;

// todo don't show entered passwords in console

internal static class Program
{
    private static readonly EntryManager EntryManager = new(GetEntryDirectory());


    private static void Main(string[] args)
    {
        StorageUtils.CreateDirectoryIfNotExists(GetEntryDirectory());
        if (args.Length >= 1)
            switch (args[0])
            {
                case "list":
                    ListEntries();
                    return;
                case "view":
                    if (args.Length >= 2)
                    {
                        ViewEntryByName(args[1]);
                        return;
                    }

                    Console.WriteLine("Usage: smallpass view [entryname]");
                    return;
                case "viewid":
                    if (args.Length >= 2)
                    {
                        ViewEntryById(args[1]);
                        return;
                    }

                    Console.WriteLine("Usage: smallpass viewid [entryid]");
                    return;
                case "create":
                    if (args.Length >= 2)
                    {
                        CreateEntry(args[1]);
                        return;
                    }

                    Console.WriteLine("Usage: smallpass create [entryname]");
                    return;
                case "help":
                    Console.WriteLine("To be implemented");
                    Console.WriteLine("Usage: smallpass [help/list/create/view]");
                    return;
            }

        Console.WriteLine("Usage: smallpass [help/list/create/view/viewid]");
    }

    private static string? ReadInputHidden()
    {
        var sb = new StringBuilder();
        while (true)
        {
            var keyInfo = Console.ReadKey(true);
            if (keyInfo.Key == ConsoleKey.Enter)
                // enter ends the input
                break;
            if (keyInfo.Key == ConsoleKey.Backspace)
            {
                // backspace so we remove the last char from the stringbuilder
                sb.Remove(sb.Length - 1, 1);
                continue;
            }
            sb.Append(keyInfo.KeyChar);
            
        }
        return sb.ToString();
    }

    private static void ViewEntryByName(string name)
    {
        var entry = EntryManager.FindEntryByName(name);
        if (entry == null)
        {
            Console.WriteLine($"Entry with name {name} not found");
            return;
        }

        PrintFullEntry(entry);
    }

    private static void ViewEntryById(string entryId)
    {
        var entry = EntryManager.FindEntryById(entryId);
        if (entry == null)
        {
            Console.WriteLine($"Entry with id {entryId} not found");
            return;
        }

        PrintFullEntry(entry);
    }

    private static void ListEntries()
    {
        var entries = EntryManager.ReadEntries();
        entries.ForEach(PrintEntrySummary);
    }

    private static void PrintFullEntry(Entry entry)
    {
        Console.WriteLine($"Id: {entry.Id}");
        Console.WriteLine($"Name: {entry.EntryName}");
        Console.WriteLine($"Hash: {Convert.ToBase64String(entry.PasswordHash)}");
        Console.WriteLine($"IV: {Convert.ToBase64String(entry.Iv)}");
        Console.WriteLine($"Salt: {Convert.ToBase64String(entry.Salt)}");
        Console.WriteLine("Enter decryption key");

        var decryptionKey = ReadInputHidden();
        if (string.IsNullOrEmpty(decryptionKey))
        {
            Console.WriteLine("Decryption key is empty");
            return;
        }

        var decryptedPassword = DecryptPassword(entry.EncryptedPassword, decryptionKey, entry.Iv, entry.Salt);
        Console.WriteLine(decryptedPassword);
    }

    private static string DecryptPassword(byte[] encryptedPassword, string decryptionKey, byte[] iv, byte[] salt)
    {
        var decryptionKeyBytes = Encoding.UTF8.GetBytes(decryptionKey);
        var decryptionKeyHash = HashUtils.ComputePbkdf2Hash(decryptionKeyBytes, salt);
        var decryptedPasswordBytes = EncryptionUtils.DecryptData(encryptedPassword, decryptionKeyHash, iv);
        var decryptedPassword = Encoding.UTF8.GetString(decryptedPasswordBytes ?? Array.Empty<byte>());
        return decryptedPassword.Trim('\0'); // remove the padding trailing zeroes
    }


    private static void CreateEntry(string entryName)
    {
        if (EntryManager.CheckIfEntryWithNameExists(entryName))
        {
            Console.WriteLine("There is already an entry with this name");
            return;
        }

        Console.WriteLine("Please enter the password to be stored");
        var password = ReadInputHidden();
        if (string.IsNullOrEmpty(password))
        {
            Console.WriteLine("Password is empty");
            return;
        }

        Console.WriteLine("Please enter the encryption key");
        var encryptionKey = ReadInputHidden();
        if (string.IsNullOrEmpty(encryptionKey))
        {
            Console.WriteLine("Encryption password is empty");
            return;
        }

        var fileName = Guid.NewGuid().ToString();


        var iv = EncryptionUtils.GenerateAesIv();
        var salt = HashUtils.GenerateSecureSalt(32);

        var encryptedPassword = EncryptPassword(password, encryptionKey, iv, salt);
        var encryptedPasswordHash = HashUtils.ComputeSha256Hash(encryptedPassword);

        var entry = new Entry(fileName, entryName, encryptedPasswordHash, encryptedPassword, iv, salt);
        EntryManager.SaveEntry(entry);
    }

    private static byte[] EncryptPassword(string password, string encryptionKey, byte[] iv, byte[] salt)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        passwordBytes =
            EncryptionUtils.PadBytes(passwordBytes,
                256); // we add a padding to the password so the encrypted data doesn't indicate the length
        var encryptionKeyBytes = Encoding.UTF8.GetBytes(encryptionKey);
        var encryptionKeyHash = HashUtils.ComputePbkdf2Hash(encryptionKeyBytes, salt);
        var encryptedPassword = EncryptionUtils.EncryptData(passwordBytes, encryptionKeyHash, iv);
        return encryptedPassword;
    }

    private static string GetEntryDirectory()
    {
        var homePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(homePath, ".pw");
    }

    private static void PrintEntrySummary(Entry entry)
    {
        Console.WriteLine($"{entry.EntryName}:{entry.Id}:{Convert.ToBase64String(entry.PasswordHash)}");
    }
}