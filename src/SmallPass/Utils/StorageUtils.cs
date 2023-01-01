namespace SmallPass.Utils;

public static class StorageUtils
{
    public static string GetFilePath(string baseDir, string fileName)
    {
        return Path.Combine(baseDir, fileName);
    }

    public static void CreateDirectoryIfNotExists(string entryDir)
    {
        if (!Directory.Exists(entryDir)) Directory.CreateDirectory(entryDir);
    }
}