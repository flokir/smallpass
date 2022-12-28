namespace SmallPass.Utils;

public static class StorageUtils
{
    public static string GetFilePath(string baseDir, string fileName)
    {
        return Path.Combine(baseDir, fileName);
    }
}