using System.Text.Json;
using SmallPass.Utils;

namespace SmallPass;

public class EntryManager
{
    private readonly string _baseDir;

    public EntryManager(string baseDir)
    {
        _baseDir = baseDir;
    }

    public bool CheckIfEntryWithNameExists(string entryName)
    {
        var entries = ReadEntries();
        return entries.Any(entry => entry.EntryName.Equals(entryName));
    }

    public void SaveEntry(Entry entry)
    {
        // the entry id is used as the filename
        var fileName = entry.Id;
        var jsonText = JsonSerializer.Serialize(entry);
        File.WriteAllText(StorageUtils.GetFilePath(_baseDir, fileName), jsonText);
    }

    public Entry? FindEntryById(string entryId)
    {
        var jsonText = File.ReadAllText(StorageUtils.GetFilePath(_baseDir, entryId));
        var entry = JsonSerializer.Deserialize<Entry>(jsonText);
        return entry;
    }

    public Entry? FindEntryByName(string entryName)
    {
        var entries = ReadEntries();
        return entries.FirstOrDefault(entry => entry.EntryName.Equals(entryName));
    }

    public List<Entry> ReadEntries()
    {
        var entries = new List<Entry>();
        var entryDirectory = _baseDir;
        foreach (var filePath in Directory.GetFiles(entryDirectory))
        {
            var entry = FindEntryById(filePath);
            if (entry != null) entries.Add(entry);
        }

        return entries;
    }
}