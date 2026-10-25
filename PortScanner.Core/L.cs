namespace PortScanner.Core;

public enum Lang { Tr, En }

public static class L
{
    public static Lang Current { get; set; } = DefaultLang();

    private static Lang DefaultLang() =>
        System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "tr"
            ? Lang.Tr : Lang.En;

    // Kullanım: L.T("Türkçe metin", "English text")
    public static string T(string tr, string en) => Current == Lang.Tr ? tr : en;

    private static string SettingsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "PortTarayici", "lang.txt");

    public static void Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
                Current = File.ReadAllText(SettingsPath).Trim() == "en" ? Lang.En : Lang.Tr;
        }
        catch { }
    }

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, Current == Lang.En ? "en" : "tr");
        }
        catch { }
    }
}