using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace PortScanner.Core;

public record StartupItem(
    string Name, string Source, string FilePath, string Signature, RiskLevel Risk, string Note)
{
    public string RiskText => Risk switch
    {
        RiskLevel.Yuksek => L.T("Yüksek", "High"),
        RiskLevel.Orta => L.T("Orta", "Medium"),
        RiskLevel.Dusuk => L.T("Düşük", "Low"),
        _ => L.T("Bilinmiyor", "Unknown")
    };
}

[SupportedOSPlatform("windows")]
public static class StartupScanner
{
    public static string SigUnsigned => L.T("İmzasız", "Unsigned");

    public static async Task<List<StartupItem>> ScanAsync(CancellationToken ct = default)
    {
        var raw = new List<(string Name, string Command, string Source)>();

        string regUser = L.T("Kayıt defteri (kullanıcı)", "Registry (user)");
        string regSys = L.T("Kayıt defteri (sistem)", "Registry (system)");

        var keys = new (RegistryKey Root, string Sub, string Source)[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", regUser),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", regSys),
            (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", regSys),
        };

        foreach (var (root, sub, source) in keys)
        {
            try
            {
                using var k = root.OpenSubKey(sub);
                if (k == null) continue;
                foreach (var name in k.GetValueNames())
                    if (k.GetValue(name) is string cmd && cmd.Length > 0)
                        raw.Add((name, cmd, source));
            }
            catch { }
        }

        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };

        string startupFolder = L.T("Başlangıç klasörü", "Startup folder");

        foreach (var dir in folders)
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                foreach (var f in Directory.GetFiles(dir))
                {
                    if (f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    raw.Add((System.IO.Path.GetFileNameWithoutExtension(f), f, startupFolder));
                }
            }
            catch { }
        }

        var entries = raw
            .Select(r => (r.Name, r.Source, FilePath: ExtractPath(r.Command)))
            .ToList();

        var toCheck = entries
            .Select(e => e.FilePath)
            .Where(p => !p.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && File.Exists(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var sigs = await GetSignaturesAsync(toCheck, ct);

        return entries
            .Select(e => Evaluate(e.Name, e.Source, e.FilePath, sigs))
            .OrderByDescending(i => i.Risk)
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ExtractPath(string command)
    {
        string c = Environment.ExpandEnvironmentVariables(command.Trim());

        if (c.StartsWith('"'))
        {
            int end = c.IndexOf('"', 1);
            return end > 1 ? c[1..end] : c.Trim('"');
        }

        int exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exe >= 0) return c[..(exe + 4)];

        return c.Split(' ')[0];
    }

    // Tek PowerShell çağrısıyla tüm dosyaların imza durumunu okur
    private static async Task<Dictionary<string, string>> GetSignaturesAsync(
        List<string> paths, CancellationToken ct)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (paths.Count == 0) return result;

        try
        {
            string list = string.Join(",", paths.Select(p => "'" + p.Replace("'", "''") + "'"));
            string script =
                "$ErrorActionPreference='SilentlyContinue'; $p = @(" + list + "); " +
                "for ($i = 0; $i -lt $p.Count; $i++) { " +
                "$i.ToString() + '|' + (Get-AuthenticodeSignature -LiteralPath $p[$i]).Status }";

            string output = await PowerShellRunner.RunAsync(script, ct);

            foreach (var line in output.Split('\n'))
            {
                var parts = line.Trim().Split('|');
                if (parts.Length == 2 && int.TryParse(parts[0], out int idx)
                    && idx >= 0 && idx < paths.Count)
                    result[paths[idx]] = parts[1];
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }

        return result;
    }

    private static StartupItem Evaluate(
        string name, string source, string path, Dictionary<string, string> sigs)
    {
        if (path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            return new StartupItem(name, source, path, "-", RiskLevel.Bilinmiyor,
                L.T("Kısayol. Hedef programı elle kontrol et.",
                    "Shortcut. Check the target program manually."));

        if (!File.Exists(path))
            return new StartupItem(name, source, path, L.T("Dosya yok", "Missing"), RiskLevel.Orta,
                L.T("Program dosyası bulunamadı. Silinmiş bir programın kalıntısı olabilir, gerekmiyorsa kaldır.",
                    "The program file was not found. It may be a leftover of a removed program, remove it if not needed."));

        sigs.TryGetValue(path, out var status);

        string sig;
        RiskLevel risk;
        string note;

        switch (status)
        {
            case "Valid":
                sig = L.T("İmzalı", "Signed"); risk = RiskLevel.Dusuk;
                note = L.T("Geçerli dijital imzası var.", "Has a valid digital signature.");
                break;
            case "NotSigned":
                sig = SigUnsigned; risk = RiskLevel.Orta;
                note = L.T("Dijital imzası yok. Bu tek başına zararlı demek değildir ama tanımıyorsan araştır.",
                           "No digital signature. This alone does not mean it is malicious, but look into it if you don't recognize it.");
                break;
            case "HashMismatch":
                sig = L.T("Bozuk imza", "Broken signature"); risk = RiskLevel.Yuksek;
                note = L.T("İmzası var ama dosya sonradan değiştirilmiş görünüyor. Dikkat!",
                           "It has a signature but the file seems to have been modified afterwards. Be careful!");
                break;
            case null:
                sig = L.T("Bilinmiyor", "Unknown"); risk = RiskLevel.Bilinmiyor;
                note = L.T("İmza durumu okunamadı.", "Could not read the signature status.");
                break;
            default:
                sig = L.T("Doğrulanamadı", "Not verified"); risk = RiskLevel.Orta;
                note = L.T("İmza doğrulanamadı.", "The signature could not be verified.");
                break;
        }

        string lower = path.ToLowerInvariant();
        if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\") || lower.Contains(@"\users\public\"))
        {
            risk = RiskLevel.Yuksek;
            note = L.T("Geçici, İndirilenler ya da herkese açık klasörden çalışıyor. Tanımıyorsan kaldır. ",
                       "Runs from a temporary, Downloads or public folder. Remove it if you don't recognize it. ") + note;
        }

        return new StartupItem(name, source, path, sig, risk, note);
    }
}

[SupportedOSPlatform("windows")]
public class StartupCheck : ISecurityCheck
{
    public string Name => L.T("Başlangıç programları", "Startup programs");
    private const int Weight = 10;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        var items = await StartupScanner.ScanAsync(ct);
        var risky = items.Where(i => i.Risk == RiskLevel.Yuksek).ToList();

        if (risky.Count > 0)
        {
            string names = string.Join(", ", risky.Take(3).Select(i => i.Name));
            return new CheckResult(Name, CheckStatus.Basarisiz,
                L.T($"{risky.Count} başlangıç programı riskli görünüyor: {names}",
                    $"{risky.Count} startup program(s) look risky: {names}"),
                L.T("Başlangıç Programları sekmesinde ayrıntılara bak. Tanımadıklarını Görev Yöneticisi > Başlangıç uygulamaları bölümünden kapat.",
                    "See the details in the Startup Programs tab. Disable the ones you don't recognize in Task Manager > Startup apps."),
                Weight);
        }

        int unsigned = items.Count(i => i.Signature == StartupScanner.SigUnsigned);
        string extra = unsigned > 0
            ? L.T($" ({unsigned} tanesi imzasız, bu tek başına zararlı demek değildir.)",
                  $" ({unsigned} unsigned, which alone does not mean malicious.)")
            : "";

        return new CheckResult(Name, CheckStatus.Basarili,
            L.T($"{items.Count} başlangıç programı bulundu, belirgin bir risk yok.{extra}",
                $"{items.Count} startup program(s) found, no obvious risk.{extra}"), "", Weight);
    }
}