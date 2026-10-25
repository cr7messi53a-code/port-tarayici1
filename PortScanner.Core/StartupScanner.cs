using System.IO;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace PortScanner.Core;

public record StartupItem(
    string Name, string Source, string FilePath, string Signature, RiskLevel Risk, string Note)
{
    public string RiskText => Risk switch
    {
        RiskLevel.Yuksek => "Yüksek",
        RiskLevel.Orta => "Orta",
        RiskLevel.Dusuk => "Düşük",
        _ => "Bilinmiyor"
    };
}

[SupportedOSPlatform("windows")]
public static class StartupScanner
{
    public static async Task<List<StartupItem>> ScanAsync(CancellationToken ct = default)
    {
        var raw = new List<(string Name, string Command, string Source)>();

        var keys = new (RegistryKey Root, string Sub, string Source)[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "Kayıt defteri (kullanıcı)"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "Kayıt defteri (sistem)"),
            (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Kayıt defteri (sistem)"),
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

        foreach (var dir in folders)
        {
            try
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                foreach (var f in Directory.GetFiles(dir))
                {
                    if (f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    raw.Add((System.IO.Path.GetFileNameWithoutExtension(f), f, "Başlangıç klasörü"));
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
                "Kısayol. Hedef programı elle kontrol et.");

        if (!File.Exists(path))
            return new StartupItem(name, source, path, "Dosya yok", RiskLevel.Orta,
                "Program dosyası bulunamadı. Silinmiş bir programın kalıntısı olabilir, gerekmiyorsa kaldır.");

        sigs.TryGetValue(path, out var status);

        string sig;
        RiskLevel risk;
        string note;

        switch (status)
        {
            case "Valid":
                sig = "İmzalı"; risk = RiskLevel.Dusuk;
                note = "Geçerli dijital imzası var.";
                break;
            case "NotSigned":
                sig = "İmzasız"; risk = RiskLevel.Orta;
                note = "Dijital imzası yok. Bu tek başına zararlı demek değildir ama tanımıyorsan araştır.";
                break;
            case "HashMismatch":
                sig = "Bozuk imza"; risk = RiskLevel.Yuksek;
                note = "İmzası var ama dosya sonradan değiştirilmiş görünüyor. Dikkat!";
                break;
            case null:
                sig = "Bilinmiyor"; risk = RiskLevel.Bilinmiyor;
                note = "İmza durumu okunamadı.";
                break;
            default:
                sig = "Doğrulanamadı"; risk = RiskLevel.Orta;
                note = "İmza doğrulanamadı.";
                break;
        }

        string lower = path.ToLowerInvariant();
        if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\") || lower.Contains(@"\users\public\"))
        {
            risk = RiskLevel.Yuksek;
            note = "Geçici, İndirilenler ya da herkese açık klasörden çalışıyor. Tanımıyorsan kaldır. " + note;
        }

        return new StartupItem(name, source, path, sig, risk, note);
    }
}

[SupportedOSPlatform("windows")]
public class StartupCheck : ISecurityCheck
{
    public string Name => "Başlangıç programları";
    private const int Weight = 10;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        var items = await StartupScanner.ScanAsync(ct);
        var risky = items.Where(i => i.Risk == RiskLevel.Yuksek).ToList();

        if (risky.Count > 0)
        {
            string names = string.Join(", ", risky.Take(3).Select(i => i.Name));
            return new CheckResult(Name, CheckStatus.Basarisiz,
                $"{risky.Count} başlangıç programı riskli görünüyor: {names}",
                "Başlangıç Programları sekmesinde ayrıntılara bak. Tanımadıklarını Görev Yöneticisi > Başlangıç uygulamaları bölümünden kapat.",
                Weight);
        }

        int imzasiz = items.Count(i => i.Signature == "İmzasız");
        string extra = imzasiz > 0
            ? $" ({imzasiz} tanesi imzasız, bu tek başına zararlı demek değildir.)"
            : "";

        return new CheckResult(Name, CheckStatus.Basarili,
            $"{items.Count} başlangıç programı bulundu, belirgin bir risk yok.{extra}", "", Weight);
    }
}