using System.Runtime.Versioning;
using System.Xml.Linq;

namespace PortScanner.Core;

[SupportedOSPlatform("windows")]
public class WifiCheck : ISecurityCheck
{
    public string Name => "Kayıtlı Wi-Fi ağları";
    private const int Weight = 15;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        string dir = Path.Combine(Path.GetTempPath(), "pt_wifi_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);

        try
        {
            // Profilleri şifresiz (key=clear OLMADAN) geçici klasöre aktarır
            string output;
            try
            {
                string safeDir = dir.Replace("'", "''");
                output = await PowerShellRunner.RunAsync(
                    $"$d = '{safeDir}'; & netsh wlan export profile (\"folder=\" + $d) | Out-Null; 'OK'", ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { output = ""; }

            var files = Directory.GetFiles(dir, "*.xml");
            if (output != "OK" || files.Length == 0)
                return new CheckResult(Name, CheckStatus.Bilinmiyor,
                    "Kayıtlı Wi-Fi ağı bulunamadı (bilgisayarda Wi-Fi olmayabilir).", "", Weight);

            var open = new List<string>();
            var wep = new List<string>();
            var weak = new List<string>();

            foreach (var file in files)
            {
                XDocument doc;
                try { doc = XDocument.Load(file); }
                catch { continue; }

                string Get(string tag) =>
                    doc.Descendants().FirstOrDefault(e => e.Name.LocalName == tag)?.Value ?? "";

                string name = Get("name");
                string auth = Get("authentication").ToLowerInvariant();
                string enc = Get("encryption").ToLowerInvariant();

                if (enc == "wep" || auth == "shared") wep.Add(name);
                else if (auth == "open" && enc == "none") open.Add(name);
                else if (auth == "wpapsk" || auth == "wpa" || enc == "tkip") weak.Add(name);
            }

            if (open.Count > 0 || wep.Count > 0)
            {
                var bad = open.Concat(wep).ToList();
                return new CheckResult(Name, CheckStatus.Basarisiz,
                    $"Güvensiz kayıtlı ağlar (şifresiz veya WEP): {Join(bad)}",
                    "Ayarlar > Ağ ve İnternet > Wi-Fi > Bilinen ağları yönet > ilgili ağı 'Unut'. Kendi modemin ise güvenliğini WPA2 veya WPA3 yap.", Weight);
            }

            if (weak.Count > 0)
                return new CheckResult(Name, CheckStatus.Uyari,
                    $"Eski şifreleme (WPA/TKIP) kullanan ağlar: {Join(weak)}",
                    "Kendi modemin ise yönetim panelinden Wi-Fi güvenliğini WPA2-AES veya WPA3 yap.", Weight);

            return new CheckResult(Name, CheckStatus.Basarili,
                $"{files.Length} kayıtlı ağın tamamı modern şifreleme kullanıyor.", "", Weight);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    private static string Join(List<string> names)
    {
        var shown = names.Take(5).ToList();
        string text = string.Join(", ", shown);
        if (names.Count > shown.Count) text += $" (+{names.Count - shown.Count} ağ daha)";
        return text;
    }
}