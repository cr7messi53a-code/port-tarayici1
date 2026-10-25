using System.Runtime.Versioning;
using System.Xml.Linq;

namespace PortScanner.Core;

[SupportedOSPlatform("windows")]
public class WifiCheck : ISecurityCheck
{
    public string Name => L.T("Kayıtlı Wi-Fi ağları", "Saved Wi-Fi networks");
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
                    L.T("Kayıtlı Wi-Fi ağı bulunamadı (bilgisayarda Wi-Fi olmayabilir).",
                        "No saved Wi-Fi network found (this computer may not have Wi-Fi)."), "", Weight);

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
                    L.T($"Şifresiz veya eski (WEP) kayıtlı ağlar: {Join(bad)}. Bu ağlarda trafiğin başkaları tarafından görülebilir.",
                        $"Saved networks with no password or old WEP: {Join(bad)}. Others may be able to see your traffic on these networks."),
                    L.T("Halka açık ağları (kafe, otel, belediye vb.) işin bitince 'Unut' ya da otomatik bağlanmayı kapat: Ayarlar > Ağ ve İnternet > Wi-Fi > Bilinen ağları yönet. Bağlanman gerekirse VPN kullan. Kendi modemin ise güvenliğini WPA2 veya WPA3 yap.",
                        "When you are done with public networks (cafe, hotel, municipality, etc.), 'Forget' them or turn off auto-connect: Settings > Network & internet > Wi-Fi > Manage known networks. Use a VPN if you must connect. If it is your own router, set its security to WPA2 or WPA3."),
                    Weight);
            }

            if (weak.Count > 0)
            {
                return new CheckResult(Name, CheckStatus.Uyari,
                    L.T($"Eski şifreleme (WPA/TKIP) kullanan ağlar: {Join(weak)}",
                        $"Networks using old encryption (WPA/TKIP): {Join(weak)}"),
                    L.T("Kendi modemin ise yönetim panelinden Wi-Fi güvenliğini WPA2-AES veya WPA3 yap.",
                        "If it is your own router, set the Wi-Fi security to WPA2-AES or WPA3 in its admin panel."), Weight);
            }

            return new CheckResult(Name, CheckStatus.Basarili,
                L.T($"{files.Length} kayıtlı ağın tamamı modern şifreleme kullanıyor.",
                    $"All {files.Length} saved networks use modern encryption."), "", Weight);
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
        if (names.Count > shown.Count)
            text += L.T($" (+{names.Count - shown.Count} ağ daha)", $" (+{names.Count - shown.Count} more)");
        return text;
    }
}