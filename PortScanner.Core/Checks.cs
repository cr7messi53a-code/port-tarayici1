using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace PortScanner.Core;

[SupportedOSPlatform("windows")]
public class FirewallCheck : ISecurityCheck
{
    public string Name => "Güvenlik duvarı";
    private const int Weight = 30;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        var profiles = new (string Key, string Label)[]
        {
            ("DomainProfile", "Etki alanı"),
            ("StandardProfile", "Özel ağ"),
            ("PublicProfile", "Genel ağ"),
        };

        var off = new List<string>();
        foreach (var (key, label) in profiles)
        {
            using var k = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{key}");
            // Değer yoksa Windows varsayılanı "açık"tır
            if (k?.GetValue("EnableFirewall") is int v && v == 0)
                off.Add(label);
        }

        var result = off.Count == 0
            ? new CheckResult(Name, CheckStatus.Basarili,
                "Güvenlik duvarı tüm ağ türlerinde açık.", "", Weight)
            : new CheckResult(Name, CheckStatus.Basarisiz,
                "Şu profillerde kapalı: " + string.Join(", ", off),
                "Windows Güvenliği > Güvenlik duvarı ve ağ koruması bölümünden aç.", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class UacCheck : ISecurityCheck
{
    public string Name => "Kullanıcı Hesabı Denetimi (UAC)";
    private const int Weight = 20;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
        bool enabled = k?.GetValue("EnableLUA") is not int v || v != 0;

        var result = enabled
            ? new CheckResult(Name, CheckStatus.Basarili,
                "UAC açık. Programlar izinsiz yönetici yetkisi alamaz.", "", Weight)
            : new CheckResult(Name, CheckStatus.Basarisiz,
                "UAC kapalı. Zararlı bir program sessizce yönetici yetkisi alabilir.",
                "Başlat'a 'UAC' yaz > 'Kullanıcı Hesabı Denetimi ayarlarını değiştir' > sürgüyü yukarı çek.", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class RdpCheck : ISecurityCheck
{
    public string Name => "Uzak Masaüstü (RDP)";
    private const int Weight = 20;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Terminal Server");
        bool denied = k?.GetValue("fDenyTSConnections") is not int v || v != 0;

        var result = denied
            ? new CheckResult(Name, CheckStatus.Basarili,
                "Uzak Masaüstü kapalı. Dışarıdan bağlanılamaz.", "", Weight)
            : new CheckResult(Name, CheckStatus.Uyari,
                "Uzak Masaüstü açık. Saldırganların en çok denediği kapılardan biri.",
                "Kullanmıyorsan Ayarlar > Sistem > Uzak Masaüstü bölümünden kapat.", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class DefenderCheck : ISecurityCheck
{
    public string Name => "Virüs koruması (Windows Defender)";
    private const int Weight = 30;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        string output;
        try
        {
            output = await PowerShellRunner.RunAsync(
                "$s = Get-MpComputerStatus; \"$($s.RealTimeProtectionEnabled)|$($s.AntivirusSignatureAge)\"", ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { output = ""; }

        var parts = output.Split('|');
        if (parts.Length != 2
            || !bool.TryParse(parts[0], out bool realTime)
            || !int.TryParse(parts[1], out int ageDays))
        {
            return new CheckResult(Name, CheckStatus.Bilinmiyor,
                "Defender bilgisi okunamadı. Başka bir antivirüs kullanıyor olabilirsin.",
                "Kullandığın antivirüsün açık ve güncel olduğundan emin ol.", Weight);
        }

        if (!realTime)
            return new CheckResult(Name, CheckStatus.Basarisiz,
                "Gerçek zamanlı koruma kapalı.",
                "Windows Güvenliği > Virüs ve tehdit koruması > Gerçek zamanlı korumayı aç.", Weight);

        if (ageDays > 7)
            return new CheckResult(Name, CheckStatus.Uyari,
                $"Koruma açık ama virüs tanımları {ageDays} gün önce güncellenmiş.",
                "Windows Güncelleştirme'den güncellemeleri kontrol et.", Weight);

        return new CheckResult(Name, CheckStatus.Basarili,
            "Gerçek zamanlı koruma açık, tanımlar güncel.", "", Weight);
    }
}

[SupportedOSPlatform("windows")]
public class WindowsUpdateCheck : ISecurityCheck
{
    public string Name => "Windows güncellemeleri";
    private const int Weight = 20;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        string output;
        try
        {
            output = await PowerShellRunner.RunAsync(
                "$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { $h.InstalledOn.ToString('yyyy-MM-dd') }", ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { output = ""; }

        if (!DateTime.TryParseExact(output, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var last))
        {
            return new CheckResult(Name, CheckStatus.Bilinmiyor,
                "Son güncelleme tarihi okunamadı.",
                "Ayarlar > Windows Update bölümünden güncellemeleri kontrol et.", Weight);
        }

        int days = (int)(DateTime.Now - last).TotalDays;

        if (days <= 45)
            return new CheckResult(Name, CheckStatus.Basarili,
                $"Son güvenlik güncellemesi {days} gün önce yüklenmiş.", "", Weight);

        if (days <= 90)
            return new CheckResult(Name, CheckStatus.Uyari,
                $"Son güncelleme {days} gün önce yüklenmiş.",
                "Ayarlar > Windows Update > Güncellemeleri denetle.", Weight);

        return new CheckResult(Name, CheckStatus.Basarisiz,
            $"Son güncelleme {days} gün önce yüklenmiş. Bilinen açıklar kapatılmamış olabilir.",
            "Ayarlar > Windows Update > Güncellemeleri denetle ve hepsini yükle.", Weight);
    }
}

[SupportedOSPlatform("windows")]
public class Smb1Check : ISecurityCheck
{
    public string Name => "Eski dosya paylaşım protokolü (SMBv1)";
    private const int Weight = 15;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
        bool enabled = k?.GetValue("SMB1") is int v && v == 1;

        var result = enabled
            ? new CheckResult(Name, CheckStatus.Basarisiz,
                "SMBv1 açık. Fidye yazılımlarının (WannaCry gibi) kullandığı eski bir protokol.",
                "Başlat'a 'Windows özelliklerini aç veya kapat' yaz > 'SMB 1.0/CIFS' kutusunun işaretini kaldır.", Weight)
            : new CheckResult(Name, CheckStatus.Basarili,
                "SMBv1 açık olarak ayarlanmamış.", "", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class GuestAccountCheck : ISecurityCheck
{
    public string Name => "Konuk (Guest) hesabı";
    private const int Weight = 5;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        string output;
        try
        {
            output = await PowerShellRunner.RunAsync(
                "$g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }; if ($g) { $g.Enabled }", ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { output = ""; }

        if (!bool.TryParse(output, out bool enabled))
            return new CheckResult(Name, CheckStatus.Bilinmiyor,
                "Konuk hesabı durumu okunamadı.", "", Weight);

        return enabled
            ? new CheckResult(Name, CheckStatus.Basarisiz,
                "Konuk hesabı açık. Parolasız giriş kapısı olabilir.",
                "Yönetici PowerShell'de: net user guest /active:no", Weight)
            : new CheckResult(Name, CheckStatus.Basarili,
                "Konuk hesabı kapalı.", "", Weight);
    }
}

[SupportedOSPlatform("windows")]
public class AutoLoginCheck : ISecurityCheck
{
    public string Name => "Otomatik oturum açma";
    private const int Weight = 10;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        bool auto = k?.GetValue("AutoAdminLogon")?.ToString() == "1";

        var result = auto
            ? new CheckResult(Name, CheckStatus.Uyari,
                "Bilgisayar parola sormadan otomatik açılıyor. Cihaza erişen herkes içeri girer.",
                "Başlat'a 'netplwiz' yaz > 'Kullanıcıların bu bilgisayarı kullanmak için ... girmesi gerekir' kutusunu işaretle.", Weight)
            : new CheckResult(Name, CheckStatus.Basarili,
                "Otomatik oturum açma kapalı.", "", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class SharedFoldersCheck : ISecurityCheck
{
    public string Name => "Paylaşılan klasörler";
    private const int Weight = 10;

    public async Task<CheckResult> RunAsync(CancellationToken ct)
    {
        string output;
        try
        {
            output = await PowerShellRunner.RunAsync(
                "$n = Get-CimInstance Win32_Share | Where-Object { $_.Type -eq 0 } | ForEach-Object { $_.Name }; 'OK|' + ($n -join ', ')", ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { output = ""; }

        if (!output.StartsWith("OK|"))
            return new CheckResult(Name, CheckStatus.Bilinmiyor,
                "Paylaşımlar okunamadı.", "", Weight);

        string names = output[3..].Trim();

        return names.Length == 0
            ? new CheckResult(Name, CheckStatus.Basarili,
                "Ağda paylaşılan klasör yok.", "", Weight)
            : new CheckResult(Name, CheckStatus.Uyari,
                $"Ağa açık klasörler: {names}",
                "Paylaşımın gerekli değilse klasöre sağ tıkla > Özellikler > Paylaşım > Gelişmiş paylaşım > işareti kaldır.", Weight);
    }
}

internal static class PowerShellRunner
{
    public static async Task<string> RunAsync(string script, CancellationToken ct)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var psi = new ProcessStartInfo("powershell.exe",
            $"-NoProfile -NonInteractive -EncodedCommand {encoded}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell başlatılamadı.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(15));

        try
        {
            string output = await p.StandardOutput.ReadToEndAsync(cts.Token);
            await p.WaitForExitAsync(cts.Token);
            return output.Trim();
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { }
            throw;
        }
    }
}