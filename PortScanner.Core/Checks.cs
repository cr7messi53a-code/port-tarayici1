using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace PortScanner.Core;

[SupportedOSPlatform("windows")]
public class FirewallCheck : ISecurityCheck
{
    public string Name => L.T("Güvenlik duvarı", "Firewall");
    private const int Weight = 30;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        var profiles = new (string Key, string Label)[]
        {
            ("DomainProfile", L.T("Etki alanı", "Domain")),
            ("StandardProfile", L.T("Özel ağ", "Private network")),
            ("PublicProfile", L.T("Genel ağ", "Public network")),
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
                L.T("Güvenlik duvarı tüm ağ türlerinde açık.",
                    "The firewall is on for all network types."), "", Weight)
            : new CheckResult(Name, CheckStatus.Basarisiz,
                L.T("Şu profillerde kapalı: ", "Turned off for: ") + string.Join(", ", off),
                L.T("Windows Güvenliği > Güvenlik duvarı ve ağ koruması bölümünden aç.",
                    "Turn it on in Windows Security > Firewall & network protection."), Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class UacCheck : ISecurityCheck
{
    public string Name => L.T("Kullanıcı Hesabı Denetimi (UAC)", "User Account Control (UAC)");
    private const int Weight = 20;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
        bool enabled = k?.GetValue("EnableLUA") is not int v || v != 0;

        var result = enabled
            ? new CheckResult(Name, CheckStatus.Basarili,
                L.T("UAC açık. Programlar izinsiz yönetici yetkisi alamaz.",
                    "UAC is on. Programs cannot get administrator rights without permission."), "", Weight)
            : new CheckResult(Name, CheckStatus.Basarisiz,
                L.T("UAC kapalı. Zararlı bir program sessizce yönetici yetkisi alabilir.",
                    "UAC is off. A malicious program could silently gain administrator rights."),
                L.T("Başlat'a 'UAC' yaz > 'Kullanıcı Hesabı Denetimi ayarlarını değiştir' > sürgüyü yukarı çek.",
                    "Type 'UAC' in Start > 'Change User Account Control settings' > move the slider up."), Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class RdpCheck : ISecurityCheck
{
    public string Name => L.T("Uzak Masaüstü (RDP)", "Remote Desktop (RDP)");
    private const int Weight = 20;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Terminal Server");
        bool denied = k?.GetValue("fDenyTSConnections") is not int v || v != 0;

        var result = denied
            ? new CheckResult(Name, CheckStatus.Basarili,
                L.T("Uzak Masaüstü kapalı. Dışarıdan bağlanılamaz.",
                    "Remote Desktop is off. Nobody can connect from outside."), "", Weight)
            : new CheckResult(Name, CheckStatus.Uyari,
                L.T("Uzak Masaüstü açık. Saldırganların en çok denediği kapılardan biri.",
                    "Remote Desktop is on. It is one of the doors attackers try most often."),
                L.T("Kullanmıyorsan Ayarlar > Sistem > Uzak Masaüstü bölümünden kapat.",
                    "If you don't use it, turn it off in Settings > System > Remote Desktop."), Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class DefenderCheck : ISecurityCheck
{
    public string Name => L.T("Virüs koruması (Windows Defender)", "Virus protection (Windows Defender)");
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
                L.T("Defender bilgisi okunamadı. Başka bir antivirüs kullanıyor olabilirsin.",
                    "Could not read Defender status. You may be using another antivirus."),
                L.T("Kullandığın antivirüsün açık ve güncel olduğundan emin ol.",
                    "Make sure your antivirus is on and up to date."), Weight);
        }

        if (!realTime)
            return new CheckResult(Name, CheckStatus.Basarisiz,
                L.T("Gerçek zamanlı koruma kapalı.", "Real-time protection is off."),
                L.T("Windows Güvenliği > Virüs ve tehdit koruması > Gerçek zamanlı korumayı aç.",
                    "Turn it on in Windows Security > Virus & threat protection > Real-time protection."), Weight);

        if (ageDays > 7)
            return new CheckResult(Name, CheckStatus.Uyari,
                L.T($"Koruma açık ama virüs tanımları {ageDays} gün önce güncellenmiş.",
                    $"Protection is on but virus definitions were updated {ageDays} days ago."),
                L.T("Windows Güncelleştirme'den güncellemeleri kontrol et.",
                    "Check for updates in Windows Update."), Weight);

        return new CheckResult(Name, CheckStatus.Basarili,
            L.T("Gerçek zamanlı koruma açık, tanımlar güncel.",
                "Real-time protection is on and definitions are up to date."), "", Weight);
    }
}

[SupportedOSPlatform("windows")]
public class WindowsUpdateCheck : ISecurityCheck
{
    public string Name => L.T("Windows güncellemeleri", "Windows updates");
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

        string checkAdvice = L.T("Ayarlar > Windows Update > Güncellemeleri denetle.",
                                 "Settings > Windows Update > Check for updates.");

        if (!DateTime.TryParseExact(output, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var last))
        {
            return new CheckResult(Name, CheckStatus.Bilinmiyor,
                L.T("Son güncelleme tarihi okunamadı.", "Could not read the last update date."),
                checkAdvice, Weight);
        }

        int days = (int)(DateTime.Now - last).TotalDays;

        if (days <= 45)
            return new CheckResult(Name, CheckStatus.Basarili,
                L.T($"Son güvenlik güncellemesi {days} gün önce yüklenmiş.",
                    $"The last security update was installed {days} days ago."), "", Weight);

        if (days <= 90)
            return new CheckResult(Name, CheckStatus.Uyari,
                L.T($"Son güncelleme {days} gün önce yüklenmiş.",
                    $"The last update was installed {days} days ago."),
                checkAdvice, Weight);

        return new CheckResult(Name, CheckStatus.Basarisiz,
            L.T($"Son güncelleme {days} gün önce yüklenmiş. Bilinen açıklar kapatılmamış olabilir.",
                $"The last update was installed {days} days ago. Known vulnerabilities may be unpatched."),
            L.T("Ayarlar > Windows Update > Güncellemeleri denetle ve hepsini yükle.",
                "Settings > Windows Update > Check for updates and install them all."), Weight);
    }
}

[SupportedOSPlatform("windows")]
public class Smb1Check : ISecurityCheck
{
    public string Name => L.T("Eski dosya paylaşım protokolü (SMBv1)", "Legacy file sharing protocol (SMBv1)");
    private const int Weight = 15;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
        bool enabled = k?.GetValue("SMB1") is int v && v == 1;

        var result = enabled
            ? new CheckResult(Name, CheckStatus.Basarisiz,
                L.T("SMBv1 açık. Fidye yazılımlarının (WannaCry gibi) kullandığı eski bir protokol.",
                    "SMBv1 is on. It is an old protocol used by ransomware such as WannaCry."),
                L.T("Başlat'a 'Windows özelliklerini aç veya kapat' yaz > 'SMB 1.0/CIFS' kutusunun işaretini kaldır.",
                    "Type 'Turn Windows features on or off' in Start > uncheck 'SMB 1.0/CIFS File Sharing Support'."), Weight)
            : new CheckResult(Name, CheckStatus.Basarili,
                L.T("SMBv1 açık olarak ayarlanmamış.", "SMBv1 is not enabled."), "", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class GuestAccountCheck : ISecurityCheck
{
    public string Name => L.T("Konuk (Guest) hesabı", "Guest account");
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
                L.T("Konuk hesabı durumu okunamadı.", "Could not read the guest account status."), "", Weight);

        return enabled
            ? new CheckResult(Name, CheckStatus.Basarisiz,
                L.T("Konuk hesabı açık. Parolasız giriş kapısı olabilir.",
                    "The guest account is on. It can be a password-free way in."),
                L.T("Yönetici PowerShell'de: net user guest /active:no",
                    "In an administrator PowerShell: net user guest /active:no"), Weight)
            : new CheckResult(Name, CheckStatus.Basarili,
                L.T("Konuk hesabı kapalı.", "The guest account is off."), "", Weight);
    }
}

[SupportedOSPlatform("windows")]
public class AutoLoginCheck : ISecurityCheck
{
    public string Name => L.T("Otomatik oturum açma", "Automatic sign-in");
    private const int Weight = 10;

    public Task<CheckResult> RunAsync(CancellationToken ct)
    {
        using var k = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
        bool auto = k?.GetValue("AutoAdminLogon")?.ToString() == "1";

        var result = auto
            ? new CheckResult(Name, CheckStatus.Uyari,
                L.T("Bilgisayar parola sormadan otomatik açılıyor. Cihaza erişen herkes içeri girer.",
                    "The computer signs in automatically without a password. Anyone with access to the device gets in."),
                L.T("Başlat'a 'netplwiz' yaz > 'Kullanıcıların bu bilgisayarı kullanmak için ... girmesi gerekir' kutusunu işaretle.",
                    "Type 'netplwiz' in Start > check 'Users must enter a user name and password to use this computer'."), Weight)
            : new CheckResult(Name, CheckStatus.Basarili,
                L.T("Otomatik oturum açma kapalı.", "Automatic sign-in is off."), "", Weight);

        return Task.FromResult(result);
    }
}

[SupportedOSPlatform("windows")]
public class SharedFoldersCheck : ISecurityCheck
{
    public string Name => L.T("Paylaşılan klasörler", "Shared folders");
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
                L.T("Paylaşımlar okunamadı.", "Could not read the shares."), "", Weight);

        string names = output[3..].Trim();

        return names.Length == 0
            ? new CheckResult(Name, CheckStatus.Basarili,
                L.T("Ağda paylaşılan klasör yok.", "No folders are shared on the network."), "", Weight)
            : new CheckResult(Name, CheckStatus.Uyari,
                L.T($"Ağa açık klasörler: {names}", $"Folders shared on the network: {names}"),
                L.T("Paylaşımın gerekli değilse klasöre sağ tıkla > Özellikler > Paylaşım > Gelişmiş paylaşım > işareti kaldır.",
                    "If you don't need sharing, right-click the folder > Properties > Sharing > Advanced Sharing > uncheck it."), Weight);
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

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell could not be started.");
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