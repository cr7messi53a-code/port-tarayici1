using System.Text.RegularExpressions;

namespace PortScanner.Core;

public static class VersionAdvisor
{
    // Banner'dan servis adını tahmin eder, tanıyamazsa null döner
    public static string? Identify(string banner)
    {
        string b = banner.ToLowerInvariant();

        if (b.StartsWith("ssh-")) return "SSH";
        if (b.Contains("ftp")) return "FTP";
        if (b.Contains("smtp")) return "SMTP";
        if (b.StartsWith("http/") || b.Contains("nginx") || b.Contains("apache")
            || b.Contains("microsoft-iis") || b.Contains("lighttpd")
            || b.Contains("simplehttp") || b.Contains("caddy"))
            return "HTTP";

        return null;
    }

    // Bilinen eski/tehlikeli sürümleri yakalar, sorun yoksa null döner
    public static string? Warn(string banner)
    {
        var ssh = Regex.Match(banner, @"OpenSSH[_-](\d+)\.(\d+)", RegexOptions.IgnoreCase);
        if (ssh.Success && int.Parse(ssh.Groups[1].Value) < 8)
            return L.T(
                $"OpenSSH {ssh.Groups[1].Value}.{ssh.Groups[2].Value} eski bir sürüm, bilinen açıkları olabilir.",
                $"OpenSSH {ssh.Groups[1].Value}.{ssh.Groups[2].Value} is an old version and may have known vulnerabilities.");

        var apache = Regex.Match(banner, @"Apache/(\d+)\.(\d+)", RegexOptions.IgnoreCase);
        if (apache.Success)
        {
            int maj = int.Parse(apache.Groups[1].Value);
            int min = int.Parse(apache.Groups[2].Value);
            if (maj < 2 || (maj == 2 && min < 4))
                return L.T(
                    $"Apache {maj}.{min} desteği bitmiş eski bir sürüm.",
                    $"Apache {maj}.{min} is an old version that is no longer supported.");
        }

        var iis = Regex.Match(banner, @"Microsoft-IIS/(\d+)\.(\d+)", RegexOptions.IgnoreCase);
        if (iis.Success && int.Parse(iis.Groups[1].Value) < 10)
            return L.T(
                $"IIS {iis.Groups[1].Value}.{iis.Groups[2].Value} eski bir sürüm, desteği bitmiş olabilir.",
                $"IIS {iis.Groups[1].Value}.{iis.Groups[2].Value} is an old version and may no longer be supported.");

        if (banner.Contains("vsftpd 2.3.4", StringComparison.OrdinalIgnoreCase))
            return L.T(
                "vsftpd 2.3.4 sürümünde bilinen bir arka kapı var!",
                "vsftpd 2.3.4 has a known backdoor!");

        return null;
    }
}