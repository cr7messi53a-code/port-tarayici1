using System.Net.Sockets;

namespace PortScanner.Core;

public enum RiskLevel { Bilinmiyor, Dusuk, Orta, Yuksek }

public record PortResult(int Port, string Service, string Note, RiskLevel Risk, string Banner = "")
{
    public string RiskText => Risk switch
    {
        RiskLevel.Yuksek => L.T("Yüksek", "High"),
        RiskLevel.Orta => L.T("Orta", "Medium"),
        RiskLevel.Dusuk => L.T("Düşük", "Low"),
        _ => L.T("Bilinmiyor", "Unknown")
    };
}

public static class TcpPortScanner
{
    // Bu portlarda banner okumanın anlamı yok (ikili protokol ya da şifreli)
    private static readonly HashSet<int> NoBannerPorts = new() { 135, 139, 445, 3389, 443, 8443 };

    private static (string Service, RiskLevel Risk, string Note)? GetKnown(int port) => port switch
    {
        21 => ("FTP", RiskLevel.Yuksek, L.T(
            "Şifresiz dosya aktarımı. Kullanmıyorsan kapat, kullanıyorsan SFTP'ye geç.",
            "Unencrypted file transfer. Turn it off if unused, or switch to SFTP.")),
        22 => ("SSH", RiskLevel.Orta, L.T(
            "Uzaktan terminal erişimi. Güçlü parola veya anahtar kullan.",
            "Remote terminal access. Use a strong password or key.")),
        23 => ("Telnet", RiskLevel.Yuksek, L.T(
            "Şifresiz ve eski bir protokol. Kapat, SSH kullan.",
            "Old and unencrypted protocol. Turn it off and use SSH.")),
        25 => ("SMTP", RiskLevel.Orta, L.T(
            "Mail sunucusu. Bilerek kurmadıysan kapat.",
            "Mail server. Turn it off if you did not set it up on purpose.")),
        53 => ("DNS", RiskLevel.Orta, L.T(
            "Alan adı sunucusu. Modem/router'larda normaldir.",
            "Domain name server. Normal on modems/routers.")),
        80 => ("HTTP", RiskLevel.Dusuk, L.T(
            "Web sunucusu. Trafik şifrelenmemiş, hassas veri taşımamalı.",
            "Web server. Traffic is not encrypted, so it should not carry sensitive data.")),
        110 => ("POP3", RiskLevel.Orta, L.T(
            "Eski mail protokolü, şifresiz olabilir.",
            "Old mail protocol, may be unencrypted.")),
        135 => ("RPC", RiskLevel.Orta, L.T(
            "Windows servisi. Ağ içinde normal, internete açık olmamalı.",
            "Windows service. Normal on a local network, but should not be exposed to the internet.")),
        139 => ("NetBIOS", RiskLevel.Orta, L.T(
            "Eski Windows dosya paylaşımı. İnternete açık olmamalı.",
            "Old Windows file sharing. Should not be exposed to the internet.")),
        143 => ("IMAP", RiskLevel.Orta, L.T(
            "Mail protokolü, şifresiz olabilir.",
            "Mail protocol, may be unencrypted.")),
        443 => ("HTTPS", RiskLevel.Dusuk, L.T(
            "Şifreli web sunucusu. Genelde sorun değil.",
            "Encrypted web server. Usually not a problem.")),
        445 => ("SMB", RiskLevel.Orta, L.T(
            "Windows dosya paylaşımı. Ağ içinde normal, internete açık olursa çok tehlikeli (fidye yazılımları).",
            "Windows file sharing. Normal on a local network, very dangerous if exposed to the internet (ransomware).")),
        1433 => ("SQL Server", RiskLevel.Yuksek, L.T(
            "Veritabanı. Dışarıdan erişilmemeli.",
            "Database. Should not be reachable from outside.")),
        3306 => ("MySQL", RiskLevel.Yuksek, L.T(
            "Veritabanı. Dışarıdan erişilmemeli.",
            "Database. Should not be reachable from outside.")),
        3389 => ("RDP", RiskLevel.Yuksek, L.T(
            "Uzak masaüstü. Çok saldırı alır, kullanmıyorsan kapat.",
            "Remote desktop. Attacked very often, turn it off if you don't use it.")),
        5432 => ("PostgreSQL", RiskLevel.Yuksek, L.T(
            "Veritabanı. Dışarıdan erişilmemeli.",
            "Database. Should not be reachable from outside.")),
        5900 => ("VNC", RiskLevel.Yuksek, L.T(
            "Uzak ekran paylaşımı. Zayıf korunur, kapat veya VPN arkasına al.",
            "Remote screen sharing. Weakly protected, turn it off or put it behind a VPN.")),
        6379 => ("Redis", RiskLevel.Yuksek, L.T(
            "Genelde parolasız çalışır. Dışarıdan erişilmemeli.",
            "Often runs without a password. Should not be reachable from outside.")),
        8080 => ("HTTP-Alt", RiskLevel.Dusuk, L.T(
            "Alternatif web sunucusu. Ne çalıştığını kontrol et.",
            "Alternative web server. Check what is running there.")),
        8443 => ("HTTPS-Alt", RiskLevel.Dusuk, L.T(
            "Alternatif şifreli web sunucusu.",
            "Alternative encrypted web server.")),
        27017 => ("MongoDB", RiskLevel.Yuksek, L.T(
            "Veritabanı. Dışarıdan erişilmemeli.",
            "Database. Should not be reachable from outside.")),
        _ => null
    };

    public static async Task ScanAsync(
        string host, int startPort, int endPort,
        Action<PortResult> onOpen,
        IProgress<int>? progress = null,
        int timeoutMs = 500, int maxParallel = 200,
        CancellationToken ct = default)
    {
        var gate = new SemaphoreSlim(maxParallel);
        var tasks = new List<Task>();
        int done = 0;
        int total = endPort - startPort + 1;

        for (int port = startPort; port <= endPort; port++)
        {
            await gate.WaitAsync(ct);
            int p = port;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (await IsOpenAsync(host, p, timeoutMs, ct))
                    {
                        var known = GetKnown(p);
                        bool isKnown = known != null;

                        var result = known is { } k
                            ? new PortResult(p, k.Service, k.Note, k.Risk)
                            : new PortResult(p, L.T("Bilinmiyor", "Unknown"),
                                L.T("Tanınmayan servis. Sen açmadıysan hangi program olduğunu araştır.",
                                    "Unrecognized service. If you did not start it, find out which program it is."),
                                RiskLevel.Bilinmiyor);

                        if (!NoBannerPorts.Contains(p))
                        {
                            string banner = await BannerGrabber.GrabAsync(host, p, 1500, ct);
                            if (banner.Length > 0)
                            {
                                result = result with { Banner = banner };

                                if (!isKnown)
                                {
                                    var id = VersionAdvisor.Identify(banner);
                                    if (id != null)
                                        result = result with
                                        {
                                            Service = id,
                                            Note = L.T("Servis, verdiği yanıttan tanındı.",
                                                       "Service recognized from its response.")
                                        };
                                }

                                var warning = VersionAdvisor.Warn(banner);
                                if (warning != null)
                                    result = result with
                                    {
                                        Risk = RiskLevel.Yuksek,
                                        Note = warning + " " + result.Note
                                    };
                            }
                        }

                        onOpen(result);
                    }
                }
                catch (OperationCanceledException) { }
                finally
                {
                    gate.Release();
                    int d = Interlocked.Increment(ref done);
                    progress?.Report(d * 100 / total);
                }
            }, ct));
        }

        await Task.WhenAll(tasks);
        ct.ThrowIfCancellationRequested();
    }

    private static async Task<bool> IsOpenAsync(
        string host, int port, int timeoutMs, CancellationToken ct)
    {
        using var client = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await client.ConnectAsync(host, port, cts.Token);
            return true;
        }
        catch { return false; }
    }
}