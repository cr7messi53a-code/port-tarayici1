using System.Net.Sockets;

namespace PortScanner.Core;

public enum RiskLevel { Bilinmiyor, Dusuk, Orta, Yuksek }

public record PortResult(int Port, string Service, string Note, RiskLevel Risk)
{
    public string RiskText => Risk switch
    {
        RiskLevel.Yuksek => "Yüksek",
        RiskLevel.Orta => "Orta",
        RiskLevel.Dusuk => "Düşük",
        _ => "Bilinmiyor"
    };
}

public static class TcpPortScanner
{
    private static readonly Dictionary<int, (string Service, RiskLevel Risk, string Note)> Known = new()
    {
        [21]    = ("FTP", RiskLevel.Yuksek, "Şifresiz dosya aktarımı. Kullanmıyorsan kapat, kullanıyorsan SFTP'ye geç."),
        [22]    = ("SSH", RiskLevel.Orta, "Uzaktan terminal erişimi. Güçlü parola veya anahtar kullan."),
        [23]    = ("Telnet", RiskLevel.Yuksek, "Şifresiz ve eski bir protokol. Kapat, SSH kullan."),
        [25]    = ("SMTP", RiskLevel.Orta, "Mail sunucusu. Bilerek kurmadıysan kapat."),
        [53]    = ("DNS", RiskLevel.Orta, "Alan adı sunucusu. Modem/router'larda normaldir."),
        [80]    = ("HTTP", RiskLevel.Dusuk, "Web sunucusu. Trafik şifrelenmemiş, hassas veri taşımamalı."),
        [110]   = ("POP3", RiskLevel.Orta, "Eski mail protokolü, şifresiz olabilir."),
        [135]   = ("RPC", RiskLevel.Orta, "Windows servisi. Ağ içinde normal, internete açık olmamalı."),
        [139]   = ("NetBIOS", RiskLevel.Orta, "Eski Windows dosya paylaşımı. İnternete açık olmamalı."),
        [143]   = ("IMAP", RiskLevel.Orta, "Mail protokolü, şifresiz olabilir."),
        [443]   = ("HTTPS", RiskLevel.Dusuk, "Şifreli web sunucusu. Genelde sorun değil."),
        [445]   = ("SMB", RiskLevel.Orta, "Windows dosya paylaşımı. Ağ içinde normal, internete açık olursa çok tehlikeli (fidye yazılımları)."),
        [1433]  = ("SQL Server", RiskLevel.Yuksek, "Veritabanı. Dışarıdan erişilmemeli."),
        [3306]  = ("MySQL", RiskLevel.Yuksek, "Veritabanı. Dışarıdan erişilmemeli."),
        [3389]  = ("RDP", RiskLevel.Yuksek, "Uzak masaüstü. Çok saldırı alır, kullanmıyorsan kapat."),
        [5432]  = ("PostgreSQL", RiskLevel.Yuksek, "Veritabanı. Dışarıdan erişilmemeli."),
        [5900]  = ("VNC", RiskLevel.Yuksek, "Uzak ekran paylaşımı. Zayıf korunur, kapat veya VPN arkasına al."),
        [6379]  = ("Redis", RiskLevel.Yuksek, "Genelde parolasız çalışır. Dışarıdan erişilmemeli."),
        [8080]  = ("HTTP-Alt", RiskLevel.Dusuk, "Alternatif web sunucusu. Ne çalıştığını kontrol et."),
        [8443]  = ("HTTPS-Alt", RiskLevel.Dusuk, "Alternatif şifreli web sunucusu."),
        [27017] = ("MongoDB", RiskLevel.Yuksek, "Veritabanı. Dışarıdan erişilmemeli."),
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
                        var result = Known.TryGetValue(p, out var k)
                            ? new PortResult(p, k.Service, k.Note, k.Risk)
                            : new PortResult(p, "Bilinmiyor",
                                "Tanınmayan servis. Sen açmadıysan hangi program olduğunu araştır.",
                                RiskLevel.Bilinmiyor);
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