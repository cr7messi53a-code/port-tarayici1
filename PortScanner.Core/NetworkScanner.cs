using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace PortScanner.Core;

public record DeviceResult(string Ip, string HostName, string Info);

public static class NetworkScanner
{
    private static readonly int[] ProbePorts = { 80, 443, 445, 139, 22, 3389, 8080 };

    // Bilgisayarın bağlı olduğu yerel ağı bulur, örn. "192.168.1.0/24"
    public static string? GetLocalCidr()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback
                or NetworkInterfaceType.Tunnel) continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (ua.IPv4Mask == null) continue;

                var ipBytes = ua.Address.GetAddressBytes();
                if (ipBytes[0] == 169 && ipBytes[1] == 254) continue; // link-local

                int prefix = 0;
                foreach (var b in ua.IPv4Mask.GetAddressBytes())
                    prefix += System.Numerics.BitOperations.PopCount(b);

                if (prefix < 24) prefix = 24; // çok büyük ağlarda tarama uzamasın

                uint net = IpToNumber(ua.Address) & (uint.MaxValue << (32 - prefix));
                return $"{NumberToIp(net)}/{prefix}";
            }
        }
        return null;
    }

    public static async Task ScanAsync(
        string cidr, Action<DeviceResult> onFound,
        IProgress<int>? progress = null,
        int timeoutMs = 800, int maxParallel = 100,
        CancellationToken ct = default)
    {
        var hosts = ExpandCidr(cidr);
        var gate = new SemaphoreSlim(maxParallel);
        var tasks = new List<Task>();
        int done = 0;

        foreach (var ip in hosts)
        {
            await gate.WaitAsync(ct);
            var target = ip;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    string? info = await ProbeAsync(target, timeoutMs, ct);
                    if (info != null)
                    {
                        string name = await ResolveNameAsync(target);
                        onFound(new DeviceResult(target.ToString(), name, info));
                    }
                }
                catch (OperationCanceledException) { }
                catch { }
                finally
                {
                    gate.Release();
                    int d = Interlocked.Increment(ref done);
                    progress?.Report(d * 100 / hosts.Count);
                }
            }, ct));
        }

        await Task.WhenAll(tasks);
        ct.ThrowIfCancellationRequested();
    }

    // Önce ping dener, ping engelliyse yaygın portlara TCP bağlantısı dener
    private static async Task<string?> ProbeAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(ip, timeoutMs);
            if (reply.Status == IPStatus.Success)
                return $"Ping {reply.RoundtripTime} ms";
        }
        catch { }

        var checks = ProbePorts.Select(p => TcpAliveAsync(ip, p, 400, ct)).ToList();
        bool[] results = await Task.WhenAll(checks);
return results.Any(r => r) ? L.T("TCP yanıtı", "TCP response") : null;    }

    private static async Task<bool> TcpAliveAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        using var client = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await client.ConnectAsync(ip, port, cts.Token);
            return true;
        }
        catch (SocketException se) when (se.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return true; // port kapalı ama cihaz cevap verdi, yani canlı
        }
        catch { return false; }
    }

    private static async Task<string> ResolveNameAsync(IPAddress ip)
    {
        try
        {
            var lookup = Dns.GetHostEntryAsync(ip);
            if (await Task.WhenAny(lookup, Task.Delay(1000)) == lookup)
                return (await lookup).HostName;
        }
        catch { }
        return "-";
    }

    public static List<IPAddress> ExpandCidr(string cidr)
    {
        var parts = cidr.Trim().Split('/');
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0], out var ip)
            || ip.AddressFamily != AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out int prefix)
            || prefix < 20 || prefix > 30)
throw new FormatException(L.T(
    "Geçersiz ağ. Örnek: 192.168.1.0/24 (önek 20-30 arası)",
    "Invalid network. Example: 192.168.1.0/24 (prefix between 20 and 30)"));
        uint mask = uint.MaxValue << (32 - prefix);
        uint network = IpToNumber(ip) & mask;
        uint broadcast = network | ~mask;

        var list = new List<IPAddress>();
        for (uint a = network + 1; a < broadcast; a++)
            list.Add(new IPAddress(new[]
            {
                (byte)(a >> 24), (byte)(a >> 16), (byte)(a >> 8), (byte)a
            }));
        return list;
    }

    public static uint IpToNumber(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
    }

    public static uint IpToNumber(string ip) => IpToNumber(IPAddress.Parse(ip));

    private static string NumberToIp(uint a) =>
        $"{a >> 24}.{(a >> 16) & 255}.{(a >> 8) & 255}.{a & 255}";
}