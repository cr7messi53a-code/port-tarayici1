using System.Net.Sockets;
using System.Text;

namespace PortScanner.Core;

public static class BannerGrabber
{
    private static readonly HashSet<int> HttpPorts = new() { 80, 8000, 8008, 8080, 8888 };

    public static async Task<string> GrabAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        using var client = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        try
        {
            await client.ConnectAsync(host, port, cts.Token);
            var stream = client.GetStream();

            // Web sunucuları kendiliğinden konuşmaz, küçük bir istek göndeririz
            if (HttpPorts.Contains(port))
            {
                byte[] req = Encoding.ASCII.GetBytes(
                    $"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: PortTarayici\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(req, cts.Token);
            }

            var buffer = new byte[1024];
            int n = await stream.ReadAsync(buffer, cts.Token);
            if (n <= 0) return "";

            return Clean(Encoding.ASCII.GetString(buffer, 0, n));
        }
        catch { return ""; }
    }

    private static string Clean(string raw)
    {
        if (raw.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            var lines = raw.Split('\n').Select(l => l.Trim()).ToList();
            var server = lines.FirstOrDefault(l => l.StartsWith("Server:", StringComparison.OrdinalIgnoreCase));
            return server != null ? server[7..].Trim() : lines[0];
        }

        string first = raw.Split('\n')[0].Trim();
        first = new string(first.Where(c => c >= 32 && c < 127).ToArray());
        return first.Length > 80 ? first[..80] : first;
    }
}