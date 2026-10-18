using System.Runtime.Versioning;

namespace PortScanner.Core;

public enum CheckStatus { Basarili, Uyari, Basarisiz, Bilinmiyor }

public record CheckResult(string Name, CheckStatus Status, string Message, string Advice, int Weight)
{
    public string StatusText => Status switch
    {
        CheckStatus.Basarili => "✔ İyi",
        CheckStatus.Uyari => "⚠ Dikkat",
        CheckStatus.Basarisiz => "✖ Sorun",
        _ => "? Bilinmiyor"
    };
}

public interface ISecurityCheck
{
    string Name { get; }
    Task<CheckResult> RunAsync(CancellationToken ct);
}

[SupportedOSPlatform("windows")]
public static class SecurityAudit
{
    public static List<ISecurityCheck> AllChecks() => new()
{
    new FirewallCheck(),
    new DefenderCheck(),
    new UacCheck(),
    new RdpCheck(),
    new WindowsUpdateCheck(),
    new Smb1Check(),
    new GuestAccountCheck(),
    new AutoLoginCheck(),
    new SharedFoldersCheck(),
    new WifiCheck(),
};

    public static async Task<int> RunAsync(
        Action<CheckResult> onResult,
        IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
        var checks = AllChecks();
        var results = new List<CheckResult>();

        for (int i = 0; i < checks.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            CheckResult r;
            try
            {
                r = await checks[i].RunAsync(ct);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                r = new CheckResult(checks[i].Name, CheckStatus.Bilinmiyor,
                    "Kontrol edilemedi: " + ex.Message, "", 0);
            }

            results.Add(r);
            onResult(r);
            progress?.Report((i + 1) * 100 / checks.Count);
        }

        return CalculateScore(results);
    }

    // Bilinmeyen sonuçlar puana dahil edilmez, "Dikkat" yarım puan sayılır
    public static int CalculateScore(IEnumerable<CheckResult> results)
    {
        var rated = results.Where(r => r.Status != CheckStatus.Bilinmiyor && r.Weight > 0).ToList();
        int total = rated.Sum(r => r.Weight);
        if (total == 0) return 0;

        double earned = rated.Sum(r => r.Status switch
        {
            CheckStatus.Basarili => (double)r.Weight,
            CheckStatus.Uyari => r.Weight / 2.0,
            _ => 0.0
        });

        return (int)Math.Round(earned * 100 / total);
    }
}