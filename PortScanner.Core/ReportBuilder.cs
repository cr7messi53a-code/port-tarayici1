using System.Net;
using System.Text;

namespace PortScanner.Core;

public static class ReportBuilder
{
    public static string BuildHtml(
        IEnumerable<DeviceResult> devices, string target,
        IEnumerable<PortResult> ports,
        IEnumerable<CheckResult> checks, int? score)
    {
        var devs = devices.ToList();
        var prts = ports.ToList();
        var chks = checks.ToList();
        var sb = new StringBuilder();
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"tr\"><head><meta charset=\"utf-8\">");
        sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.AppendLine("<title>Güvenlik Raporu</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:'Segoe UI',Arial,sans-serif;max-width:980px;margin:32px auto;padding:0 16px;color:#111;line-height:1.45}");
        sb.AppendLine("h1{margin-bottom:4px}");
        sb.AppendLine("h2{margin-top:32px;border-bottom:2px solid #e5e7eb;padding-bottom:6px}");
        sb.AppendLine(".muted{color:#6b7280;font-size:14px}");
        sb.AppendLine("table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}");
        sb.AppendLine("th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}");
        sb.AppendLine("th{background:#f3f4f6}");
        sb.AppendLine(".badge{color:#fff;font-weight:600;padding:2px 8px;border-radius:4px;white-space:nowrap}");
        sb.AppendLine(".g{background:#16a34a}.o{background:#d97706}.r{background:#dc2626}.n{background:#6b7280}");
        sb.AppendLine(".score{font-size:56px;font-weight:700;margin:8px 0}");
        sb.AppendLine(".gt{color:#16a34a}.ot{color:#d97706}.rt{color:#dc2626}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>Güvenlik Raporu</h1>");
        sb.AppendLine($"<p class=\"muted\">Oluşturulma: {DateTime.Now:dd.MM.yyyy HH:mm} · Port Tarayıcı</p>");

        if (chks.Count > 0)
        {
            sb.AppendLine("<h2>Bilgisayar Kontrolü</h2>");
            if (score.HasValue)
            {
                string scoreCls = score.Value >= 80 ? "gt" : score.Value >= 50 ? "ot" : "rt";
                sb.AppendLine($"<div class=\"score {scoreCls}\">{score.Value} <span class=\"muted\">/ 100</span></div>");
            }
            sb.AppendLine("<table><tr><th>Durum</th><th>Kontrol</th><th>Sonuç</th><th>Ne yapmalı?</th></tr>");
            foreach (var c in chks)
            {
                string cls = c.Status switch
                {
                    CheckStatus.Basarili => "g",
                    CheckStatus.Uyari => "o",
                    CheckStatus.Basarisiz => "r",
                    _ => "n"
                };
                sb.AppendLine($"<tr><td><span class=\"badge {cls}\">{E(c.StatusText)}</span></td>" +
                              $"<td>{E(c.Name)}</td><td>{E(c.Message)}</td><td>{E(c.Advice)}</td></tr>");
            }
            sb.AppendLine("</table>");
        }

        if (devs.Count > 0)
        {
            sb.AppendLine("<h2>Ağdaki Cihazlar</h2>");
            sb.AppendLine("<table><tr><th>IP</th><th>Cihaz adı</th><th>Yanıt</th></tr>");
            foreach (var d in devs)
                sb.AppendLine($"<tr><td>{E(d.Ip)}</td><td>{E(d.HostName)}</td><td>{E(d.Info)}</td></tr>");
            sb.AppendLine("</table>");
        }

        if (prts.Count > 0)
        {
            sb.AppendLine($"<h2>Açık Portlar ({E(target)})</h2>");
            sb.AppendLine("<table><tr><th>Port</th><th>Servis</th><th>Risk</th><th>Sürüm / Banner</th><th>Açıklama</th></tr>");
            foreach (var p in prts)
            {
                string cls = p.Risk switch
                {
                    RiskLevel.Yuksek => "r",
                    RiskLevel.Orta => "o",
                    RiskLevel.Dusuk => "g",
                    _ => "n"
                };
                sb.AppendLine($"<tr><td>{p.Port}</td><td>{E(p.Service)}</td>" +
                              $"<td><span class=\"badge {cls}\">{E(p.RiskText)}</span></td>" +
                              $"<td>{E(p.Banner)}</td><td>{E(p.Note)}</td></tr>");
            }
            sb.AppendLine("</table>");
        }

        sb.AppendLine("<p class=\"muted\" style=\"margin-top:40px\">Bu rapor yalnızca kendi cihaz ve ağında yapılan kontrollere dayanır. " +
                      "Virüs taraması veya tam bir güvenlik denetimi yerine geçmez. " +
                      "IP ve cihaz adları içerdiği için herkese açık yerlerde paylaşma.</p>");
        sb.AppendLine("</body></html>");

        return sb.ToString();
    }
}