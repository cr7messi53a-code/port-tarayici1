using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace PortScanner.Core;

public record PasswordAnalysis(int Score, string Level, List<string> Tips);

public static class PasswordChecker
{
    private static readonly HttpClient Http = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("PortTarayici/1.2");
        c.DefaultRequestHeaders.Add("Add-Padding", "true");
        return c;
    }

    private static readonly string[] Common =
    {
        "password", "parola", "sifre", "şifre", "123456", "12345", "qwerty", "admin",
        "iloveyou", "111111", "abc123", "galatasaray", "fenerbahce", "besiktas", "trabzonspor"
    };

    // k-anonymity: servise sadece SHA-1 özetinin ilk 5 karakteri gider
    public static async Task<int> GetBreachCountAsync(string password, CancellationToken ct = default)
    {
        string hex = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        string prefix = hex[..5];
        string suffix = hex[5..];

        string body = await Http.GetStringAsync($"https://api.pwnedpasswords.com/range/{prefix}", ct);

        foreach (var line in body.Split('\n'))
        {
            var parts = line.Trim().Split(':');
            if (parts.Length == 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase))
                return int.TryParse(parts[1], out int count) ? count : 0;
        }
        return 0;
    }

    // Kaba bir tahmin: uzunluk + karakter çeşitliliği
    public static PasswordAnalysis Analyze(string pw)
    {
        var tips = new List<string>();

        int score = Math.Min(pw.Length, 20) * 3;
        int classes = 0;
        if (pw.Any(char.IsLower)) classes++;
        if (pw.Any(char.IsUpper)) classes++;
        if (pw.Any(char.IsDigit)) classes++;
        if (pw.Any(c => !char.IsLetterOrDigit(c))) classes++;
        score += classes * 10;

        string lower = pw.ToLowerInvariant();
        if (Common.Any(lower.Contains))
        {
            score = Math.Min(score, 20);
            tips.Add("Çok yaygın bir kelime veya dizi içeriyor.");
        }
        if (pw.Distinct().Count() <= 2)
            score = Math.Min(score, 10);

        if (pw.Length < 12) tips.Add("En az 12 karakter kullan.");
        if (classes < 3) tips.Add("Büyük/küçük harf, rakam ve sembolü karıştır.");
        tips.Add("Her hesap için farklı parola kullan, bir parola yöneticisi işini kolaylaştırır.");

        string level = score < 40 ? "Zayıf" : score < 70 ? "Orta" : "Güçlü";
        return new PasswordAnalysis(score, level, tips);
    }
}