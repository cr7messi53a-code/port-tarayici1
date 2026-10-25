using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using PortScanner.Core;

namespace PortScanner.Wpf;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<PortResult> _ports = new();
    private readonly ObservableCollection<DeviceResult> _devices = new();
    private readonly ObservableCollection<CheckResult> _checks = new();
    private readonly ObservableCollection<StartupItem> _startup = new();
    private CancellationTokenSource? _cts;
    private int? _lastScore;
    private bool _loading = true;

    public MainWindow()
    {
        L.Load();
        InitializeComponent();

        PortGrid.ItemsSource = _ports;
        DeviceGrid.ItemsSource = _devices;
        AuditGrid.ItemsSource = _checks;
        StartupGrid.ItemsSource = _startup;
        CidrBox.Text = NetworkScanner.GetLocalCidr() ?? "192.168.1.0/24";

        LangBox.SelectedIndex = L.Current == Lang.En ? 1 : 0;
        _loading = false;
        ApplyLanguage();
    }

    private void LangBox_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_loading) return;
        L.Current = LangBox.SelectedIndex == 1 ? Lang.En : Lang.Tr;
        L.Save();
        ApplyLanguage();
    }

    // Arayüzdeki sabit metinleri seçili dile çevirir
    private void ApplyLanguage()
    {
        Title = L.T("Port Tarayıcı", "Port Scanner");
        LangLabel.Text = L.T("Dil:", "Language:");

        TabNet.Header = L.T("Ağ Tarayıcı", "Network Scanner");
        TabAudit.Header = L.T("Bilgisayar Kontrolü", "Computer Check");
        TabPw.Header = L.T("Parola Kontrolü", "Password Check");
        TabStartup.Header = L.T("Başlangıç Programları", "Startup Programs");

        NetLabel.Text = L.T("Ağ:", "Network:");
        NetBtn.Content = L.T("Ağı Tara", "Scan Network");
        HostLabel.Text = L.T("Hedef:", "Target:");
        PortLabel.Text = L.T("Port:", "Ports:");
        ScanBtn.Content = L.T("Portları Tara", "Scan Ports");
        CancelBtn.Content = L.T("İptal", "Cancel");

        DeviceGrid.Columns[0].Header = "IP";
        DeviceGrid.Columns[1].Header = L.T("Cihaz Adı", "Device Name");
        DeviceGrid.Columns[2].Header = L.T("Yanıt", "Response");

        PortGrid.Columns[0].Header = "Port";
        PortGrid.Columns[1].Header = L.T("Servis", "Service");
        PortGrid.Columns[2].Header = L.T("Sürüm / Banner", "Version / Banner");
        PortGrid.Columns[3].Header = L.T("Risk", "Risk");
        PortGrid.Columns[4].Header = L.T("Ne demek, ne yapmalı?", "What does it mean?");

        AuditBtn.Content = L.T("Bilgisayarımı Kontrol Et", "Check My Computer");
        AuditGrid.Columns[0].Header = L.T("Durum", "Status");
        AuditGrid.Columns[1].Header = L.T("Kontrol", "Check");
        AuditGrid.Columns[2].Header = L.T("Sonuç", "Result");
        AuditGrid.Columns[3].Header = L.T("Ne yapmalı?", "What to do?");

        PwTitle.Text = L.T(
            "Parolanın veri sızıntılarında geçip geçmediğini kontrol et.",
            "Check whether your password appears in known data breaches.");
        PwInfo.Text = L.T(
            "Parolan bilgisayarından çıkmaz. Have I Been Pwned servisine sadece parolanın SHA-1 özetinin ilk 5 karakteri gönderilir.",
            "Your password never leaves your computer. Only the first 5 characters of its SHA-1 hash are sent to the Have I Been Pwned service.");
        PwBtn.Content = L.T("Kontrol Et", "Check");

        StartupBtn.Content = L.T("Başlangıç Programlarını Listele", "List Startup Programs");
        StartupInfo.Text = L.T(
            "Windows açılırken kendiliğinden çalışan programlar. İmzasız olmak zararlı olmak demek değildir; tanımadığın ve riskli işaretlenenlere dikkat et.",
            "Programs that start automatically with Windows. Being unsigned does not mean being malicious; pay attention to ones you don't recognize and ones marked risky.");
        StartupGrid.Columns[0].Header = L.T("Risk", "Risk");
        StartupGrid.Columns[1].Header = L.T("Ad", "Name");
        StartupGrid.Columns[2].Header = L.T("İmza", "Signature");
        StartupGrid.Columns[3].Header = L.T("Konum", "Location");
        StartupGrid.Columns[4].Header = L.T("Dosya", "File");
        StartupGrid.Columns[5].Header = L.T("Not", "Note");

        ReportBtn.Content = L.T("Raporu Kaydet (HTML)", "Save Report (HTML)");
        StatusText.Text = L.T("Hazır.", "Ready.");
    }

    private void SetBusy(bool busy)
    {
        ScanBtn.IsEnabled = !busy;
        NetBtn.IsEnabled = !busy;
        AuditBtn.IsEnabled = !busy;
        StartupBtn.IsEnabled = !busy;
        ReportBtn.IsEnabled = !busy;
        CancelBtn.IsEnabled = busy;
    }

    private void InsertDevice(DeviceResult d)
    {
        uint n = NetworkScanner.IpToNumber(d.Ip);
        int i = 0;
        while (i < _devices.Count && NetworkScanner.IpToNumber(_devices[i].Ip) < n) i++;
        _devices.Insert(i, d);
    }

    private void InsertPort(PortResult r)
    {
        int i = 0;
        while (i < _ports.Count && _ports[i].Port < r.Port) i++;
        _ports.Insert(i, r);
    }

    private async void AuditBtn_Click(object sender, RoutedEventArgs e)
    {
        _checks.Clear();
        _lastScore = null;
        ScoreText.Text = "--";
        ScoreText.Foreground = Brushes.Gray;
        Bar.Value = 0;
        SetBusy(true);
        StatusText.Text = L.T("Bilgisayar kontrol ediliyor...", "Checking your computer...");
        _cts = new CancellationTokenSource();
        var progress = new Progress<int>(p => Bar.Value = p);

        try
        {
            int score = await SecurityAudit.RunAsync(r => _checks.Add(r), progress, _cts.Token);
            _lastScore = score;

            ScoreText.Text = score.ToString();
            ScoreText.Foreground = score >= 80
                ? new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A))
                : score >= 50
                    ? new SolidColorBrush(Color.FromRgb(0xD9, 0x77, 0x06))
                    : new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));

            int sorun = _checks.Count(c => c.Status is CheckStatus.Basarisiz or CheckStatus.Uyari);
            StatusText.Text = sorun == 0
                ? L.T("Bitti. Kontrol edilen her şey yolunda.", "Done. Everything checked looks fine.")
                : L.T($"Bitti. {sorun} konuda dikkat etmen gereken bir şey var.",
                      $"Done. {sorun} item(s) need your attention.");
        }
        catch (OperationCanceledException) { StatusText.Text = L.T("İptal edildi.", "Cancelled."); }
        catch (Exception ex) { StatusText.Text = L.T("Hata: ", "Error: ") + ex.Message; }
        finally { SetBusy(false); }
    }

    private async void NetBtn_Click(object sender, RoutedEventArgs e)
    {
        _devices.Clear();
        Bar.Value = 0;
        SetBusy(true);
        StatusText.Text = L.T("Ağ taranıyor...", "Scanning network...");
        _cts = new CancellationTokenSource();
        var progress = new Progress<int>(p => Bar.Value = p);

        try
        {
            await NetworkScanner.ScanAsync(
                CidrBox.Text,
                d => Dispatcher.Invoke(() => InsertDevice(d)),
                progress, ct: _cts.Token);

            StatusText.Text = L.T(
                $"Bitti. {_devices.Count} cihaz bulundu. Port taramak için bir cihaza çift tıkla.",
                $"Done. {_devices.Count} device(s) found. Double-click a device to scan its ports.");
        }
        catch (OperationCanceledException) { StatusText.Text = L.T("İptal edildi.", "Cancelled."); }
        catch (FormatException ex) { StatusText.Text = ex.Message; }
        catch (Exception ex) { StatusText.Text = L.T("Hata: ", "Error: ") + ex.Message; }
        finally { SetBusy(false); }
    }

    private void DeviceGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DeviceGrid.SelectedItem is DeviceResult d)
        {
            HostBox.Text = d.Ip;
            StatusText.Text = L.T(
                $"Hedef seçildi: {d.Ip}. 'Portları Tara'ya basabilirsin.",
                $"Target selected: {d.Ip}. You can press 'Scan Ports'.");
        }
    }

    private async void ScanBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(StartBox.Text, out int start) ||
            !int.TryParse(EndBox.Text, out int end) ||
            start < 1 || end > 65535 || start > end)
        {
            MessageBox.Show(L.T("Port aralığı 1-65535 arasında olmalı.",
                                "Port range must be between 1 and 65535."));
            return;
        }

        _ports.Clear();
        Bar.Value = 0;
        SetBusy(true);
        StatusText.Text = L.T("Portlar taranıyor...", "Scanning ports...");
        _cts = new CancellationTokenSource();
        var progress = new Progress<int>(p => Bar.Value = p);

        try
        {
            await TcpPortScanner.ScanAsync(
                HostBox.Text.Trim(), start, end,
                r => Dispatcher.Invoke(() => InsertPort(r)),
                progress, ct: _cts.Token);

            int yuksek = _ports.Count(p => p.Risk == RiskLevel.Yuksek);
            int orta = _ports.Count(p => p.Risk == RiskLevel.Orta);
            int dusuk = _ports.Count(p => p.Risk == RiskLevel.Dusuk);
            StatusText.Text = L.T(
                $"Bitti. {_ports.Count} açık port: {yuksek} yüksek, {orta} orta, {dusuk} düşük risk.",
                $"Done. {_ports.Count} open port(s): {yuksek} high, {orta} medium, {dusuk} low risk.");
        }
        catch (OperationCanceledException) { StatusText.Text = L.T("İptal edildi.", "Cancelled."); }
        catch (Exception ex) { StatusText.Text = L.T("Hata: ", "Error: ") + ex.Message; }
        finally { SetBusy(false); }
    }

    private async void PwBtn_Click(object sender, RoutedEventArgs e)
    {
        string pw = PwBox.Password;
        if (string.IsNullOrEmpty(pw))
        {
            PwResult.Foreground = Brushes.Gray;
            PwResult.Text = L.T("Önce bir parola yaz.", "Type a password first.");
            return;
        }

        PwBtn.IsEnabled = false;
        PwResult.Foreground = Brushes.Gray;
        PwResult.Text = L.T("Kontrol ediliyor...", "Checking...");

        var analysis = PasswordChecker.Analyze(pw);
        PwStrength.Text = $"{L.T("Güç tahmini", "Strength estimate")}: {analysis.Level} ({analysis.Score}/100)\n• "
            + string.Join("\n• ", analysis.Tips);

        try
        {
            int count = await PasswordChecker.GetBreachCountAsync(pw);
            if (count > 0)
            {
                PwResult.Text = L.T(
                    $"✖ Bu parola veri sızıntılarında {count:N0} kez görülmüş. Kullanma!",
                    $"✖ This password has appeared in data breaches {count:N0} times. Don't use it!");
                PwResult.Foreground = Brushes.Crimson;
            }
            else
            {
                PwResult.Text = L.T(
                    "✔ Bilinen veri sızıntılarında bulunamadı. (Bu, güçlü olduğu anlamına gelmez.)",
                    "✔ Not found in known data breaches. (This does not mean it is strong.)");
                PwResult.Foreground = Brushes.ForestGreen;
            }
        }
        catch (Exception)
        {
            PwResult.Text = L.T(
                "Sızıntı kontrolü yapılamadı (internet yok ya da servise ulaşılamadı).",
                "Breach check failed (no internet connection or the service is unreachable).");
            PwResult.Foreground = Brushes.DarkOrange;
        }
        finally
        {
            PwBox.Clear();
            PwBtn.IsEnabled = true;
        }
    }

    private async void StartupBtn_Click(object sender, RoutedEventArgs e)
    {
        _startup.Clear();
        Bar.Value = 0;
        Bar.IsIndeterminate = true;
        SetBusy(true);
        StatusText.Text = L.T("Başlangıç programları taranıyor...", "Scanning startup programs...");
        _cts = new CancellationTokenSource();

        try
        {
            var items = await StartupScanner.ScanAsync(_cts.Token);
            foreach (var item in items) _startup.Add(item);

            int yuksek = items.Count(i => i.Risk == RiskLevel.Yuksek);
            StatusText.Text = yuksek == 0
                ? L.T($"Bitti. {items.Count} başlangıç programı, belirgin bir risk yok.",
                      $"Done. {items.Count} startup program(s), no obvious risk.")
                : L.T($"Bitti. {items.Count} programdan {yuksek} tanesi riskli görünüyor.",
                      $"Done. {yuksek} of {items.Count} programs look risky.");
        }
        catch (OperationCanceledException) { StatusText.Text = L.T("İptal edildi.", "Cancelled."); }
        catch (Exception ex) { StatusText.Text = L.T("Hata: ", "Error: ") + ex.Message; }
        finally
        {
            Bar.IsIndeterminate = false;
            SetBusy(false);
        }
    }

    private void ReportBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_devices.Count == 0 && _ports.Count == 0 && _checks.Count == 0)
        {
            MessageBox.Show(L.T(
                "Rapora eklenecek sonuç yok. Önce bir tarama ya da kontrol yap.",
                "Nothing to include in the report. Run a scan or check first."));
            return;
        }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = L.T("HTML raporu (*.html)|*.html", "HTML report (*.html)|*.html"),
            FileName = $"{L.T("guvenlik-raporu", "security-report")}-{DateTime.Now:yyyyMMdd-HHmm}.html"
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            string html = ReportBuilder.BuildHtml(
                _devices, HostBox.Text.Trim(), _ports, _checks, _lastScore);
            File.WriteAllText(dlg.FileName, html, new UTF8Encoding(true));
            StatusText.Text = L.T("Rapor kaydedildi: ", "Report saved: ") + dlg.FileName;

            try { Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true }); }
            catch { }
        }
        catch (Exception ex)
        {
            StatusText.Text = L.T("Rapor kaydedilemedi: ", "Could not save report: ") + ex.Message;
        }
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();
}