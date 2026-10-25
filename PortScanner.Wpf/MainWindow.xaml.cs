using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using PortScanner.Core;

namespace PortScanner.Wpf;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<PortResult> _ports = new();
    private readonly ObservableCollection<DeviceResult> _devices = new();
    private readonly ObservableCollection<CheckResult> _checks = new();
    private CancellationTokenSource? _cts;
    private int? _lastScore;

    public MainWindow()
    {
        InitializeComponent();
        PortGrid.ItemsSource = _ports;
        DeviceGrid.ItemsSource = _devices;
        AuditGrid.ItemsSource = _checks;
        CidrBox.Text = NetworkScanner.GetLocalCidr() ?? "192.168.1.0/24";
    }

    private void SetBusy(bool busy)
    {
        ScanBtn.IsEnabled = !busy;
        NetBtn.IsEnabled = !busy;
        AuditBtn.IsEnabled = !busy;
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
        StatusText.Text = "Bilgisayar kontrol ediliyor...";
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
                ? "Bitti. Kontrol edilen her şey yolunda."
                : $"Bitti. {sorun} konuda dikkat etmen gereken bir şey var.";
        }
        catch (OperationCanceledException) { StatusText.Text = "İptal edildi."; }
        catch (Exception ex) { StatusText.Text = "Hata: " + ex.Message; }
        finally { SetBusy(false); }
    }

    private async void NetBtn_Click(object sender, RoutedEventArgs e)
    {
        _devices.Clear();
        Bar.Value = 0;
        SetBusy(true);
        StatusText.Text = "Ağ taranıyor...";
        _cts = new CancellationTokenSource();
        var progress = new Progress<int>(p => Bar.Value = p);

        try
        {
            await NetworkScanner.ScanAsync(
                CidrBox.Text,
                d => Dispatcher.Invoke(() => InsertDevice(d)),
                progress, ct: _cts.Token);

            StatusText.Text = $"Bitti. {_devices.Count} cihaz bulundu. Port taramak için bir cihaza çift tıkla.";
        }
        catch (OperationCanceledException) { StatusText.Text = "İptal edildi."; }
        catch (FormatException ex) { StatusText.Text = ex.Message; }
        catch (Exception ex) { StatusText.Text = "Hata: " + ex.Message; }
        finally { SetBusy(false); }
    }

    private void DeviceGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DeviceGrid.SelectedItem is DeviceResult d)
        {
            HostBox.Text = d.Ip;
            StatusText.Text = $"Hedef seçildi: {d.Ip}. 'Portları Tara'ya basabilirsin.";
        }
    }

    private async void ScanBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(StartBox.Text, out int start) ||
            !int.TryParse(EndBox.Text, out int end) ||
            start < 1 || end > 65535 || start > end)
        {
            MessageBox.Show("Port aralığı 1-65535 arasında olmalı.");
            return;
        }

        _ports.Clear();
        Bar.Value = 0;
        SetBusy(true);
        StatusText.Text = "Portlar taranıyor...";
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
            StatusText.Text = $"Bitti. {_ports.Count} açık port: {yuksek} yüksek, {orta} orta, {dusuk} düşük risk.";
        }
        catch (OperationCanceledException) { StatusText.Text = "İptal edildi."; }
        catch (Exception ex) { StatusText.Text = "Hata: " + ex.Message; }
        finally { SetBusy(false); }
    }

    private async void PwBtn_Click(object sender, RoutedEventArgs e)
    {
        string pw = PwBox.Password;
        if (string.IsNullOrEmpty(pw))
        {
            PwResult.Foreground = Brushes.Gray;
            PwResult.Text = "Önce bir parola yaz.";
            return;
        }

        PwBtn.IsEnabled = false;
        PwResult.Foreground = Brushes.Gray;
        PwResult.Text = "Kontrol ediliyor...";

        var analysis = PasswordChecker.Analyze(pw);
        PwStrength.Text = $"Güç tahmini: {analysis.Level} ({analysis.Score}/100)\n• "
            + string.Join("\n• ", analysis.Tips);

        try
        {
            int count = await PasswordChecker.GetBreachCountAsync(pw);
            if (count > 0)
            {
                PwResult.Text = $"✖ Bu parola veri sızıntılarında {count:N0} kez görülmüş. Kullanma!";
                PwResult.Foreground = Brushes.Crimson;
            }
            else
            {
                PwResult.Text = "✔ Bilinen veri sızıntılarında bulunamadı. (Bu, güçlü olduğu anlamına gelmez.)";
                PwResult.Foreground = Brushes.ForestGreen;
            }
        }
        catch (Exception)
        {
            PwResult.Text = "Sızıntı kontrolü yapılamadı (internet yok ya da servise ulaşılamadı).";
            PwResult.Foreground = Brushes.DarkOrange;
        }
        finally
        {
            PwBox.Clear();
            PwBtn.IsEnabled = true;
        }
    }

    private void ReportBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_devices.Count == 0 && _ports.Count == 0 && _checks.Count == 0)
        {
            MessageBox.Show("Rapora eklenecek sonuç yok. Önce bir tarama ya da kontrol yap.");
            return;
        }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "HTML raporu (*.html)|*.html",
            FileName = $"guvenlik-raporu-{DateTime.Now:yyyyMMdd-HHmm}.html"
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            string html = ReportBuilder.BuildHtml(
                _devices, HostBox.Text.Trim(), _ports, _checks, _lastScore);
            File.WriteAllText(dlg.FileName, html, new UTF8Encoding(true));
            StatusText.Text = "Rapor kaydedildi: " + dlg.FileName;

            try { Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true }); }
            catch { }
        }
        catch (Exception ex)
        {
            StatusText.Text = "Rapor kaydedilemedi: " + ex.Message;
        }
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();
}