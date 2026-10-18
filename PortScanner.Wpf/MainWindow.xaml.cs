using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using PortScanner.Core;

namespace PortScanner.Wpf;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<PortResult> _ports = new();
    private readonly ObservableCollection<DeviceResult> _devices = new();
    private CancellationTokenSource? _cts;

    public MainWindow()
    {
        InitializeComponent();
        PortGrid.ItemsSource = _ports;
        DeviceGrid.ItemsSource = _devices;
        CidrBox.Text = NetworkScanner.GetLocalCidr() ?? "192.168.1.0/24";
    }

    private void SetBusy(bool busy)
    {
        ScanBtn.IsEnabled = !busy;
        NetBtn.IsEnabled = !busy;
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
StatusText.Text = $"Bitti. {_ports.Count} açık port: {yuksek} yüksek, {orta} orta, {dusuk} düşük risk.";        }
        catch (OperationCanceledException) { StatusText.Text = "İptal edildi."; }
        catch (Exception ex) { StatusText.Text = "Hata: " + ex.Message; }
        finally { SetBusy(false); }
    }

    private void CancelBtn_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();
}