using System.IO;
using System.Windows;

namespace PortScanner.Wpf;

public partial class App : Application
{
    public App()
    {
        DispatcherUnhandledException += (s, e) =>
        {
            Report(e.Exception);
            e.Handled = true;
            Shutdown();
        };

        AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            Report(e.ExceptionObject as Exception);
    }

    private static void Report(Exception? ex)
    {
        string text = ex?.ToString() ?? "Bilinmeyen hata";
        try
        {
            File.WriteAllText(
                Path.Combine(Path.GetTempPath(), "port-tarayici-hata.txt"), text);
        }
        catch { }
        MessageBox.Show(text, "Başlangıç hatası");
    }
}