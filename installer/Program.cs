using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Installer;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        bool silent = false;
        string? overridePath = null;
        bool? overrideShortcut = null;
        foreach (var a in args)
        {
            if (string.Equals(a, "/silent", StringComparison.OrdinalIgnoreCase) || string.Equals(a, "-silent", StringComparison.OrdinalIgnoreCase))
                silent = true;
            else if (a.StartsWith("/path=", StringComparison.OrdinalIgnoreCase))
                overridePath = a.Substring(6);
            else if (string.Equals(a, "/desktop", StringComparison.OrdinalIgnoreCase))
                overrideShortcut = true;
            else if (string.Equals(a, "/nodesktop", StringComparison.OrdinalIgnoreCase))
                overrideShortcut = false;
        }

        try
        {
            if (silent)
            {
                InstallEngine.RunSilent(overridePath, overrideShortcut ?? true);
                return;
            }

            Application.Run(new WizardForm());
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.ToString(), "安装失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
