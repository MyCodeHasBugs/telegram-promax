using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Installer;

/// <summary>
/// 实际的解压安装逻辑。负责：读到内嵌的 payload.zip → 询问目标目录 → 解压 → 可选创建桌面快捷方式 → 完成。
/// </summary>
internal static class InstallEngine
{
    public const string ProductName = "E2EChatClient";
    public const string ExeName = "E2EChatClient.exe";
    public const long ApproxPayloadBytes = 20L * 1024 * 1024; // 大约 20MB

    // ───────── 资源加载 ─────────

    private static Stream LoadPayloadStream()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("payload.zip", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("找不到内嵌的 payload.zip 资源");
        return asm.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException("无法打开 payload.zip 资源流");
    }

    // ───────── 同步/静默安装 ─────────

    public static void RunSilent(string? targetDir, bool createShortcut)
    {
        if (string.IsNullOrEmpty(targetDir))
            targetDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), ProductName);

        ExtractTo(targetDir, null);
        if (createShortcut) CreateDesktopShortcut(targetDir);

        var exePath = Path.Combine(targetDir, ExeName);
        if (File.Exists(exePath))
        {
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exePath) { UseShellExecute = true }); }
            catch { /* 静默安装失败时不抛 */ }
        }
    }

    // ───────── 解压（带进度回调）─────────

    public static void ExtractTo(string targetDir, IProgress<InstallProgress>? progress)
    {
        Directory.CreateDirectory(targetDir);
        long totalEntries;
        long done = 0;

        using (var payload = LoadPayloadStream())
        using (var archive = new ZipArchive(payload, ZipArchiveMode.Read, leaveOpen: false))
        {
            totalEntries = archive.Entries.Count;
            progress?.Report(new InstallProgress(0, totalEntries, 0, "准备安装…"));

            // BUG-2 修复: 计算 targetDir 的规范全路径, 用于后续 Zip Slip 防御
            string fullTarget = Path.GetFullPath(targetDir)
                                + Path.DirectorySeparatorChar;

            int idx = 0;
            foreach (var entry in archive.Entries)
            {
                idx++;
                done++;
                string rel = entry.FullName.Replace('/', '\\');
                string dst = Path.Combine(targetDir, rel);

                // BUG-2 修复 (Zip Slip): 验证解压目标在 targetDir 内,
                //   防止恶意 entry (含 ".." 或绝对路径) 写到 targetDir 之外.
                string fullDst = Path.GetFullPath(dst);
                if (!fullDst.StartsWith(fullTarget, StringComparison.OrdinalIgnoreCase))
                    throw new IOException($"Zip Slip 检测: entry 路径越界 targetDir: {entry.FullName}");

                if (rel.EndsWith("\\") || entry.Length == 0 && string.IsNullOrEmpty(entry.Name))
                {
                    Directory.CreateDirectory(dst);
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
                    using (var src = entry.Open())
                    using (var outFs = File.Create(dst))
                    {
                        src.CopyTo(outFs);
                    }
                }

                if (idx % 8 == 0 || idx == totalEntries)
                {
                    double pct = totalEntries == 0 ? 100 : (double)done / totalEntries * 100;
                    progress?.Report(new InstallProgress(done, totalEntries, pct, $"解压中 {done}/{totalEntries}"));
                }
            }
        }

        progress?.Report(new InstallProgress(totalEntries, totalEntries, 100, "安装完成"));
    }

    // ───────── 桌面快捷方式 ─────────

    public static void CreateDesktopShortcut(string targetDir)
    {
        try
        {
            string exePath = Path.Combine(targetDir, ExeName);
            if (!File.Exists(exePath)) return;

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string lnk = Path.Combine(desktop, ProductName + ".lnk");
            if (File.Exists(lnk)) File.Delete(lnk);

            Type t = Type.GetTypeFromProgID("WScript.Shell") ?? throw new InvalidOperationException("WScript.Shell 不可用");
            dynamic shell = Activator.CreateInstance(t)!;
            dynamic sc = shell.CreateShortcut(lnk);
            sc.TargetPath = exePath;
            sc.WorkingDirectory = targetDir;
            sc.Description = ProductName;
            sc.IconLocation = exePath + ",0";
            sc.Save();
            Marshal.FinalReleaseComObject(sc);
            Marshal.FinalReleaseComObject(shell);
        }
        catch
        {
            // 上层不抛
        }
    }
}

internal readonly record struct InstallProgress(long Done, long Total, double Percent, string Message);
