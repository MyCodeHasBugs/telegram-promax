using System;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Installer;

/// <summary>
/// 单窗体、多面板向导：欢迎/路径选择 → 快捷方式选项 → 进度 → 完成。
/// </summary>
internal sealed class WizardForm : Form
{
    private readonly Label _titleLabel = new();
    private readonly Label _hintLabel = new();

    private readonly Label _pathLabel = new();
    private readonly TextBox _pathBox = new();
    private readonly Button _browseButton = new();
    private readonly Label _sizeLabel = new();

    private readonly CheckBox _shortcutBox = new();
    private readonly CheckBox _launchBox = new();

    private readonly ProgressBar _progress = new();
    private readonly Label _progressLabel = new();

    private readonly Button _backButton = new();
    private readonly Button _nextButton = new();
    private readonly Button _cancelButton = new();

    private int _step = 0;
    private bool _installing = false;

    // 默认安装路径：ProgramFiles\E2EChatClient
    private static readonly string DefaultPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), InstallEngine.ProductName);

    public WizardForm()
    {
        Text = InstallEngine.ProductName + " 安装程序";
        ClientSize = new Size(460, 360);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        Icon = System.Drawing.SystemIcons.Application;

        BuildUi();
        RefreshStep();
    }

    private void BuildUi()
    {
        // ── 顶部标题 ──
        _titleLabel.AutoSize = false;
        _titleLabel.Location = new Point(24, 18);
        _titleLabel.Size = new Size(410, 40);
        _titleLabel.Font = new Font("Segoe UI", 14F, FontStyle.Bold);
        _titleLabel.ForeColor = Color.FromArgb(0x22, 0x5D, 0xE3);
        Controls.Add(_titleLabel);

        _hintLabel.AutoSize = false;
        _hintLabel.Location = new Point(24, 56);
        _hintLabel.Size = new Size(410, 32);
        _hintLabel.Font = new Font("Segoe UI", 9F);
        _hintLabel.ForeColor = SystemColors.GrayText;
        Controls.Add(_hintLabel);

        var sep = new Label
        {
            Location = new Point(24, 96),
            Size = new Size(410, 1),
            BackColor = SystemColors.ControlLight
        };
        Controls.Add(sep);

        // ── 路径页 ──
        _pathLabel.Text = "安装到：";
        _pathLabel.Location = new Point(24, 116);
        _pathLabel.Size = new Size(410, 20);
        _pathLabel.Font = new Font("Segoe UI", 9F);
        Controls.Add(_pathLabel);

        _pathBox.Location = new Point(24, 140);
        _pathBox.Size = new Size(330, 24);
        _pathBox.Font = new Font("Segoe UI", 9F);
        _pathBox.TextChanged += (_, _) => OnPathChanged();
        Controls.Add(_pathBox);

        _browseButton.Text = "浏览…";
        _browseButton.Location = new Point(358, 138);
        _browseButton.Size = new Size(76, 28);
        _browseButton.Click += OnBrowse;
        Controls.Add(_browseButton);

        _sizeLabel.Location = new Point(24, 176);
        _sizeLabel.Size = new Size(410, 20);
        _sizeLabel.Font = new Font("Segoe UI", 9F);
        _sizeLabel.ForeColor = SystemColors.GrayText;
        _sizeLabel.Text = $"所需空间：约 {InstallEngine.ApproxPayloadBytes / (1024 * 1024)} MB";
        Controls.Add(_sizeLabel);

        // ── 快捷方式页 ──
        _shortcutBox.Text = "在桌面创建快捷方式";
        _shortcutBox.Location = new Point(24, 130);
        _shortcutBox.Size = new Size(410, 28);
        _shortcutBox.Checked = true;
        _shortcutBox.Font = new Font("Segoe UI", 9F);
        Controls.Add(_shortcutBox);

        _launchBox.Text = "安装完成后启动 " + InstallEngine.ProductName;
        _launchBox.Location = new Point(24, 164);
        _launchBox.Size = new Size(410, 28);
        _launchBox.Checked = true;
        _launchBox.Font = new Font("Segoe UI", 9F);
        Controls.Add(_launchBox);

        // ── 进度页 ──
        _progress.Location = new Point(24, 140);
        _progress.Size = new Size(410, 22);
        _progress.Style = ProgressBarStyle.Continuous;
        Controls.Add(_progress);

        _progressLabel.Location = new Point(24, 176);
        _progressLabel.Size = new Size(410, 30);
        _progressLabel.Font = new Font("Segoe UI", 9F);
        _progressLabel.ForeColor = SystemColors.GrayText;
        Controls.Add(_progressLabel);

        // ── 底部按钮 ──
        _backButton.Text = "上一步";
        _backButton.Location = new Point(170, 308);
        _backButton.Size = new Size(80, 32);
        _backButton.Click += OnBack;
        Controls.Add(_backButton);

        _nextButton.Text = "下一步";
        _nextButton.Location = new Point(256, 308);
        _nextButton.Size = new Size(80, 32);
        _nextButton.Click += OnNext;
        Controls.Add(_nextButton);

        _cancelButton.Text = "取消";
        _cancelButton.Location = new Point(342, 308);
        _cancelButton.Size = new Size(80, 32);
        _cancelButton.Click += OnCancel;
        Controls.Add(_cancelButton);

        AcceptButton = _nextButton;
        CancelButton = _cancelButton;
    }

    // ───────── 顶部 Step 内容切换 ─────────
    private const int StepPath = 0;      // 选择安装路径
    private const int StepOptions = 1;   // 桌面快捷方式
    private const int StepInstalling = 2;// 安装中
    private const int StepDone = 3;       // 完成

    private void RefreshStep()
    {
        // 隐藏全部页内容
        _pathLabel.Visible = _pathBox.Visible = _browseButton.Visible = _sizeLabel.Visible = false;
        _shortcutBox.Visible = _launchBox.Visible = false;
        _progress.Visible = _progressLabel.Visible = false;

        switch (_step)
        {
            case StepPath:
                _titleLabel.Text = "选择安装位置";
                _hintLabel.Text = $"请选择 " + InstallEngine.ProductName + " 的安装目录。\n默认路径：C:\\Program Files\\" + InstallEngine.ProductName + "\\";
                _pathLabel.Visible = _pathBox.Visible = _browseButton.Visible = _sizeLabel.Visible = true;
                if (string.IsNullOrEmpty(_pathBox.Text))
                    _pathBox.Text = DefaultPath;
                _backButton.Enabled = false;
                _nextButton.Text = "下一步";
                _nextButton.Enabled = DirectoryOK(_pathBox.Text);
                _launchBox.Visible = false;
                break;

            case StepOptions:
                _titleLabel.Text = "附加选项";
                _hintLabel.Text = "请选择是否创建桌面快捷方式。\n(所需空间：约 " + (InstallEngine.ApproxPayloadBytes / (1024 * 1024)) + " MB)";
                _shortcutBox.Visible = true;
                _launchBox.Visible = true;
                _backButton.Enabled = true;
                _nextButton.Text = "安装";
                _nextButton.Enabled = true;
                break;

            case StepInstalling:
                _titleLabel.Text = "正在安装…";
                _hintLabel.Text = "正在将文件解压到：" + _pathBox.Text;
                _progress.Visible = _progressLabel.Visible = true;
                _progress.Value = 0;
                _progressLabel.Text = "准备安装…";
                _backButton.Enabled = false;
                _nextButton.Enabled = false;
                _nextButton.Text = "安装";
                StartInstall();
                break;

            case StepDone:
                _titleLabel.Text = "安装完成";
                _hintLabel.Text = InstallEngine.ProductName + " 已成功安装到您的计算机。";
                _progress.Visible = false;
                _progressLabel.Visible = false;
                _backButton.Enabled = false;
                _cancelButton.Enabled = true;
                _cancelButton.Text = "关闭";
                _nextButton.Enabled = true;
                _nextButton.Text = "完成";
                break;
        }
    }

    // ───────── 路径校验 ─────────
    private static bool DirectoryOK(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var full = Path.GetFullPath(path.Trim());
            if (full.IndexOfAny(Path.GetInvalidPathChars()) >= 0) return false;
            string? parent = Path.GetDirectoryName(full);
            if (string.IsNullOrEmpty(parent)) return false;
            // 必须在固定磁盘上
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void OnPathChanged()
    {
        if (_step == StepPath)
            _nextButton.Enabled = DirectoryOK(_pathBox.Text);
    }

    private void OnBrowse(object? s, EventArgs e)
    {
        using var dlg = new FolderBrowserDialog
        {
            Description = "选择安装目录",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
            SelectedPath = DirectoryOK(_pathBox.Text) ? _pathBox.Text : DefaultPath
        };
        if (dlg.ShowDialog(this) == DialogResult.OK)
            _pathBox.Text = dlg.SelectedPath;
    }

    private void OnBack(object? s, EventArgs e)
    {
        if (_step > StepPath && _step < StepInstalling)
        {
            _step--;
            RefreshStep();
        }
    }

    private void OnNext(object? s, EventArgs e)
    {
        if (_step == StepPath)
        {
            if (!DirectoryOK(_pathBox.Text))
            {
                MessageBox.Show(this, "路径无效，请重新选择。", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            _step = StepOptions;
            RefreshStep();
        }
        else if (_step == StepOptions)
        {
            _step = StepInstalling;
            RefreshStep();
        }
        else if (_step == StepDone)
        {
            try
            {
                if (_launchBox.Checked && !_installing)
                {
                    var exe = Path.Combine(_pathBox.Text, InstallEngine.ExeName);
                    if (File.Exists(exe))
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe) { UseShellExecute = true });
                }
            }
            catch { }
            Close();
        }
    }

    private void OnCancel(object? s, EventArgs e)
    {
        if (_installing)
        {
            if (MessageBox.Show(this, "安装尚未完成，确定要取消吗？", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;
        }
        Close();
    }

    // ───────── 后台执行 ─────────
    private void StartInstall()
    {
        _installing = true;
        string target = Path.GetFullPath(_pathBox.Text.Trim());
        bool makeShortcut = _shortcutBox.Checked;

        var prog = new Progress<InstallProgress>(p =>
        {
            if (_progress.Value != (int)p.Percent && p.Percent >= 0 && p.Percent <= 100)
                _progress.Value = (int)p.Percent;
            _progressLabel.Text = p.Message;
        });

        Task.Run(() =>
        {
            InstallEngine.ExtractTo(target, prog as IProgress<InstallProgress>);
            if (makeShortcut)
                InstallEngine.CreateDesktopShortcut(target);
        }).ContinueWith(t =>
        {
            _installing = false;
            if (t.IsFaulted)
            {
                Exception ex = t.Exception!;
                BeginInvoke(() =>
                {
                    MessageBox.Show(this, "安装失败：\n" + ex.InnerException?.Message ?? ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    Close();
                });
            }
            else
            {
                BeginInvoke(() =>
                {
                    _step = StepDone;
                    RefreshStep();
                });
            }
        }, TaskScheduler.Default);
    }
}
