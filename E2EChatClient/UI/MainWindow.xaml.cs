using System;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

// BrushConverter().ConvertFrom(...) 返回 object? 与 SolidColorBrush 转换产生 CS8600,
// 这些颜色字符串都是硬编码常量, 不会为 null, 故此文件关闭该警告.
#pragma warning disable CS8600

using E2EChatClient.CryptoV2;
using E2EChatClient.Net.V2;
using E2EChatClient.Native;

namespace E2EChatClient.UI
{
    public partial class MainWindow : Window
    {
        private ChatSessionV2? _session;
        private string _myName = "";

        public MainWindow()
        {
            InitializeComponent();

            // GPU/DLL 探测保留 (与 V2 加密主链路无关, 仅信息展示)
            string gpu = CryptoLibBridge.IsGpuAvailable() ? "GPU 可用" : "GPU 未启用 (CPU 后备)";
            PushEvent("[启动] " + gpu);
            PushEvent("[启动] DLL: " + (CryptoLibBridge.IsDllAvailable()
                ? "CryptoLib.dll 已加载"
                : "CryptoLib.dll 缺失 — 走 C# 内置 Cipher"));
            PushEvent("[V2] X25519 + XChaCha20-Poly1305 + BLAKE3 + Ed25519 + DoubleRatchet");
        }

        private async void ConnBtn_Click(object sender, RoutedEventArgs e)
        {
            // 已连接 → 断开
            if (_session != null)
            {
                await _session.LeaveAsync();
                _session.Dispose();
                _session = null;
                ConnBtn.Content = "连接";
                ConnBtn.Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#89b4fa");
                SendBtn.IsEnabled = false;
                ConnStatus.Text = "● 已断开";
                ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                MembersList.Items.Clear();
                return;
            }

            string host = HostBox.Text.Trim();
            int port = int.Parse(PortBox.Text.Trim());
            string name = NameBox.Text.Trim();
            string room = RoomBox.Text.Trim();

            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(room))
            {
                MessageBox.Show("昵称和房间不能空");
                return;
            }
            _myName = name;

            // F3-4 房间准入: 如房间名非 lobby 且 server 已给该房设过密码, 用户必须输对密码
            // 才能进. 客户端无法预先知道该房是否加密, 让 server 在 auth 响应上告知.
            // 简化: 用户填入房名后, 若想加入带密码房, 弹密码框 (空表示先尝试公开房).
            string roomPassword = "";
            if (room != "lobby") {
                // 主动问一次密码 (可为空 = 试公开房)
                var pwDialog = new SimpleInputDialog(
                    "加入房间密码 (可选)",
                    $"房间 \"{room}\" 若被主人加密, 须填密码.\n留空 = 试公开房 (失败再带密码重试):");
                pwDialog.Owner = this;
                if (pwDialog.ShowDialog() == true) {
                    roomPassword = pwDialog.Answer ?? "";
                }
            }

            _session = new ChatSessionV2(host, port);
            // F1: 严格 TLS. 勾选 TLS 必须填指纹, 否则视为配置失败的拒绝连接.
            // 之前 GUI 勾 TLS 即 AllowSelfSigned=true = "加密但不认证", 任意中间人亮自签即可 MITM.
            if (TlsBox.IsChecked == true) {
                string fp = CertShaBox.Text.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(fp)) {
                    System.Windows.MessageBox.Show(
                        "开启 TLS 必须填服务器证书 SHA256 指纹 (gen_self_signed_cert.py 会打印).\n" +
                        "拒绝以'信任任意证书'模式连接, 防止 MITM.",
                        "TLS 指纹缺失",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Warning);
                    return;
                }
                _session.UseTls = true;
                _session.AllowSelfSigned = false;       // 强制指纹锁
                _session.ServerCertSha256 = fp;
            } else {
                // 头号 🔴 修复 (2026-07-15): 默认 ws:// 明文 = auth.epub/成员关系/消息外壳全裸奔.
                // 不动协议默认 (保留内网联调友好), 但每次明文连接强制 informed consent:
                // 用户必须主动确认"我了解网络风险"才会继续, 防误用默认值进入不安全通道.
                var mbResult = System.Windows.MessageBox.Show(
                    "⚠ 你将以 **明文 ws://** 连接服务器.\n\n" +
                    "风险: auth.epub、成员关系、消息外壳在网络链路上全裸奔. 任何在链路上的" +
                    "人 (ISP/同 Wi-Fi/企业代理) 可被动读取; 主动 MITM 可在不破任何密钥的情况下\n" +
                    "读改写全部所谓端到端消息 (Pass2-F2).\n\n" +
                    "推荐: 取消本弹窗 → 勾选 TLS → 把 gen_self_signed_cert.py 打印的指纹粘进指纹框.\n\n" +
                    "我只在内网联调或已知安全网络下使用明文, 确认继续?",
                    "明文连接风险确认",
                    System.Windows.MessageBoxButton.YesNo,
                    System.Windows.MessageBoxImage.Warning,
                    System.Windows.MessageBoxResult.No);
                if (mbResult != System.Windows.MessageBoxResult.Yes) {
                    _session.Dispose();
                    _session = null;
                    return;
                }
                PushEvent("[⚠] 已确认明文连接风险 (Pass2-F2: 默认 ws:// 不防 MITM)");
            }

            _session.OnAuthResult += (ok, info) =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (ok)
                    {
                        ConnBtn.Content = "断开";
                        ConnBtn.Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                        SendBtn.IsEnabled = true;
                        ConnStatus.Text = "● 已连接 " + _session.Room + "  sid=" + (_session.MySid ?? "");
                        ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#a6e3a1");
                        string epub = _session?.MyEphemeralPubB64 ?? "";
                        MyKeyBlock.Text = "我的临时公钥 (b64): " +
                            (string.IsNullOrEmpty(epub) ? "" :
                             (epub.Length > 32 ? epub[..32] + "..." : epub));
                        PushEvent("[ECDH] 临时 X25519 私钥 32B 已生成 (用完 zeroize)");
                        PushEvent("[BLAKE3] 自写 BLAKE3 实例就绪, 准备验消息");
                        PushEvent("[DoubleRatchet] HKDF-SHA512 双链棘轮就绪");
                        // 主动通知房间,让其他成员注册我的临时公钥(以防服务器 new_member 广播次序错位)
                        _session?.NotifyRoomIAmHere();
                    }
                    else
                    {
                        ConnStatus.Text = "● 认证失败 " + info;
                        ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                        _session?.Dispose();
                        _session = null;
                    }
                });
            };

            // V2: OnMessageReceived (sender_sid, plaintext) — 仅 2 参数
            _session.OnMessageReceived += (senderSid, text) =>
            {
                Dispatcher.Invoke(() =>
                {
                    PushChat(senderSid, text, incoming: true);
                    PushEvent($"[解密] BLAKE3 自校 + Ed25519 验签 + XChaCha20-Poly1305 通过, 来源 {senderSid}");
                });
            };

            // V2: OnNewMember (peer_sid, peer_epub_b64) — 2 参数 (无 name)
            // F4-2 后续 (TOFU 不防主动 MITM): 成员列表里展示完整 64 字符 BLAKE3 指纹首/尾截断,
            // 双击该成员可在弹窗里比对完整指纹做带外核对. 这是 TOFU 不够时的主动防线:
            // MITM 在线即把你对端换成了他, 但他与真对端的 epub 指纹不同, 带外核对即可识破.
            _session.OnNewMember += (peerSid, peerEpubB64) =>
            {
                Dispatcher.Invoke(() =>
                {
                    string fullFp = FullFingerprintHex(peerEpubB64);
                    string shortFp = fullFp.Length >= 12 ? fullFp[..12] : fullFp;
                    string label = $" {peerSid}  ({shortFp}…)";
                    // Tag 存完整指纹, 双击时弹出带外比对用
                    var li = new ListBoxItem { Content = label, Tag = (peerSid, fullFp) };
                    if (!MembersList.Items.OfType<ListBoxItem>().Any(x =>
                            x.Tag is ValueTuple<string,string> t && t.Item1 == peerSid))
                        MembersList.Items.Add(li);
                    PushEvent($"[成员] 加入 → sid={peerSid}  epub_fp[:12]={shortFp}…  "
                            + $"(双击成员可看完整指纹做带外核对)");
                });
            };
            MembersList.MouseDoubleClick += (s, e) =>
            {
                if (MembersList.SelectedItem is ListBoxItem li
                    && li.Tag is ValueTuple<string, string> tag)
                {
                    string peerSid = tag.Item1;
                    string fullFp = tag.Item2;
                    System.Windows.MessageBox.Show(
                        $"对端 sid:  {peerSid}\n\n"
                        + $"对端 epub 完整 BLAKE3 指纹 (64 字符):\n  {fullFp}\n\n"
                        + "⚠ MITM 防护: 带外 (其他信道, 如电话/当面/PGP) 与该成员核对此指纹.\n"
                        + "  完全一致 → 此为真对端; 不一致 → 你正被中间人, 立即断开并改用 wss+证书指纹锁.",
                        "带外指纹比对 — TOFM 安全防线",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                }
            };

            _session.OnServerEvent += (msg) =>
            {
                Dispatcher.Invoke(() =>
                {
                    PushEvent("[server] " + msg);
                    if (msg.Contains("kick") || msg.Contains("reject"))
                    {
                        ConnStatus.Text = "● 被服务器拒绝";
                        ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                        SendBtn.IsEnabled = false;
                    }
                    if (msg.Contains("message_dropped"))
                    {
                        PushChat("⚠", "服务器丢失我刚发的一条消息 (BLAKE3 校验未通过)", incoming: false);
                    }
                });
            };

            // F3-4 房间列表 (服务端 list_rooms -> OnRoomList)
            _session.OnRoomList += (rooms) =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (rooms.Count == 0) {
                        PushEvent("[房间] 服务器无在线房间 (除了默认 lobby)");
                        System.Windows.MessageBox.Show(
                            "服务器上当前无在线房间 (除默认 lobby 之外).\n\n" +
                            "如想加入有密码的房间, 让房主告诉你房名 + 密码, 在顶部 \"房间\" 框输入房名再点连接, " +
                            "弹密码框即输入.",
                            "房间列表",
                            System.Windows.MessageBoxButton.OK,
                            System.Windows.MessageBoxImage.Information);
                        return;
                    }
                    var sb = new System.Text.StringBuilder();
                    sb.AppendLine("当前在线房间:");
                    sb.AppendLine();
                    foreach (var r in rooms)
                        sb.AppendLine($"  {r.Name}  {(r.HasPassword ? "🔒" : "公开")}  在线 {r.MemberCount} 人");
                    sb.AppendLine();
                    sb.AppendLine("加入有密码房间: 把房名填到顶部 \"房间\" 框, 点连接, 输入密码.");
                    System.Windows.MessageBox.Show(sb.ToString(), "房间列表",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                    PushEvent($"[房间] 收到 {rooms.Count} 个在线房间");
                });
            };

            ConnStatus.Text = "● 正在认证...";
            ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f9e2af");
            try
            {
                // V2: AuthAsync(room) — 不再传 name (握手包最小化, name 仅本地用)
                bool ok = await _session.AuthAsync(room, roomPassword, timeoutMs: 8000);
                if (!ok && _session != null)
                {
                    // 失败可能是房密码错. 让用户看到 server reason (::_session.OnAuthResult 已 print)
                    ConnStatus.Text = "● 认证超时或被拒 (房间密码错?)";
                    ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                    _session.Dispose();
                    _session = null;
                }
            }
            catch (Exception ex)
            {
                ConnStatus.Text = "● 连接异常: " + ex.Message;
                ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                _session?.Dispose();
                _session = null;
            }
        }

        private async void SendBtn_Click(object sender, RoutedEventArgs e) => await DoSend();

        private async void MsgBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await DoSend();
        }

        private async Task DoSend()
        {
            if (_session == null || !SendBtn.IsEnabled) return;
            string text = MsgBox.Text.Trim();
            if (string.IsNullOrEmpty(text)) return;
            MsgBox.Clear();
            // 自己的本地气泡 + 远端加密发出
            PushChat(_myName, text, incoming: false);
            await _session.SendMessageAsync(text, "ALL");
        }

        // ============================================================
        //  UI 辅助
        // ============================================================
        private void PushChat(string name, string text, bool incoming)
        {
            Border bubble = new()
            {
                Background = (SolidColorBrush)new BrushConverter().ConvertFrom(incoming ? "#313244" : "#a6e3a1"),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(8),
                Margin = new Thickness(0, 0, 0, 6),
                HorizontalAlignment = incoming ? HorizontalAlignment.Left : HorizontalAlignment.Right,
            };
            TextBlock header = new()
            {
                Text = name,
                Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#a6adc8"),
                FontSize = 10,
                Margin = new Thickness(0, 0, 0, 2),
            };
            TextBlock body = new()
            {
                Text = text,
                Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom(incoming ? "#cdd6f4" : "Black"),
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 540,
            };
            StackPanel panel = new();
            panel.Children.Add(header);
            panel.Children.Add(body);
            bubble.Child = panel;

            ChatPanel.Children.Add(bubble);
            ChatScroll.ScrollToBottom();
        }

        private void PushEvent(string s)
        {
            EventsList.Items.Insert(0, DateTime.Now.ToString("HH:mm:ss") + " " + s);
            if (EventsList.Items.Count > 200)
                EventsList.Items.RemoveAt(EventsList.Items.Count - 1);
            StatusBar.Text = s;
        }

        // V2: 指纹改用 BLAKE3 (替代 MD5)
        private static string Fingerprint(string? pubB64)
        {
            if (string.IsNullOrEmpty(pubB64)) return "—";
            try
            {
                byte[] b = Convert.FromBase64String(pubB64);
                return Blake3Hash.HashHex(b)[..12];
            }
            catch { return "?"; }
        }

        // F4-2 后续: 完整 64 字符 BLAKE3 指纹 (带外比对用). 现仅 OnNewMember 双击弹窗使用.
        private static string FullFingerprintHex(string? pubB64)
        {
            if (string.IsNullOrEmpty(pubB64)) return new string('—', 16);
            try
            {
                byte[] b = Convert.FromBase64String(pubB64);
                return Blake3Hash.HashHex(b);
            }
            catch { return new string('?', 16); }
        }

        protected override void OnClosed(EventArgs e)
        {
            _session?.Dispose();
            base.OnClosed(e);
        }

        // F3-4 房间准入: 创建带密码的新房
        private async void CreateRoomBtn_Click(object sender, RoutedEventArgs e)
        {
            string room = NewRoomBox.Text.Trim();
            string pw   = NewRoomPwBox.Text;
            if (string.IsNullOrEmpty(room)) {
                MessageBox.Show("请填新房名");
                return;
            }
            if (room == "lobby") {
                MessageBox.Show("\"lobby\" 是保留公开房名, 不能创建. 换个房名.");
                return;
            }
            if (!string.IsNullOrEmpty(pw) && pw.Length < 4) {
                MessageBox.Show("密码至少 4 字符 (留空 = 公开房)");
                return;
            }
            string host = HostBox.Text.Trim();
            int port = int.Parse(PortBox.Text.Trim());
            using var creator = new ChatSessionV2(host, port);
            if (TlsBox.IsChecked == true) {
                string fp = CertShaBox.Text.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(fp)) {
                    MessageBox.Show("勾了 TLS 但没填指纹. 取消创建.");
                    return;
                }
                creator.UseTls = true;
                creator.AllowSelfSigned = false;
                creator.ServerCertSha256 = fp;
            }
            PushEvent($"[房间] 创建中: {room} (密码{(string.IsNullOrEmpty(pw) ? "—" : "已设")})");
            bool ok = await creator.CreateRoomAsync(room, string.IsNullOrEmpty(pw) ? null : pw);
            if (ok) {
                PushEvent($"[房间] 创建成功: {room}. 房名已记录到 server 内存 (owner 离线即清).");
                NewRoomBox.Clear();
                NewRoomPwBox.Clear();
                RoomBox.Text = room;
                MessageBox.Show($"房的密码已设到服务器. 现在点 \"连接\" 即以 owner 身份加入 {room}.\n" +
                                $"加入密码即刚才那个 (此会话将断开并自动走主连接).",
                                "房间创建成功",
                                MessageBoxButton.OK, MessageBoxImage.Information);
            } else {
                PushEvent($"[房间] 创建失败: {room} (可能撞名已被他人占用 / ep_sig 校验失败)");
                MessageBox.Show($"创建失败. 可能: 房间名已被他人占用 / id_sig 无效 / 服务器未启 / 没勾 TLS 但服务端是 wss.",
                                "创建房间失败",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // F3-4: 列房 (点连接后才能查 — server 要求先 auth)
        private void RefreshRoomBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_session != null) {
                _session.RequestRoomList();
                PushEvent("[房间] 已向服务器查询在线房间列表");
            } else {
                MessageBox.Show("先点 \"连接\" 进入服务器后才能查房.",
                                "未连接", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
    }

    /// <summary>
    /// 极简模态文本输入对话框. 返回 DialogResult=true 表示用户点 OK, Answer 为输入内容.
    /// F3-4 房间密码输入用 (避免为单功能引大库).
    /// </summary>
    internal sealed class SimpleInputDialog : Window
    {
        public string? Answer { get; private set; }
        public SimpleInputDialog(string title, string prompt)
        {
            Title = title;
            Width = 420; Height = 170;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#1e1e2e");
            ResizeMode = ResizeMode.NoResize;
            var sp = new StackPanel { Margin = new Thickness(10) };
            var tb = new TextBlock {
                Text = prompt, Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#cdd6f4"),
                TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0,0,0,8) };
            var box = new TextBox {
                Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#313244"),
                Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#cdd6f4"),
                Padding = new Thickness(4), Margin = new Thickness(0,0,0,8) };
            var bp = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var ok = new Button { Content = "OK", Width = 70, Margin = new Thickness(4,0,0,0),
                                  Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#a6e3a1"),
                                  Foreground = Brushes.Black };
            var cancel = new Button { Content = "Cancel", Width = 70, Margin = new Thickness(4,0,0,0),
                                      Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#313244"),
                                      Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#cdd6f4") };
            ok.Click     += (s,e) => { Answer = box.Text; DialogResult = true;  Close(); };
            cancel.Click += (s,e) => {                            DialogResult = false; Close(); };
            bp.Children.Add(ok); bp.Children.Add(cancel);
            sp.Children.Add(tb); sp.Children.Add(box); sp.Children.Add(bp);
            Content = sp;
            box.Focus();
        }
    }
}
