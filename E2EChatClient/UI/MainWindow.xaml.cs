using System;
using System.Linq;
using System.Runtime.InteropServices;
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
        // F5-identity: 持久化 Ed25519 身份密钥, 跨重连/重启稳定.
        //   id_pub 作为踢人禁令键和房主认领键的前提: 必须每次连接用同一身份.
        //   启动时从 %LOCALAPPDATA%/E2EChatClient/identity.key 加载 (不存在则生成落盘).
        private readonly Ed25519Keypair _identityKey;

        public MainWindow()
        {
            InitializeComponent();

            // GL 玻璃背景失败 → 切 CPU 动画兜底 (RDP/老机/驱动不支持时)
            GlassBg.Failed += () => Dispatcher.BeginInvoke(() =>
            {
                GlassBg.Visibility = Visibility.Collapsed;
                GlassFallback.Visibility = Visibility.Visible;
                PushEvent("[UI] GL 玻璃不可用, 已切换 WPF 动画背景");
            });

            // F5-identity: 加载持久化身份 (id_pub 跨重连稳定, 是踢人禁令+房主认领的前提)
            _identityKey = IdentityStore.LoadOrCreate();
            string idFp = FullFingerprintHex(Convert.ToBase64String(_identityKey.PublicKey ?? Array.Empty<byte>()));
            PushEvent("[身份] Ed25519 长期身份已加载, id_pub 指纹=" + (idFp.Length >= 16 ? idFp[..16] + "…" : idFp));

            // GPU/DLL 探测保留 (与 V2 加密主链路无关, 仅信息展示)
            string gpu = CryptoLibBridge.IsGpuAvailable() ? "GPU 可用" : "GPU 未启用 (CPU 后备)";
            PushEvent("[启动] " + gpu);
            // GPU 密钥池: CUDA DLL 就绪时后台预生成 32 把 X25519 会话密钥
            if (GpuKeyPool.IsGpuBacked) {
                GpuKeyPool.TryFillAsync();
                PushEvent("[启动] GPU 密钥池后台填充中 (32 把 X25519/次)");
            }
            PushEvent("[启动] DLL: " + (CryptoLibBridge.IsDllAvailable()
                ? "CryptoLib.dll 已加载"
                : "CryptoLib.dll 缺失 — 走 C# 内置 Cipher"));
            PushEvent("[V2] X25519 + ML-KEM-1024 (抗量子混合握手) + XChaCha20-Poly1305 + BLAKE3 + Ed25519 + DoubleRatchet");
        }

        // ============================================================
        //  液态玻璃: 按系统版本自动选择 — Win11 Mica / Win10 Acrylic / 更老直接纯色
        // ============================================================
        private static class NativeGlass
        {
            [DllImport("dwmapi.dll", PreserveSig = true)]
            public static extern int DwmSetWindowAttribute(
                IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);

            [DllImport("user32.dll")]
            public static extern int SetWindowCompositionAttribute(
                IntPtr hwnd, ref WINDOWCOMPOSITIONATTRIBDATA data);

            [DllImport("ntdll.dll")]
            public static extern int RtlGetVersion(ref OSVERSIONINFOEX os);

            [StructLayout(LayoutKind.Sequential)]
            public struct OSVERSIONINFOEX
            {
                public uint dwOSVersionInfoSize;
                public uint dwMajorVersion;
                public uint dwMinorVersion;
                public uint dwBuildNumber;
                public uint dwPlatformId;
                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
                public string szCSDVersion;
                public ushort wServicePackMajor;
                public ushort wServicePackMinor;
                public ushort wSuiteMask;
                public byte wProductType;
                public byte wReserved;
            }

            // user32 SetWindowCompositionAttribute 用的结构
            [StructLayout(LayoutKind.Sequential)]
            public struct AccentPolicy
            {
                public int AccentState;   // 0=关闭 1=渐变 2=透明渐变 3=模糊(老) 4=亚克力模糊
                public int AccentFlags;   // 0=默认
                public uint GradientColor; // ABGR
                public int AnimationId;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct WINDOWCOMPOSITIONATTRIBDATA
            {
                public int Attribute;   // 19 = WCA_ACCENT_POLICY
                public IntPtr Data;
                public int SizeOfData;
            }
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            ApplyLiquidGlass();
        }

        private void ApplyLiquidGlass()
        {
            try
            {
                IntPtr hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                if (hwnd == IntPtr.Zero) return;

                // 深色标题栏 (Win10 1809+/Win11 都支持)
                int dark = 1;
                NativeGlass.DwmSetWindowAttribute(hwnd, 20, ref dark, sizeof(int));

                // 判定系统: Win11 = Major 10 Build >= 22000
                var os = new NativeGlass.OSVERSIONINFOEX {
                    dwOSVersionInfoSize = (uint)Marshal.SizeOf<NativeGlass.OSVERSIONINFOEX>()
                };
                NativeGlass.RtlGetVersion(ref os);
                bool isWin11 = os.dwMajorVersion == 10 && os.dwBuildNumber >= 22000;

                if (isWin11)
                {
                    // Win11: Mica 系统背景 (DWMWA_SYSTEMBACKDROP_TYPE = 38, 2 = Mica)
                    int backdrop = 2;
                    NativeGlass.DwmSetWindowAttribute(hwnd, 38, ref backdrop, sizeof(int));
                    PushEvent("[UI] 液态玻璃: Mica 模式 (Win11)");
                }
                else
                {
                    // Win10: ACCENT_ENABLE_ACRYLICBLURBEHIND (亚克力模糊), Win10 1809+
                    // 暗色调调色, ABGR = AA BB GG RR (小端内存为反序)
                    NativeGlass.AccentPolicy acc = new()
                    {
                        AccentState    = 4,                     // ACCENT_ENABLE_ACRYLICBLURBEHIND
                        AccentFlags    = 0,
                        GradientColor  = 0x66_0A_10_14,         // 微透暗黑 (Win10 亚克力玻璃)
                        AnimationId    = 0,
                    };
                    IntPtr policyPtr = Marshal.AllocHGlobal(Marshal.SizeOf(acc));
                    try
                    {
                        Marshal.StructureToPtr(acc, policyPtr, false);
                        var data = new NativeGlass.WINDOWCOMPOSITIONATTRIBDATA
                        {
                            Attribute  = 19,    // WCA_ACCENT_POLICY
                            Data       = policyPtr,
                            SizeOfData = Marshal.SizeOf(acc),
                        };
                        NativeGlass.SetWindowCompositionAttribute(hwnd, ref data);
                        // 亚克力需要半透明底才能透出来
                        if (Background is SolidColorBrush)
                        {
                            Background = new SolidColorBrush(Color.FromArgb(0xE0, 0x0B, 0x0F, 0x1A));
                        }
                        PushEvent("[UI] 液态玻璃: Acrylic 模式 (Win10)");
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(policyPtr);
                    }
                }
            }
            catch
            {
                // 老系统/DWM 失效 → 仅保留 XAML 渐变玻璃卡
                PushEvent("[UI] 液态玻璃: 纯色玻璃 (系统 DWM 不可用)");
            }
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
                KickBtn.IsEnabled = false;
                return;
            }

            string host = HostBox.Text.Trim();
            // BUG-10 修复: int.Parse 未捕获 FormatException, 改用 TryParse
            if (!int.TryParse(PortBox.Text.Trim(), out int port) || port < 1 || port > 65535) {
                MessageBox.Show("端口必须是 1-65535 的数字", "端口无效");
                return;
            }
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

            // 傻瓜式 TLS: 永远勾着, 用户不用懂指纹. 第一次连接自动钉 (TOFU);
            // 之后指纹对不上即拒, 防 MITM. 失败时提示用户可改明文重试.
            bool usePlaintext = false;

retry_connect:
            _session = new ChatSessionV2(host, port, _identityKey);
            _session.UseTls = !usePlaintext;
            _session.AllowSelfSigned = false;
            _session.ServerCertSha256 = null;   // TOFU 模式

            _session.OnTofuCert = (h, sha, firstSeen) => Dispatcher.BeginInvoke(() =>
            {
                if (firstSeen)
                    PushEvent($"[TLS/TOFU] 首次见到 {h} 的证书指纹: {sha[..12]}… 已自动钉定");
                else
                    PushEvent($"[TLS] 证书指纹吻合: {sha[..12]}…");
            });

            if (!usePlaintext && !string.IsNullOrEmpty(RoomBox.Text.Trim()))
            {
                // 预先通知: 连不上会提示可退回明文
                PushEvent("[TLS] 启用 wss 加密 + TOFU 证书钉定. 服务器不支持 TLS 时会提示回退.");
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
                        // F5: 房主才显示可踢人; 更新踢出按钮状态
                        if (_session?.IsOwner == true) {
                            PushEvent("[房主] 你是本房房主, 可踢出其他成员 (踢出后 10 分钟禁入)");
                        }
                        UpdateKickButtonState();
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

            // F5: 成员列表选中变化时更新踢人按钮状态
            MembersList.SelectionChanged += (s, e) => UpdateKickButtonState();

            // F5: 本用户被房主踢出
            _session.OnKicked += (reason) =>
            {
                Dispatcher.Invoke(() =>
                {
                    PushEvent($"[⚠ 被踢出] {reason}. 10 分钟内不可再加入该房.");
                    ConnStatus.Text = "● 已被房主踢出";
                    ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                    SendBtn.IsEnabled = false;
                    KickBtn.IsEnabled = false;
                    ConnBtn.Content = "连接";
                    ConnBtn.Background = (SolidColorBrush)new BrushConverter().ConvertFrom("#89b4fa");
                    MembersList.Items.Clear();
                    // 释放已断的会话, 让用户点一次"连接"即可重连 (无需先清理死会话).
                    // 服务器已 disconnect 本 sid, 此处 Dispose 只是回收本地资源.
                    _session?.Dispose();
                    _session = null;
                    System.Windows.MessageBox.Show(
                        "你已被房主踢出该房间.\n\n10 分钟内不可再加入此房.\n" +
                        "如需重新加入, 请等待 10 分钟后重试.",
                        "被踢出房间",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                });
            };

            // F5: 房内另一成员被踢出 — 从成员列表移除
            _session.OnMemberKicked += (kickedSid) =>
            {
                Dispatcher.Invoke(() =>
                {
                    var item = MembersList.Items.OfType<ListBoxItem>().FirstOrDefault(x =>
                        x.Tag is ValueTuple<string, string> t && t.Item1 == kickedSid);
                    if (item != null) MembersList.Items.Remove(item);
                    PushEvent($"[成员] 被房主踢出 → sid={kickedSid}");
                });
            };

            // F5: 踢人操作结果
            _session.OnKickResult += (ok, reason) =>
            {
                Dispatcher.Invoke(() =>
                {
                    if (ok)
                        PushEvent("[踢人] 成功: 目标已被移出房间并 10 分钟禁入");
                    else
                        PushEvent($"[踢人] 失败: {reason}");
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
                string hint = ex switch
                {
                    System.Net.WebSockets.WebSocketException wse when (wse.WebSocketErrorCode == System.Net.WebSockets.WebSocketError.NotAWebSocket)
                        => "服务器在线但握手被拒 (HTTP 状态非 101).\n可能: 服务器没跑 socket.io / URL 不对",
                    System.Net.WebSockets.WebSocketException
                        => "WebSocket 无法建立连接.\n常见原因: 服务器没启动 / 端口被防火墙拦",
                    System.Security.Authentication.AuthenticationException
                        => "TLS 证书不匹配.\n· 服务器换了证书 → 这是 TOFU 防伪正常行为, 先确认服务器是否真的换了证书\n· 如果确实换了, 删 %LOCALAPPDATA%\\E2EChatClient\\tofu_pins.json 再试",
                    _ => ex.Message,
                };
                ConnStatus.Text = "● 连接失败: " + hint.Split('\n')[0];
                ConnStatus.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#f38ba8");
                PushEvent("[连接失败] " + hint);

                _session?.Dispose();
                _session = null;

                // wss 失败 → 询问是否回落到明文 ws://
                if (!usePlaintext)
                {
                    var ans = System.Windows.MessageBox.Show(
                        "加密连接失败。\n\n" +
                        hint + "\n\n" +
                        "要改用明文 ws:// 再试吗? (不安全, 消息可能被窃听)",
                        "要回退明文吗",
                        System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Question,
                        System.Windows.MessageBoxResult.No);
                    if (ans == System.Windows.MessageBoxResult.Yes) {
                        usePlaintext = true;
                        PushEvent("[回退] 用户选择明文 ws 重试");
                        goto retry_connect;
                    }
                }
                return;
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
            // 液晶玻璃气泡: 自己 = 柔绿高光, 对方 = 白带细描边
            Border bubble = new()
            {
                Background = (SolidColorBrush)new BrushConverter().ConvertFrom(incoming ? "#33FFFFFF" : "#668FE6A8"),
                BorderBrush = (SolidColorBrush)new BrushConverter().ConvertFrom(incoming ? "#40FFFFFF" : "#80FFFFFF"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(12, 8, 12, 8),
                Margin = new Thickness(0, 0, 0, 8),
                HorizontalAlignment = incoming ? HorizontalAlignment.Left : HorizontalAlignment.Right,
            };
            TextBlock header = new()
            {
                Text = name,
                Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#BFCCD8"),
                FontSize = 10,
                Margin = new Thickness(0, 0, 0, 3),
            };
            TextBlock body = new()
            {
                Text = text,
                Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom(incoming ? "#F2F6FF" : "#0B0F1A"),
                TextWrapping = TextWrapping.Wrap,
                MaxWidth = 560,
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
            // F5-identity: 持久化身份密钥由 MainWindow 拥有生命周期, 窗口关闭时 zeroize
            _identityKey.Dispose();
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
            // BUG-10 修复: 同 ConnBtn_Click, 用 TryParse 防崩溃
            if (!int.TryParse(PortBox.Text.Trim(), out int port) || port < 1 || port > 65535) {
                MessageBox.Show("端口必须是 1-65535 的数字", "端口无效");
                return;
            }
            using var creator = new ChatSessionV2(host, port, _identityKey);
            // TOFU: 创建房间也走加密, 0 配置
            creator.UseTls = true;
            creator.AllowSelfSigned = false;
            creator.ServerCertSha256 = null;
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
                MessageBox.Show($"创建失败. 可能: 房间名已被他人占用 / id_sig 无效 / 服务器未启 / 服务器不支持 wss.",
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

        // ============================================================
        //  F5: 房主踢人
        // ============================================================
        private void KickBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_session == null || !_session.IsOwner) {
                MessageBox.Show("仅房主可踢人.", "无权限", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            string? targetSid = null;
            if (MembersList.SelectedItem is ListBoxItem li
                && li.Tag is ValueTuple<string, string> tag) {
                targetSid = tag.Item1;
            }
            if (string.IsNullOrEmpty(targetSid)) {
                MessageBox.Show("请先在成员列表中选中要踢出的成员.",
                                "未选中成员", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            // 二次确认
            var result = MessageBox.Show(
                $"确定踢出成员 sid={targetSid}?\n\n该成员将被立即断开, 且 10 分钟内不可再加入本房.",
                "确认踢出", MessageBoxButton.YesNo, MessageBoxImage.Question,
                MessageBoxResult.No);
            if (result != MessageBoxResult.Yes) return;

            _session.KickMember(targetSid);
            PushEvent($"[踢人] 已发起: 目标 sid={targetSid}");
        }

        /// <summary>
        /// F5: 更新踢人按钮可用状态 — 仅房主 + 已选中某成员时可用.
        /// </summary>
        private void UpdateKickButtonState()
        {
            bool canKick = _session != null
                           && _session.IsOwner
                           && MembersList.SelectedItem is ListBoxItem;
            KickBtn.IsEnabled = canKick;
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
