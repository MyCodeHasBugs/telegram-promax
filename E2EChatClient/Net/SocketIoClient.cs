using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;       // BCL 内置 (System.Net.WebSockets)
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Generic;

namespace E2EChatClient.Net
{
    /// <summary>
    /// 服务器协议: python-socketio 5.x AsyncServer (uvicorn ASGI),
    /// 通过 engine.io v4/SIO v5 接入.
    /// WebSocket 握手路径:  ws://host:32759/socket.io/?EIO=4&transport=websocket
    /// 本类手写 socket.io v5 over WebSocket (不引第三方库),
    /// 仅支持项目实际用到的消息类型:
    ///   open / auth / auth_response / new_member / new_member_request / relay_message
    ///   chat_message / typing / server_event / disconnect / heartbeat / heartbeat_ack
    ///   who_online / online_list / client_error / connect / error
    ///
    /// Engine.io packet types (v4):
    ///   0 open,1 close,2 ping,3 pong,4 message
    /// Socket.io packet types (v5):
    ///   0 connect,1 disconnect,2 event,3 ack,4 error,5 binary event,6 binary ack
    /// </summary>
    public class SocketIoClient : IDisposable
    {
        public string ServerHost { get; private set; }
        public int ServerPort { get; private set; }
        public string Namespace { get; private set; } = "/";
        // 是否启用 TLS (wss://). 默认 false 与旧版本兼容; 显式开启后用 wss://.
        // 自签证书校验回调: 服务器证书指纹比对 (SHA256 of DER) / 临时阶段容许任意自签
        public bool UseTls { get; set; } = false;
        // 允许自签证书 — 默认 **false** (严格指纹锁)
        // 开发期 / 内网部署 设置 AllowSelfSigned=true 才接受任意自签证书
        public bool AllowSelfSigned { get; set; } = false;
        public string? ServerCertSha256 { get; set; } // hex, 可选校验指纹

        public event Action<string, JsonElement>? OnEvent;
        public event Action<string>? OnError;
        public event Action<bool, string>? OnAuthResult;
        public event Action? OnConnected;
        public event Action<string>? OnDisconnected;

        private ClientWebSocket _ws = new();
        private CancellationTokenSource _cts = new();
        private Task? _recvTask;
        private Task? _pingTask;

        // ack id 映射
        private static int _nextAck = 1;
        private readonly ConcurrentDictionary<int, TaskCompletionSource<JsonElement>> _acks =
            new();

        private readonly string _sidPath;   // engine.io 路径

        public SocketIoClient(string host = "127.0.0.1", int port = 32759, string ns = "/")
        {
            ServerHost = host;
            ServerPort = port;
            Namespace = ns;
            _sidPath = $"/socket.io/?EIO=4&transport=websocket";
        }

        // 客户端身份闸门 token (与 server 硬编码常量一致), 浏览器/通用 sio 客户端不会带
        // 这个 header, server 在 connect 时检查不通过直接拒. 挡浏览器直连 / Postman / curl
        public const string CLIENT_GATE_TOKEN = "E2EChat/v2/client-auth-token-3f8a7c1d9b5e4d2a";

        public async Task ConnectAsync()
        {
            string scheme = UseTls ? "wss" : "ws";
            var url = new Uri($"{scheme}://{ServerHost}:{ServerPort}{_sidPath}");

            // 方案 A: 客户端身份闸门. 浏览器/socketio-default 不带自定义 header -> server 拒
            _ws.Options.SetRequestHeader("X-E2EChat-Client", CLIENT_GATE_TOKEN);

            // TLS: 配置 RemoteCertificateValidationCallback
            // - AllowSelfSigned=true: 接受任意自签 (开发期 / 内网部署)
            // - AllowSelfSigned=false + ServerCertSha256: 严格指纹校验 (队形 pin)
            if (UseTls) {
                _ws.Options.RemoteCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => {
                    if (cert == null) return false;
                    if (AllowSelfSigned) return true;
                    if (string.IsNullOrEmpty(ServerCertSha256) || cert == null) return false;
                    // 计算 DER SHA256
                    using var sha = System.Security.Cryptography.SHA256.Create();
                    byte[] der = cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
                    string hashHex = BitConverter.ToString(sha.ComputeHash(der)).Replace("-", "").ToLowerInvariant();
                    return hashHex == ServerCertSha256;
                };
            }

            await _ws.ConnectAsync(url, _cts.Token);
            _recvTask = Task.Run(ReceiveLoop, _cts.Token);
            _pingTask  = Task.Run(PingLoop,   _cts.Token);
        }

        // ===== 发送 =====
        public Task EmitAsync(string eventName, object payload, int? ackId = null)
        {
            // socket.io v5:  "42"[ackId][ns,]"["eventName"[,payload]"]"
            //   默认 namespace "/" 时省略 ns 部分
            string nsPart = Namespace == "/" ? "" : $"{Namespace},";
            string body;
            if (payload == null)
                body = $"[\"{eventName}\"]";
            else
                body = $"[\"{eventName}\",{JsonSerializer.Serialize(payload)}]";

            string ackStr = ackId.HasValue ? ackId.Value.ToString() : "";
            string packet = $"42{ackStr}{nsPart}{body}";
            return SendRawAsync(packet);
        }

        public Task<JsonElement> EmitWithAckAsync(string eventName, object payload, int timeoutMs = 5000)
        {
            int ack = Interlocked.Increment(ref _nextAck);
            var tcs = new TaskCompletionSource<JsonElement>();
            _acks[ack] = tcs;
            string nsPart = Namespace == "/" ? "" : $"{Namespace},";
            string body;
            if (payload == null)
                body = $"[\"{eventName}\"]";
            else
                body = $"[\"{eventName}\",{JsonSerializer.Serialize(payload)}]";

            string packet = $"42{ack}{nsPart}{body}";
            _ = SendRawAsync(packet);

            var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            cts.CancelAfter(timeoutMs);
            _ = Task.Run(async () =>
            {
                try
                {
                    using (cts.Token.Register(() => tcs.TrySetCanceled()))
                    {
                        await tcs.Task;
                    }
                }
                catch { _acks.TryRemove(ack, out _); }
            });
            return tcs.Task;
        }

        private async Task SendRawAsync(string text)
        {
            if (_ws.State != WebSocketState.Open) return;
            byte[] data = Encoding.UTF8.GetBytes(text);
            await _ws.SendAsync(data, WebSocketMessageType.Text, true, _cts.Token);
        }

        // ===== 接收 =====
        private async Task ReceiveLoop()
        {
            ArraySegment<byte> buffer = new byte[16 * 1024];
            using MemoryStream accumulate = new MemoryStream();

            try
            {
                while (_ws.State == WebSocketState.Open && !_cts.IsCancellationRequested)
                {
                    WebSocketReceiveResult recv;
                    do
                    {
                        recv = await _ws.ReceiveAsync(buffer, _cts.Token);
                        if (recv.MessageType == WebSocketMessageType.Close)
                        {
                            OnDisconnected?.Invoke(recv.CloseStatusDescription ?? "closed");
                            return;
                        }
                        accumulate.Write(buffer.Array!, buffer.Offset, recv.Count);
                    } while (!recv.EndOfMessage);

                    byte[] full = accumulate.ToArray();
                    accumulate.SetLength(0);
                    if (full.Length == 0) continue;

                    HandleFrame(Encoding.UTF8.GetString(full));
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                OnError?.Invoke(ex.Message);
            }
        }

        private async Task PingLoop()
        {
            while (!_cts.IsCancellationRequested && _ws.State == WebSocketState.Open)
            {
                await Task.Delay(25000);
                if (_ws.State != WebSocketState.Open) break;
                // engine.io ping: packet "2"
                try { await SendRawAsync("2"); }
                catch { }
            }
        }

        private void HandleFrame(string frame)
        {
            if (string.IsNullOrEmpty(frame)) return;
            char engineType = frame[0];
            switch (engineType)
            {
                case '0':   // open - 收到 engine.io 的握手 payload
                    // 解析 sid, 发一个 socket.io "40" connect 包
                    _ = SendRawAsync($"40{Namespace}");
                    break;
                case '2':   // engine.io ping - 立刻回 pong
                    _ = SendRawAsync("3");
                    break;
                case '3':   // engine.io pong
                    break;

                case '4':   // 主要消息路径
                    HandlSioPacket(frame);
                    break;

                case '1':   // close
                    _ = DisconnectAsync("server closed");
                    break;
            }
        }

        private void HandlSioPacket(string frame)
        {
            if (frame.Length < 2) return;
            char sioType = frame[1];
            switch (sioType)
            {
                case '2':   // event
                    DispatchEvent(frame.Substring(2));
                    break;
                case '0':   // connect
                    OnConnected?.Invoke();
                    break;
                case '1':   // sio disconnect (服务器主动断开)
                    OnDisconnected?.Invoke($"sio disconn namespace={frame.Substring(2)}");
                    break;
                case '3':   // ack
                    // 43<ackId>[payload]
                    TryDispatchAck(frame.Substring(2));
                    break;
                case '4':
                    if (frame.Length > 2) OnOpcodeError?.Invoke($"sio error: {frame.Substring(2)}");
                    break;
            }
        }

        public event Action<string>? OnOpcodeError;

        private void DispatchEvent(string rest)
        {
            // rest = ["eventName",$payload]   (ack id 已不存在,因为 这是 server → client)
            // 也可能是 "namespace,[\"eventName\",{...}]" —  我们默认 /
            // 直接 parse as JSON array
            try
            {
                using var doc = JsonDocument.Parse(rest);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) return;
                var arr = doc.RootElement.EnumerateArray();
                if (!arr.MoveNext()) return;
                string evName = arr.Current.GetString() ?? "";
                JsonElement? payload = null;
                if (arr.MoveNext()) payload = arr.Current;

                if (evName == "auth_response")
                    OnAuthResult?.Invoke(payload.HasValue && payload.Value.TryGetProperty("ok", out var ok) && ok.GetBoolean(),
                                         payload.HasValue ? payload.Value.GetRawText() : "");
                OnEvent?.Invoke(evName, payload ?? default);
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"parse event: {ex.Message}");
            }
        }

        private void TryDispatchAck(string rest)
        {
            // 格式: <ackId>["array",...]
            int i = 0;
            while (i < rest.Length && char.IsDigit(rest[i])) i++;
            if (i == 0) return;
            if (!int.TryParse(rest.Substring(0, i), out int ackId)) return;
            if (!_acks.TryRemove(ackId, out var tcs)) return;
            try
            {
                using var doc = JsonDocument.Parse(rest.Substring(i));
                if (doc.RootElement.ValueKind == JsonValueKind.Array &&
                    doc.RootElement.EnumerateArray().MoveNext())
                {
                    var first = doc.RootElement.EnumerateArray().Current;
                    tcs.TrySetResult(first);
                }
                else tcs.TrySetResult(default);
            }
            catch (Exception ex) { tcs.TrySetException(ex); }
        }

        public async Task DisconnectAsync(string reason = "client closed")
        {
            try
            {
                if (_ws.State == WebSocketState.Open)
                    await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, reason, CancellationToken.None);
            }
            catch { }
            OnDisconnected?.Invoke(reason);
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _ws.Dispose(); } catch { }
        }
    }
}
