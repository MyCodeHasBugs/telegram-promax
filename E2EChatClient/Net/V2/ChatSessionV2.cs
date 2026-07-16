// V2 — Signal-style 端对端会话层 (真 Double Ratchet + 重放防御)
// 服务器: server_v2.py (BLAKE3 校验, "三不"原则, 无日志文件)
//
// 客户端做的事:
//   * 握手用 ephemeral X25519, 同时作为 ratchet 的初始 DH keypair (私钥注入 ratchet)
//   * 每个对端维护一个 DoubleRatchet 实例 (真 DH 棘轮 + 对称棘轮 + skipped keys)
//   * 每条消息 envelope 增 dh_pub 字段, 收方据此决定是否切换 DH
//   * 每条消息发送前:
//      1) 若对端上次发的 dh_pub 与我方记录的 peerDhPub 不同 => 先 DhRatchetForSend 切换
//      2) ratchet.RatchetForSend() -> msgKey32B
//      3) XChaCha20-Poly1305.Encrypt(key=msgKey, nonce=随机24B, plaintext, aad=epub)
//      4) ct_b64 = Base64(cipher); blake3 = BLAKE3(ct_b64_utf8_bytes) hex
//      5) Ed25519 签名 (签 cipher 原始字节)
//      6) envelope JSON: { epub, id, dh_pub, ct, sig, b3, n }
//      7) WrapWithLengthHeader -> 512B 定长分片 + 0~150ms 抖动
//   * 收到 chat_slice:
//      1) Reassembler 累积分片, 收齐后返回完整 envelope bytes
//         (Reassembler 已含 30s 超时清理 + 256 表上限, 防内存 DoS)
//      2) 解析 envelope JSON
//      3) BLAKE3 自校 (对 ct_b64 字符串的 utf8 字节)
//      4) Ed25519 验签 (对 cipher 原始字节)
//      5) ratchet.TryRecv(theirDhPub=dh_pub, n)
//         - BadDhPub -> 丢
//         - Replay   -> 告警 + 丢
//         - GapTooLarge -> 告警 + 丢
//         - Accept   -> 解密
//      6) XChaCha20Poly1305.Decrypt(msgKey, cipher, aad=epub) -> plaintext
//      7) 调 OnMessageReceived

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using E2EChatClient.Crypto;
using E2EChatClient.CryptoV2;

namespace E2EChatClient.Net.V2
{
    public class ChatSessionV2 : IDisposable
    {
        private readonly SocketIoClient _io;
        // 去掉 readonly: Dispose 时需要 zeroize + 置 null, 防 dump 内存仍可读出字节
        // (readonly 字段可 zeroize 但不可置 null, GC 仍可读到全 0 buffer)
        private byte[]? _ephemeralPriv;
        private byte[]? _ephemeralPub;
        private readonly Ed25519Keypair _identityKey;
        private readonly string _ephemeralPubB64;
        private readonly string _identityPubB64;

        // peerSid -> DoubleRatchet
        private readonly ConcurrentDictionary<string, DoubleRatchet> _ratchets = new();
        // peerSid -> 对端 ephemeral pubkey bytes  (握手后获得)
        private readonly ConcurrentDictionary<string, byte[]> _peerPubs = new();
        // peerSid -> 对端 identity pubkey bytes  (首条消息后获得)
        private readonly ConcurrentDictionary<string, byte[]> _peerIdPubs = new();
        // peerSid -> 当前对端最近一次使用的 DH pub (用于检测 DH 是否轮换)
        private readonly ConcurrentDictionary<string, byte[]> _peerLastDhPub = new();

        // 分片重组器 + sid_seed -> sender_sid 映射
        private readonly TrafficObfuscator.Reassembler _reassembler = new();
        private readonly ConcurrentDictionary<ulong, string> _sliceSender = new();
        private readonly object _peerRegLock = new();

        public string MySid  { get; private set; } = "";
        public string Room    { get; private set; } = "";
        public string MyEphemeralPubB64 => _ephemeralPubB64;
        public string MyIdentityPubB64   => _identityPubB64;

        public event Action<string, string>? OnMessageReceived;
        public event Action<string>? OnServerEvent;
        public event Action<bool, string>? OnAuthResult;
        public event Action<string, string>? OnNewMember;

        // 暴露 SocketIoClient 的 TLS 选项, 透传给 UI/调用方配置
        public bool UseTls
        {
            get => _io.UseTls;
            set => _io.UseTls = value;
        }
        // 默认 false (严格指纹锁); 内网调试时显式设 true
        public bool AllowSelfSigned
        {
            get => _io.AllowSelfSigned;
            set => _io.AllowSelfSigned = value;
        }
        public string? ServerCertSha256
        {
            get => _io.ServerCertSha256;
            set => _io.ServerCertSha256 = value;
        }

        public ChatSessionV2(string host, int port, Ed25519Keypair? identityKey = null)
        {
            _io = new SocketIoClient(host, port);
            _identityKey = identityKey ?? Ed25519Keypair.Create();
            // 握手用 ephemeral X25519, 用完 (session 结束) zeroize
            // 密钥派生依赖系统级 CSPRNG (RandomNumberGenerator -> getrandom/BCryptGenRandom),
            // 严禁使用 MAC 地址/硬盘序列号/时间戳做种子
            _ephemeralPriv = Curve25519.GeneratePrivateKey();
            _ephemeralPub  = Curve25519.GeneratePublicKey(_ephemeralPriv);
            _ephemeralPubB64 = Convert.ToBase64String(_ephemeralPub);
            _identityPubB64 = Convert.ToBase64String(_identityKey.PublicKey ?? Array.Empty<byte>());

            _io.OnEvent += HandleEvent;
            _io.OnAuthResult += (ok, info) =>
            {
                try {
                    using var doc = JsonDocument.Parse(info);
                    if (doc.RootElement.TryGetProperty("sid",  out var sEl))  MySid = sEl.GetString() ?? "";
                    if (doc.RootElement.TryGetProperty("room", out var rEl))  Room = rEl.GetString() ?? "";

                    string hashAlgo = "BLAKE3";
                    if (doc.RootElement.TryGetProperty("hash_algo", out var hEl))
                        hashAlgo = hEl.GetString() ?? "BLAKE3";
                    if (hashAlgo != "BLAKE3")
                        OnServerEvent?.Invoke($"[warn] server hash_algo={hashAlgo} (not BLAKE3)");

                    if (doc.RootElement.TryGetProperty("members", out var mEl) && mEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var mem in mEl.EnumerateArray())
                        {
                            string? sid = mem.TryGetProperty("sid",  out var s2) ? s2.GetString() : null;
                            string? pk  = mem.TryGetProperty("epub", out var p2) ? p2.GetString() : null;
                            string? idPub = mem.TryGetProperty("id",   out var id2) ? id2.GetString() : null;
                            if (sid != null && pk != null)
                                RegisterPeer(sid, pk, idPub);
                        }
                    }
                } catch (Exception ex) { OnServerEvent?.Invoke("auth parse: " + ex.Message); }
                OnAuthResult?.Invoke(ok, info);
            };
            _io.OnError += msg => OnServerEvent?.Invoke("error: " + msg);
            _io.OnDisconnected += r => OnServerEvent?.Invoke("disconnected: " + r);
        }

        /// <summary>
        /// 房间列表条目 (供 UI 列表展示 + 选择加入).
        /// </summary>
        public sealed class RoomInfo
        {
            public string Name { get; init; } = "";
            public bool   HasPassword { get; init; }
            public int    MemberCount { get; init; }
        }

        /// <summary>
        /// 房间列表到达事件: UI 据此展示可选房间 (服务端 response "room_list" 事件).
        /// </summary>
        public event Action<IReadOnlyList<RoomInfo>>? OnRoomList;

        public async Task<bool> AuthAsync(string room, string? roomPassword = null, int timeoutMs = 8000)
        {
            await _io.ConnectAsync();

            string b3 = Blake3Hash.HashHex(Encoding.UTF8.GetBytes(_ephemeralPubB64));
            // F2: 用 Ed25519 身份签名绑定 epub (防 MITM 篡改 new_member.epub, 原
            // 先 ws 明文 + 无绑定的 id_pub 字段 -> attacker 可改 epub 即可 MITM 棘轮)
            // 签名内容 = bytes(epub_b64 || room), 让 server 验证 scoping 防跨房重放
            byte[] sigInput = Encoding.UTF8.GetBytes(_ephemeralPubB64 + "@" + room);
            byte[] idSig    = _identityKey.Sign(sigInput);

            var tcs = new TaskCompletionSource<bool>();
            Action<bool, string> oneShot = null!;
            oneShot = (ok, _) => {
                tcs.TrySetResult(ok);
                _io.OnAuthResult -= oneShot;
            };
            _io.OnAuthResult += oneShot;

            // F3-4 房间准入: 若房间有密码, room_password 一并送. 服务端 BLAKE3(password) 比对.
            _ = _io.EmitAsync("auth", new
            {
                epub         = _ephemeralPubB64,
                room         = room,
                id           = _identityPubB64,
                id_sig       = Convert.ToBase64String(idSig),
                blake3       = b3,
                room_password = roomPassword ?? "",
            });

            var winner = await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs));
            if (winner != tcs.Task) return false;
            return await tcs.Task;
        }

        /// <summary>
        /// 请求服务端发当前可用房间列表 (服务端会 emit "room_list" 事件, 由 HandleEvent 路由到 OnRoomList).
        /// </summary>
        public void RequestRoomList()
        {
            _io.EmitAsync("list_rooms", new { });
        }

        /// <summary>
        /// 创建有密码的新房间. 服务端记录此 sid 为 owner, 房间空了自动清. 返回是否成功
        /// (同步等待 server create_room_result 事件, 带 owner 可后续踢人/锁门; 本版仅做密码门槛).
        /// </summary>
        public async Task<bool> CreateRoomAsync(string room, string? password, int timeoutMs = 4000)
        {
            // 密码可选(空 = 公开房间); 非空则服务端记 BLAKE3(password).
            await _io.ConnectAsync();

            string b3 = Blake3Hash.HashHex(Encoding.UTF8.GetBytes(_ephemeralPubB64));
            byte[] sigInput = Encoding.UTF8.GetBytes(_ephemeralPubB64 + "@" + room);
            byte[] idSig    = _identityKey.Sign(sigInput);

            var tcs = new TaskCompletionSource<bool>();
            void OnCreated(bool ok, string _info) { tcs.TrySetResult(ok); _io.OnAuthResult -= OnCreated; }
            _io.OnAuthResult += OnCreated;

            _ = _io.EmitAsync("create_room", new
            {
                epub         = _ephemeralPubB64,
                room         = room,
                id           = _identityPubB64,
                id_sig       = Convert.ToBase64String(idSig),
                blake3       = b3,
                room_password = password ?? "",
            });

            var winner = await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs));
            return winner == tcs.Task && await tcs.Task;
        }

        public void NotifyRoomIAmHere()
        {
            _io.EmitAsync("new_member_request", new { });
        }

        /// <summary>
        /// 注册对端 + 派生棘轮
        /// 会话层把 ephemeralPriv 注入 ratchet 作 DH 私钥, 与 ephemeralPub 配套.
        /// F2: peerIdB64 来自服务端 new_member 广播 (服务端已验过 id_sig 与 epub 绑定).
        ///     本地仅作 TOFU 缓存: 后续消息层 Ed25519 验签必须用相同 id_pub, 否则拒.
        /// </summary>
        private void RegisterPeer(string peerSid, string epubB64, string? peerIdB64 = null)
        {
            if (_ephemeralPriv == null || _ephemeralPub == null)
                throw new ObjectDisposedException(nameof(ChatSessionV2));
            byte[] epub = Convert.FromBase64String(epubB64);
            _peerPubs[peerSid] = epub;
            // 先 X25519 校验 (低阶点攻击防御 — 已在 Curve25519 内部强制)
            byte[] shared = Curve25519.ComputeSharedSecret(_ephemeralPriv, epub);
            var r = new DoubleRatchet(shared, _ephemeralPub, epub);
            r.SetMyDhPriv(_ephemeralPriv);
            _ratchets[peerSid] = r;
            _peerLastDhPub[peerSid] = epub;
            CryptographicOperations.ZeroMemory(shared);
            // F2: 缓存对端 id_pub (TOFU), 后续消息的 Ed25519 验签必须用同一 id_pub
            // F4-2: 已有 id_pub 时不覆盖, 否则 race 下后到的伪 id 会顶掉真 id.
            if (!string.IsNullOrEmpty(peerIdB64)) {
                try {
                    byte[] idBytes = Convert.FromBase64String(peerIdB64);
                    if (idBytes.Length == 32)
                        _peerIdPubs.TryAdd(peerSid, idBytes);
                } catch (FormatException) {
                    // 坏 base64 不致命: 仅放弃此次预钉, 后续消息层按 TOFU 钉
                }
            }
            OnNewMember?.Invoke(peerSid, epubB64);
        }

        // ============================================================
        //  发送
        // ============================================================
        public async Task SendMessageAsync(string text, string targetSid = "ALL")
        {
            if (_peerPubs.IsEmpty) {
                OnServerEvent?.Invoke("no peers registered yet");
                return;
            }

            var targets = targetSid == "ALL"
                ? new List<string>(_peerPubs.Keys)
                : new List<string> { targetSid };

            byte[] plaintext = Encoding.UTF8.GetBytes(text);

            foreach (var sid in targets)
            {
                if (!_ratchets.TryGetValue(sid, out var ratchet)) continue;

                // 1) 检测对端 DH pub 是否发生轮换 (我方记录的 _peerLastDhPub != ratchet.PeerDhPub => 已轮换)
                //    若已轮换: 我方也得轮换一次 (DhRatchetForSend)
                _peerLastDhPub.TryGetValue(sid, out var lastKnown);
                if (lastKnown != null && ratchet.PeerDhPub != null
                    && !BytesEqual(lastKnown, ratchet.PeerDhPub))
                {
                    ratchet.DhRatchetForSend(ratchet.PeerDhPub);
                    _peerLastDhPub[sid] = (byte[])ratchet.PeerDhPub.Clone();
                }

                // 2) 棘轮派生 msg_key
                byte[] msgKey = ratchet.RatchetForSend();
                // 3) XChaCha20-Poly1305 加密 (aad = 我的 epub)
                byte[] nonce  = XChaCha20Poly1305.GenerateNonce();
                if (_ephemeralPub == null) { CryptographicOperations.ZeroMemory(msgKey); return; }
                byte[] cipher = XChaCha20Poly1305.Encrypt(msgKey, nonce, plaintext,
                                                          aad: _ephemeralPub);
                CryptographicOperations.ZeroMemory(msgKey);

                // 4) BLAKE3 完整性校验头 — 对 base64 字符串的 utf8 字节哈希 (与服务器一致)
                string ctB64 = Convert.ToBase64String(cipher);
                string b3 = Blake3Hash.HashHex(Encoding.UTF8.GetBytes(ctB64));

                // 5) Ed25519 签名. F3 修复: 不只签 cipher, 同时签 dh_pub + n,
                //    防止 MITM 改 envelope.dh_pub 让 ratchet 失同步 (DoS).
                //    签名内容 = SHA256(dh_pub_b64 || n || cipher_raw)
                //    (用 BLAKE3 摘要避免长明文签名, 同时复用 BLAKE3 实现)
                long msgN = ratchet.SendCounter - 1;
                byte[] myDhPubB64 = Encoding.UTF8.GetBytes(Convert.ToBase64String(ratchet.MyDhPub));
                byte[] nBe        = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)msgN));
                // 拼接 dh_pub_b64 || n_be(4) || cipher 为签名输入
                byte[] sigInput = new byte[myDhPubB64.Length + 4 + cipher.Length];
                Buffer.BlockCopy(myDhPubB64, 0, sigInput, 0, myDhPubB64.Length);
                Buffer.BlockCopy(nBe,        0, sigInput, myDhPubB64.Length, 4);
                Buffer.BlockCopy(cipher,     0, sigInput, myDhPubB64.Length + 4, cipher.Length);
                byte[] sig = _identityKey.Sign(sigInput);
                CryptographicOperations.ZeroMemory(sigInput);

                // 6) 构造 envelope (JSON) — 增加 dh_pub 字段
                var envelope = new
                {
                    epub   = _ephemeralPubB64,
                    id     = _identityPubB64,
                    dh_pub = Convert.ToBase64String(ratchet.MyDhPub),
                    ct     = ctB64,
                    sig    = Convert.ToBase64String(sig),
                    b3     = b3,
                    n      = msgN,  // 本次消息对应的 counter
                };
                byte[] envBytes = JsonSerializer.SerializeToUtf8Bytes(envelope);

                // 7) WrapWithLengthHeader (4B 长度 + JSON) -> 512B 定长分片
                byte[] wrapped = TrafficObfuscator.WrapWithLengthHeader(envBytes);
                byte[] sidSeed = TrafficObfuscator.GenerateSidSeed();
                var slices = TrafficObfuscator.Slice(wrapped, sidSeed);

                // 8) 每个分片单独 emit relay_slice + 0~150ms 抖动
                await TrafficObfuscator.SendWithJitter(slices, async pkt =>
                {
                    _ = _io.EmitAsync("relay_slice", new
                    {
                        target = sid,
                        data   = Convert.ToBase64String(pkt),
                    });
                    await Task.CompletedTask;
                });
            }

            await Task.CompletedTask;
        }

        // ============================================================
        //  接收
        // ============================================================
        private void HandleEvent(string evName, JsonElement payload)
        {
            switch (evName)
            {
                case "chat_slice":    HandleChatSlice(payload); break;
                case "chat_message":  HandleChatMessage(payload); break;
                case "new_member":    HandleNewMember(payload); break;
                case "server_event":  OnServerEvent?.Invoke(payload.GetRawText()); break;
                case "room_list":     HandleRoomList(payload); break;
                case "typing":        break;
                case "online_list":   break;
            }
        }

        private void HandleRoomList(JsonElement payload)
        {
            try {
                var list = new List<RoomInfo>();
                if (payload.ValueKind == JsonValueKind.Array) {
                    foreach (var it in payload.EnumerateArray()) {
                        string name = it.TryGetProperty("name", out var n) ? (n.GetString() ?? "") : "";
                        bool   hasPw = it.TryGetProperty("has_password", out var h) && h.GetBoolean();
                        int    mcnt = it.TryGetProperty("members", out var m) ? m.GetInt32() : 0;
                        if (!string.IsNullOrEmpty(name))
                            list.Add(new RoomInfo { Name = name, HasPassword = hasPw, MemberCount = mcnt });
                    }
                }
                OnRoomList?.Invoke(list);
            } catch (Exception ex) {
                OnServerEvent?.Invoke("room_list parse: " + ex.Message);
            }
        }

        private void HandleChatSlice(JsonElement payload)
        {
            try
            {
                string? from   = payload.TryGetProperty("from", out var f) ? f.GetString() : null;
                string? dataB64 = payload.TryGetProperty("data", out var d) ? d.GetString() : null;
                if (from == null || dataB64 == null) return;

                byte[] packet;
                try { packet = Convert.FromBase64String(dataB64); }
                catch { return; }

                if (packet.Length != TrafficObfuscator.HEADER_BYTES + TrafficObfuscator.SLICE_BYTES)
                    return;

                ulong sidSeed = 0;
                for (int i = 0; i < 8; i++) sidSeed |= ((ulong)packet[i]) << (i * 8);
                _sliceSender[sidSeed] = from;

                byte[]? complete = _reassembler.Push(packet);
                if (complete == null) return;

                _sliceSender.TryRemove(sidSeed, out var senderSid);
                if (senderSid == null) senderSid = from;

                ProcessEnvelope(senderSid, complete);
            }
            catch (Exception ex) {
                OnServerEvent?.Invoke("slice recv: " + ex.Message);
            }
        }

        private void ProcessEnvelope(string fromSid, byte[] envBytes)
        {
            try
            {
                using var doc = JsonDocument.Parse(envBytes);
                var root = doc.RootElement;

                string? fromEpub = root.TryGetProperty("epub", out var ep) ? ep.GetString() : null;
                string? ctB64     = root.TryGetProperty("ct",  out var ct) ? ct.GetString() : null;
                string? sigB64    = root.TryGetProperty("sig", out var sg) ? sg.GetString() : null;
                string? claimedB3 = root.TryGetProperty("b3",  out var b3) ? b3.GetString() : null;
                string? idPubB64  = root.TryGetProperty("id",  out var idEl) ? idEl.GetString() : null;
                string? dhPubB64  = root.TryGetProperty("dh_pub", out var dhEl) ? dhEl.GetString() : null;
                long n = root.TryGetProperty("n", out var nEl) && nEl.ValueKind == JsonValueKind.Number
                         ? nEl.GetInt64() : -1;

                if (fromEpub == null || ctB64 == null) return;

                byte[] cipher;
                try { cipher = Convert.FromBase64String(ctB64); }
                catch { return; }

                // 1) BLAKE3 自校 (对 ct_b64 字符串的 utf8 字节, 与发送方/服务器一致) — 强制
                if (string.IsNullOrEmpty(claimedB3))
                {
                    _io.EmitAsync("client_error", new { severity = "tamper",
                        detail = "missing b3 field" });
                    OnServerEvent?.Invoke("缺少完整性校验字段(b3): " + fromSid);
                    return;
                }
                {
                    string calcB3 = Blake3Hash.HashHex(Encoding.UTF8.GetBytes(ctB64));
                    if (calcB3 != claimedB3)
                    {
                        _io.EmitAsync("client_error", new { severity = "tamper",
                            detail = "blake3 mismatch" });
                        OnServerEvent?.Invoke("检测到篡改(BLAKE3): " + fromSid);
                        return;
                    }
                }

                // 2) Ed25519 验签准备 — 强制
                if (string.IsNullOrEmpty(sigB64) || string.IsNullOrEmpty(idPubB64))
                {
                    OnServerEvent?.Invoke("缺少签名/身份字段: " + fromSid);
                    return;
                }
                byte[] sig;
                byte[] idPubBytes;
                try {
                    sig = Convert.FromBase64String(sigB64);
                    idPubBytes = Convert.FromBase64String(idPubB64);
                } catch (FormatException ex) {
                    OnServerEvent?.Invoke($"Base64 解码失败: {ex.Message}");
                    return;
                }
                if (sig.Length != 64 || idPubBytes.Length != 32)
                {
                    OnServerEvent?.Invoke("签名(64B)/公钥(32B)长度非法: " + fromSid);
                    return;
                }

                // 3) 注册对端 (若尚未注册 — 服务器允许我们之前未注册的 sid 发来)
                if (!_peerPubs.TryGetValue(fromSid, out var epubBytes)) {
                    lock (_peerRegLock) {
                        if (!_peerPubs.TryGetValue(fromSid, out epubBytes))
                            RegisterPeer(fromSid, fromEpub);
                    }
                    if (!_ratchets.TryGetValue(fromSid, out _)) return;
                }
                if (!_ratchets.TryGetValue(fromSid, out var ratchet)) return;
                epubBytes = _peerPubs[fromSid];

                // 4) 双棘轮 TryRecv: 重放 / DH 校验 / n 校验
                byte[]? theirDhPub = null;
                if (dhPubB64 != null) {
                    try { theirDhPub = Convert.FromBase64String(dhPubB64); }
                    catch {
                        OnServerEvent?.Invoke("envelope.dh_pub 解析失败: " + fromSid);
                        return;
                    }
                }
                if (theirDhPub == null || theirDhPub.Length != 32) {
                    OnServerEvent?.Invoke("envelope.dh_pub 长度非法: " + fromSid);
                    return;
                }

                // 5) F3: Ed25519 验签, sig 覆盖 dh_pub_b64 || n_be(4) || cipher,
                //    防 MITM 改 envelope.dh_pub 让 ratchet 失同步
                {
                    byte[] dhPubB64Bytes = Encoding.UTF8.GetBytes(dhPubB64!);
                    byte[] nBe = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)n));
                    byte[] sigInput = new byte[dhPubB64Bytes.Length + 4 + cipher.Length];
                    Buffer.BlockCopy(dhPubB64Bytes, 0, sigInput, 0, dhPubB64Bytes.Length);
                    Buffer.BlockCopy(nBe,         0, sigInput, dhPubB64Bytes.Length, 4);
                    Buffer.BlockCopy(cipher,       0, sigInput, dhPubB64Bytes.Length + 4, cipher.Length);
                    bool sigOk = Ed25519Keypair.Verify(idPubBytes, sigInput, sig);
                    CryptographicOperations.ZeroMemory(sigInput);
                    if (!sigOk)
                    {
                        _io.EmitAsync("client_error", new { severity = "tamper",
                            detail = "ed25519 sig bad (or dh_pub/n tampered)" });
                        OnServerEvent?.Invoke("Ed25519 验签失败: " + fromSid);
                        return;
                    }
                }

                // 6) F4-2: Identity pinning. 首次见到该 sid 的 id_pub 时钉定;
                //    后续再收到不同 id_pub 即视为身份冒充, 直接拒.
                //    写入也走 _peerRegLock, 与 RegisterPeer 的首次写入互斥,
                //    防 check-then-act 竞态让首个到达的伪造 id 抢跑胜出.
                lock (_peerRegLock) {
                    if (_peerIdPubs.TryGetValue(fromSid, out var pinnedId)) {
                        if (!BytesEqual(pinnedId, idPubBytes)) {
                            _io.EmitAsync("client_error", new { severity = "tamper",
                                detail = "id_pub changed" });
                            OnServerEvent?.Invoke("身份钉定失败 (id_pub 不一致): " + fromSid);
                            return;
                        }
                    } else {
                        _peerIdPubs[fromSid] = idPubBytes;
                    }
                }

                var outcome = ratchet.TryRecv(theirDhPub, n);
                if (outcome.Verdict != RatchetVerdict.Accept) {
                    string desc = outcome.Verdict switch {
                        RatchetVerdict.Replay      => "重放嫌疑",
                        RatchetVerdict.GapTooLarge => "n 间隔过大 (DoS?)",
                        RatchetVerdict.BadDhPub    => "dh_pub 非法",
                        RatchetVerdict.DhMismatch  => "dh_pub 不一致",
                        _ => "unknown"
                    };
                    _io.EmitAsync("client_error", new { severity = "ratchet_" + outcome.Verdict.ToString().ToLowerInvariant(),
                        detail = outcome.Reason ?? desc });
                    OnServerEvent?.Invoke($"[{desc}] n={n} from={fromSid} ({outcome.Reason})");
                    return;
                }

                // 更新对端最近 DH pub (用于发送侧检测我方是否需要跟着轮换)
                if (!_peerLastDhPub.TryGetValue(fromSid, out var lastDh)
                    || !BytesEqual(lastDh, theirDhPub)) {
                    _peerLastDhPub[fromSid] = (byte[])theirDhPub.Clone();
                }

                // 5) 解密
                byte[] msgKey = outcome.MessageKey!;
                byte[] pt;
                try {
                    pt = XChaCha20Poly1305.Decrypt(msgKey, cipher, aad: epubBytes);
                } catch (CryptographicException) {
                    _io.EmitAsync("client_error", new { severity = "decrypt_failed",
                        detail = "XChaCha20 tag mismatch" });
                    OnServerEvent?.Invoke("XChaCha20 解密失败: " + fromSid);
                    CryptographicOperations.ZeroMemory(msgKey);
                    return;
                }
                CryptographicOperations.ZeroMemory(msgKey);

                string text = Encoding.UTF8.GetString(pt);
                OnMessageReceived?.Invoke(fromSid, text);
            }
            catch (Exception ex) {
                OnServerEvent?.Invoke("envelope: " + ex.Message);
            }
        }

        private void HandleChatMessage(JsonElement payload)
        {
            try
            {
                string? fromSid = payload.TryGetProperty("from", out var fs) ? fs.GetString() : null;
                if (fromSid == null) return;

                string? fromEpub = payload.TryGetProperty("epub", out var ep) ? ep.GetString() : null;
                string? ctB64     = payload.TryGetProperty("ct",  out var ct) ? ct.GetString() : null;
                string? sigB64    = payload.TryGetProperty("sig", out var sg) ? sg.GetString() : null;
                string? claimedB3 = payload.TryGetProperty("b3",  out var b3) ? b3.GetString() : null;
                string? idPubB64  = payload.TryGetProperty("id",  out var idEl) ? idEl.GetString() : null;
                string? dhPubB64  = payload.TryGetProperty("dh_pub", out var dhEl) ? dhEl.GetString() : null;
                long n = payload.TryGetProperty("n", out var nEl) && nEl.ValueKind == JsonValueKind.Number
                         ? nEl.GetInt64() : -1;

                if (fromEpub == null || ctB64 == null) return;

                byte[] cipher;
                try { cipher = Convert.FromBase64String(ctB64); }
                catch { return; }

                if (string.IsNullOrEmpty(claimedB3)) {
                    OnServerEvent?.Invoke("缺少完整性校验字段(b3): " + fromSid);
                    return;
                }
                {
                    string calcB3 = Blake3Hash.HashHex(Encoding.UTF8.GetBytes(ctB64));
                    if (calcB3 != claimedB3) {
                        OnServerEvent?.Invoke("检测到篡改(BLAKE3): " + fromSid);
                        return;
                    }
                }

                if (string.IsNullOrEmpty(sigB64) || string.IsNullOrEmpty(idPubB64)) {
                    OnServerEvent?.Invoke("缺少签名/身份字段: " + fromSid);
                    return;
                }
                byte[] sig;
                byte[] idPubBytes;
                try {
                    sig = Convert.FromBase64String(sigB64);
                    idPubBytes = Convert.FromBase64String(idPubB64);
                } catch (FormatException ex) {
                    OnServerEvent?.Invoke($"Base64 解码失败: {ex.Message}");
                    return;
                }
                if (sig.Length != 64 || idPubBytes.Length != 32) {
                    OnServerEvent?.Invoke("签名(64B)/公钥(32B)长度非法: " + fromSid);
                    return;
                }

                if (!_peerPubs.TryGetValue(fromSid, out var epubBytes)) {
                    lock (_peerRegLock) {
                        if (!_peerPubs.TryGetValue(fromSid, out epubBytes))
                            RegisterPeer(fromSid, fromEpub);
                    }
                    if (!_ratchets.TryGetValue(fromSid, out _)) return;
                }
                if (!_ratchets.TryGetValue(fromSid, out var ratchet)) return;
                epubBytes = _peerPubs[fromSid];

                byte[]? theirDhPub = null;
                if (dhPubB64 != null) {
                    try { theirDhPub = Convert.FromBase64String(dhPubB64); }
                    catch {
                        OnServerEvent?.Invoke("envelope.dh_pub 解析失败: " + fromSid);
                        return;
                    }
                }
                if (theirDhPub == null || theirDhPub.Length != 32) {
                    OnServerEvent?.Invoke("envelope.dh_pub 长度非法: " + fromSid);
                    return;
                }

                // F3: sig 覆盖 dh_pub_b64 || n_be(4) || cipher
                {
                    byte[] dhPubB64Bytes = Encoding.UTF8.GetBytes(dhPubB64!);
                    byte[] nBe = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder((int)n));
                    byte[] sigInput = new byte[dhPubB64Bytes.Length + 4 + cipher.Length];
                    Buffer.BlockCopy(dhPubB64Bytes, 0, sigInput, 0, dhPubB64Bytes.Length);
                    Buffer.BlockCopy(nBe,         0, sigInput, dhPubB64Bytes.Length, 4);
                    Buffer.BlockCopy(cipher,       0, sigInput, dhPubB64Bytes.Length + 4, cipher.Length);
                    bool sigOk = Ed25519Keypair.Verify(idPubBytes, sigInput, sig);
                    CryptographicOperations.ZeroMemory(sigInput);
                    if (!sigOk) {
                        OnServerEvent?.Invoke("Ed25519 验签失败: " + fromSid);
                        return;
                    }
                }
                // F4-2: identity pinning (写入走 _peerRegLock, 与 ProcessEnvelope / RegisterPeer 互斥)
                lock (_peerRegLock) {
                    if (_peerIdPubs.TryGetValue(fromSid, out var pinnedId2)) {
                        if (!BytesEqual(pinnedId2, idPubBytes)) {
                            OnServerEvent?.Invoke("身份钉定失败 (id_pub 不一致): " + fromSid);
                            return;
                        }
                    } else {
                        _peerIdPubs[fromSid] = idPubBytes;
                    }
                }

                var outcome = ratchet.TryRecv(theirDhPub, n);
                if (outcome.Verdict != RatchetVerdict.Accept) {
                    string desc = outcome.Verdict switch {
                        RatchetVerdict.Replay      => "重放嫌疑",
                        RatchetVerdict.GapTooLarge => "n 间隔过大 (DoS?)",
                        RatchetVerdict.BadDhPub    => "dh_pub 非法",
                        RatchetVerdict.DhMismatch  => "dh_pub 不一致",
                        _ => "unknown"
                    };
                    OnServerEvent?.Invoke($"[{desc}] n={n} from={fromSid} ({outcome.Reason})");
                    return;
                }
                if (!_peerLastDhPub.TryGetValue(fromSid, out var lastDh)
                    || !BytesEqual(lastDh, theirDhPub)) {
                    _peerLastDhPub[fromSid] = (byte[])theirDhPub.Clone();
                }

                byte[] msgKey = outcome.MessageKey!;
                byte[] pt;
                try { pt = XChaCha20Poly1305.Decrypt(msgKey, cipher, aad: epubBytes); }
                catch (CryptographicException) {
                    OnServerEvent?.Invoke("XChaCha20 解密失败: " + fromSid);
                    CryptographicOperations.ZeroMemory(msgKey);
                    return;
                }
                CryptographicOperations.ZeroMemory(msgKey);
                OnMessageReceived?.Invoke(fromSid, Encoding.UTF8.GetString(pt));
            }
            catch (Exception ex) {
                OnServerEvent?.Invoke("recv: " + ex.Message);
            }
        }

        private void HandleNewMember(JsonElement payload)
        {
            string? sid    = payload.TryGetProperty("sid",  out var s)  ? s.GetString()  : null;
            string? pk     = payload.TryGetProperty("epub", out var p) ? p.GetString()  : null;
            string? idPub  = payload.TryGetProperty("id",   out var i) ? i.GetString()  : null;
            if (sid == null || pk == null) return;
            if (!_peerPubs.ContainsKey(sid)) RegisterPeer(sid, pk, idPub);
            else OnNewMember?.Invoke(sid, pk);
        }

        public async Task LeaveAsync()
        {
            await _io.DisconnectAsync("user leave");
        }

        static bool BytesEqual(byte[] a, byte[] b) {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        public void Dispose()
        {
            foreach (var kv in _ratchets) kv.Value.Dispose();
            _ratchets.Clear();
            _peerPubs.Clear();
            _peerIdPubs.Clear();
            _peerLastDhPub.Clear();
            _sliceSender.Clear();
            _identityKey.Dispose();
            // zeroize 原地, 然后置 null 防 dump
            // (readonly 阻止置 null, 故字段不再是 readonly)
            if (_ephemeralPriv != null) {
                CryptographicOperations.ZeroMemory(_ephemeralPriv);
                _ephemeralPriv = null;
            }
            if (_ephemeralPub != null) {
                CryptographicOperations.ZeroMemory(_ephemeralPub);
                _ephemeralPub = null;
            }
            _io.Dispose();
        }
    }
}
