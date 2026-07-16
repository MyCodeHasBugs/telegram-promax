# E2E 加密聊天 — 安全复审报告（第二次分析）

> 对比对象：`security_analysis.md`（首次分析）
> 复审范围：server_v2.py / cryptolib / E2EChatClient 全部 C# 源码 / 启动脚本 / 证书生成 / 探针脚本
> 结论概述：**首次报告里的 CRITICAL（低阶点攻击）和 HIGH（跨房间投递）已经被正确修复**。原语的密码学实现依然扎实。但传输层与会话绑定层仍有可被利用的漏洞，其中最重要的是「**没有经过认证的密钥交换**」——在默认不开启 TLS 的前提下，网络中间人可以在不破解任何密钥的情况下彻底击穿所谓"端到端"的保密性与真实性。

---

## 一、与首次报告的对照（已修复项）

| 首次报告 | 现状 | 验证 |
|---|---|---|
| 🔴 CRITICAL：X25519 不校验对端公钥（低阶点） | ✅ **已修复且正确** | `Curve25519.cs:46-95` 现在 `ComputeSharedSecret` 先调 `IsValidPublicKey`，用 `X25519(scalar=8, pub)` 结果为全 0 来判定 pub 落在小阶子群（RFC 7748 §6.1 标准的 cofactor 校验法），并叠加 `IsAllZero` 检查。逻辑正确。 |
| 🟠 HIGH：跨房间投递（房间隔离失效） | ✅ **已修复且正确** | `server_v2.py:270-284` 与 `:319-331` 在 `relay_message`/`relay_slice` 定向投递时校验 `target_session.room == me["room"]`，不符则踢+断连。`probe_crossroom.py` 即为此修复的回归探针。 |
| 🟠 HIGH：默认明文 + 证书校验默认关闭 | ⚠️ **部分修复，但 GUI 把它又打开了** | `SocketIoClient.cs:39` `AllowSelfSigned` 默认已改为 `false`（严格指纹锁），证书锁定逻辑本身正确。但 `MainWindow.xaml.cs:68-71` 在用户勾选"TLS"时把 `AllowSelfSigned` 重新设回 `true`（见 F1）。 |
| 🟡 MEDIUM：Reassembler 内存 DoS | 🟡 **缓解但未根除** | 新增 `MAX_PARTIAL_TABLE=256`/`PARTIAL_TIMEOUT_SEC=30`/`MAX_MESSAGE_SIZE=1MB`，但 `total` 预分配放大仍在（见 F4）。 |

> 密码学原语（XChaCha20-Poly1305 / Poly1305 / HChaCha20 / Double Ratchet 的 HKDF 对称棘轮 / Ed25519 走 NSec·libsodium / BLAKE3）经逐行复核与 RFC 8439、Signal 规范一致；每条消息用全新随机 24B nonce + 唯一 msg_key，无 nonce 重用。原语层面没有发现可利用缺陷。

---

## 二、新发现 / 仍存在且可被利用的漏洞（按可利用性排序）

### F1 — HIGH（真实可达）：GUI 里勾选"TLS"反而关闭了证书校验
**位置**：`MainWindow.xaml.cs:68-71`
```csharp
if (TlsBox.IsChecked == true) {
    _session.UseTls = true;
    _session.AllowSelfSigned = true;   // ← 问题在这里
}
```
`SocketIoClient.cs:79` 的校验回调在 `AllowSelfSigned==true` 时**对任意证书都返回 true**。于是用户为了"更安全"而勾选的 TLS，实际变成了「**有加密、无认证**」——任何能在客户端与服务器之间摆位置的攻击者，只要亮出**任意**自签证书即可被接受，进而完整中间人。

更严重的是：**严格指纹锁路径（`ServerCertSha256`）在 GUI 里根本没有入口**，用户无论如何都走不到真正的证书锁定。这直接把"默认明文"和"TLS但信任任何人"两种不安全选项暴露给用户，安全选项反而不可达。

**利用**：网络中间人（同 Wi-Fi、运营商、企业代理）在客户端启用 TLS 时，出示自签证书 → 客户端接受 → 后续 F2 的全部攻击成立。
**修复**：勾选 TLS 时**不要**设 `AllowSelfSigned=true`；改为暴露"服务器证书 SHA256 指纹"输入框，落给 `ServerCertSha256`；留一个显式的"开发期信任自签"复选框（默认不勾）。

---

### F2 — HIGH（架构性）：没有"身份↔握手"绑定 + 传输无认证 = 网络中间人击穿端到端
**位置**：`server_v2.py`（`auth`/`new_member` 不绑定 `id`↔`epub`）、`ChatSessionV2.cs:357-386`（`id` 自证、无锚点）、`SocketIoClient.cs:36`（默认 `UseTls=false`）

每条消息用 Ed25519 对 `cipher` 签名，**但签名的公钥 `id` 是发送方在 envelope 里自选的字段**，服务器从不校验 `id` 与握手阶段广播的 X25519 `epub` 之间的关系；客户端也从不验证把 `epub` 绑到某个稳定身份的签名。也就是说，**Ed25519 签名只是证明"消息来自持有这个 Ed25519 私钥的人"，而这个人每次都可以换一把新钥匙自称新身份**——没有任何根信任。

在默认 `ws://`（无 TLS）下，网络中间人（无需破解任何密钥、只需能连到服务器）可以：
1. 在明文 `new_member`/`auth_response` 里看到受害者的 `epub`；
2. 自己以成员身份连入房间，拿到自己的 sid；
3. 在线路上改写服务器下发给受害者的 `new_member`——把"Alice 的 sid"对应的 `epub` 替换成中间人的 `epub`（受害者侧 `RegisterPeer`/`HandleNewMember` 会照单全收）；
4. 之后受害者与"Alice 的 sid"之间的棘轮实际是和中间人算的，`epub`↔`id` 无任何绑定可被发现；中间人可做透明代理，**完整读取并篡改所有"端到端"消息**。

本质：这是一个**未经验证的 DH 密钥交换**。所有花哨的 Double Ratchet / XChaCha20 / Ed25519 都被"缺一个认证通道"这一件事清零。这正是 F1 里"TLS被打开却又信任任何人"会灾难化的根本原因。

**修复**：
- 默认强制 `wss` + 证书指纹锁（F1）；
- 握手阶段让 Ed25519 身份私钥**对 X25519 `epub` 签名**（如 `sig_id = Ed25519.sign(epub‖sid)`），服务器与对端在 `new_member`/`auth_response` 时校验，把 `id` 与 `epub` 密码学绑定；
- 客户端把"对方 `epub` 指纹"作为稳定身份展示，并提示用户比对带外指纹。

---

### F3 — MEDIUM：未签名的 `n` 与 `dh_pub` 可在主动攻击下让棘轮永久失同步（DoS）
**位置**：`ChatSessionV2.cs:233`（签名只覆盖 `cipher`）、`DoubleRatchet.cs:344-390`（按 `dh_pub` 做 DH 轮换）

Ed25519 只对 `cipher` 签名，**`n`（计数器）和 `dh_pub` 不在签名范围内**。主动攻击者（因 F1/F2 可达）改写中继 envelope 里的 `dh_pub`：
- `TryRecv`（`DoubleRatchet.cs:344`）把新的 `dh_pub` 当成对端换了 DH 公钥，先 drain 旧链，再用 `ECDH(myPriv, attacker_dh_pub)` 重派 root/chain——这条链攻击者自己都追不上；
- 受害者的 recv 链被永久 fork，此后该对端发来的**所有正常消息都解密失败**（可用性打击 / 被迫重新握手）；
- 改写 `n` 同样会触发 `GapTooLarge`/`Replay` 直接丢弃。

**修复**：把 `n`、`dh_pub`（以及 `epub`、`id`）一并纳入 Ed25519 签名范围，或对整个 envelope 做签名/MAC；任何头字段被篡改都应在验签阶段失败而非进棘轮逻辑。

---

### F4 — MEDIUM：Reassembler 的 `total` 预分配放大仍可造成内存压力 DoS
**位置**：`TrafficObfuscator.cs:121`（`Parts = new byte[total][]`）

首个分片到达时就按 envelope 里的 `total`（上限 `MAX_SLICES=65535`）预分配交错数组：
- 单条 `total=65535` 仅收到 1 个 512B 分片，就立刻占用约 `65535×8 ≈ 524KB` 的数组骨架；
- 攻击者（房间内成员，受 500/5s 分片限速约束）可开 256 条永远收不齐的消息（`MAX_PARTIAL_TABLE=256`），每条声明 `total=65535` → 约 **128MB** 内存被占据最长 30 秒。

规模不算灾难，但是个真实、低成本的拒绝服务。（上一版报告说的"~256MB/10s"已缓解为 1MB 上限 + 256 表 + 30s，但 `total` 放大未修。）

**修复**：把 `total` 上限收到 `ceil(MAX_MESSAGE_SIZE / SLICE_BYTES)≈2048`；或用 `Dictionary<int,byte[]>` 替代预分配数组，避免"声明即占内存"。

---

### F5 — LOW/INFO：端口解析无保护，客户端可被本地输入弄崩
**位置**：`MainWindow.xaml.cs:55` `int port = int.Parse(PortBox.Text.Trim());`

`int.Parse` 处于 `async void` 事件处理器且无 try/catch。用户输入非数字或越界（如空、`99999999999`）会抛未处理异常，**直接崩掉客户端进程**。仅本地、用户自身输入触发，非远程，但属于输入校验缺失。
**修复**：`int.TryParse` + 范围检查，失败时弹提示而非抛异常。

---

### F6 — LOW：TLS 私钥以明文落盘、有效期 10 年
**位置**：`gen_self_signed_cert.py:45`（10 年）、`:69`（`NoEncryption()`）

自签证书私钥 `key.pem` 不加密存储，证书有效期 3650 天。开发期可接受；若用于任何近似生产的部署，私钥泄露风险与过长有效期都是隐患。
**修复**：私钥加密存储（口令/PKCS#12），缩短有效期，并尽快替换为有真实信任链的证书。

---

### F7 — LOW：`auth` 握手的 `b3` 完整性校验是可选的
**位置**：`server_v2.py:168` `if b3:`

服务器仅在客户端**主动带 `b3`** 时才校验 `epub`↔`b3` 的握手完整性；不带的客户端（或被中间人剥掉 `b3`）直接跳过该检查。`relay_message` 路径强制 `b3`（见 `verify_integrity`），所以消息层面仍有校验，但握手层面的完整性是 best-effort。
**修复**：`auth` 也必须强制 `b3`，否则拒。

---

### F8 — INFO：服务器是开放中继 / 无服务端认证 / CORS `*`
**位置**：`server_v2.py:84`（`cors_allowed_origins="*"`）、`auth` 无认证、`MAX_CLIENTS=200`

匿名聊天场景下"无认证"属设计取舍，但意味着任何能连到端口的人都能加入任意房间、枚举在线成员——这恰恰是 F2 各类攻击的"入场券"。CORS `*` 在纯 Socket.IO 场景影响有限，但应随部署收紧。

---

### F9 — INFO：CryptoLib.dll 原生代码在 V2 路径是死代码，默认不编译
**位置**：`cryptolib.cpp`、`CryptoLibBridge.cs`

V2 会话层（`ChatSessionV2`）完全不调用 `CryptoLibBridge`，只用 `Curve25519.cs` + `XChaCha20Poly1305.cs`；`hybrid_encrypt/decrypt` 仍是 `not_implemented` 占位。当前 `generate_keypair` 的 `malloc(128)`+`snprintf`（输出 ≤88B）与 `base64_encode` 写入 64B 缓冲均安全，**今天没有原生漏洞**。但一旦该 DLL 被编译（OpenSSL 路径）并随包发布，需重新审计（尤其 `gpu_batch_keygen` 的 `out`/`out_len` 边界）。

---

## 三、修复优先级建议

1. **P0（F1 + F2 一起治本）**：默认 `wss` + 证书指纹锁；GUI 去掉"勾 TLS 即信任任何人"，改走指纹锁入口；握手增加 `id` 对 `epub` 的签名绑定。这两项不做，下面所有密码学都形同虚设。
2. **P1（F3）**：把 `n`/`dh_pub`/`epub`/`id` 纳入 Ed25519 签名，杜绝头字段篡改导致的棘轮失同步。
3. **P1（F4）**：收紧 `total` 上限或改字典存储，消除内存放大 DoS。
4. **P2（F5/F6/F7）**：端口解析容错、私钥加密+短有效期、握手强制 `b3`。
5. **P3（F8/F9）**：收紧 CORS、按需加服务端轻量认证；发布原生 DLL 前单独审计。

---

## 四、正确且值得保留的部分（避免误报）
- X25519 低阶点防御 ✅（`[8]*P==0` 标准 cofactor 校验）
- 跨房间投递拒绝 ✅（服务器按 room 归属校验 `target`）
- XChaCha20-Poly1305 / Poly1305 / HChaCha20 构造 ✅（逐行对齐 RFC 8439）
- Double Ratchet：HKDF-SHA512 派生、skipped-keys、重放/`GapTooLarge` 拒绝、密钥零化 ✅
- Ed25519 走 NSec·libsodium、签名/验签长度校验、私钥零化 ✅
- BLAKE3 自校 + 服务器 BLAKE3 一致性（含启动 self-check）✅
- 重放防护、密钥内存零化、证书锁定的"失败即拒"语义 ✅

**一句话总结**：密码学做得比大多数手写项目都规矩，真正的窟窿在"**密钥交换没有经过认证**"——默认不加密的传输 + 可被选中的"信任任意证书" + 自证身份，让网络中间人无需破解任何密钥即可读改写全部消息。先把 F1/F2 这条根因堵上，其余都是收尾。
