# 第三轮补充安全分析（基于 Pass1 / Pass2 的新发现与修正）

> 范围：本轮专补前两轮未覆盖的盲区——服务器全部 handler 逐行复核、未读文件（CUDA 内核、`.csx`）、`DoubleRatchet` 锁的真相、`relay_slice` 是否真被客户端使用、服务器是否验证 `id_sig`、SocketIoClient 的 TLS 实际行为。

## 进度回顾
- **Pass1** 的 CRITICAL/HIGH（X25519 低阶点、跨房间投递）已确认被**正确修复**（见 `security_analysis.md`→`security_analysis_revisit.md`）。
- **Pass2** 新发现：GUI 勾 TLS 反而关校验、无认证的密钥交换、未签名 `dh_pub`、Reassembler 放大等（`security_analysis_revisit.md`）。
- **本轮（Pass3）**：在最薄弱的"服务器是否真在做事"与"客户端到底走哪条路"上找到了决定性证据。

---

## 🔴 F3-1 服务器唯一真实性闸门是死代码（本轮最核心）

**证据**
- 客户端 `SendMessageAsync` 只调用 `_io.EmitAsync("relay_slice", ...)`（`ChatSessionV2.cs:271-279`）。全仓库 grep `relay_message`：**C# 源码里没有任何客户端 emit**，只有 README / verification HTML 提到它。
- 服务器的 BLAKE3 + `epub` 完整性校验 `verify_integrity` 只装在 `relay_message`（`server_v2.py:112-125, 219`）里；而真实流量走的 `relay_slice`（`server_v2.py:287-331`）**完全不调用它**。

**影响**
- 在实际运行的协议里，服务器对消息**零完整性、零真实性校验**。README / 注释里反复强调的"服务器 BLAKE3 校验、防冒充、防中间人嫁祸"在生产中**根本不生效**。
- 所有"服务器会校验 `epub` 防冒充"的假设都是错觉——这道闸门是写在一条没人走的代码路径上的。

**修复**：要么让客户端也走 `relay_message`（带校验），要么给 `relay_slice` 加同等校验；把完整性逻辑统一到两条路径，别留死代码给人安全感。

---

## 🟠 F3-2 `relay_slice` 无大小上限 + 无完整性 → 房间内放大 DoS

**证据**（`server_v2.py:307-331`）
```
data = envelope.get("data", "")
if not data: return
# 没有长度检查，也没有 verify_integrity 调用
```
限速 `RATE_LIMIT_MAX_SLICES=500`/5s，但单条 `data` 大小除了 engine.io 默认帧上限（~1MB）外**没有任何代码层限制**。

**攻击**：一个已认证成员（房间开放可任意加入，见 F3-4）在 5s 窗口内发 500 条 ≈1MB 切片 → 服务器向房间**全员**转发 ≈500MB。客户端虽对畸形包丢弃（`Reassembler` 要求封包正好 524B、`MAX_MESSAGE_SIZE=1MB`，`TrafficObfuscator.cs:103,97`），但仍付出接收/解码的带宽与 CPU。cover-traffic（抗流量分析）通道被恶意成员直接用于降级。

**修复**：`relay_slice` 强制 `data` 解码后正好 524B（一个合法切片封包）；加 BLAKE3/`epub` 校验；对单会话切片总字节数做配额。

---

## 🟠 F3-3 服务器从不认证任何东西（根因，强化 Pass2-F2）

1. **`auth` 不校验 `id_sig`**：`server_v2.py:152-205` 只取 `epub / b3 / room`，**完全忽略**客户端算好并发送（带 `id_sig=Sign(epub||room)`，`ChatSessionV2.cs:148-166`）的 Ed25519 签名。→ epub↔身份 绑定在服务器端**从未被验证**，纯客户端 TOFU，毫无防护意义。
2. **`auth` 不要求对 `epub` 的拥有性证明**（无挑战签名 / 无 ECDH 挑战）→ 任意 `epub` 字符串可注册。
3. 结合默认明文（`ws://`）+ GUI「TLS = 信任任意证书」（见 Pass2 / F3-8 下 TLS 复核）：网络 MITM 改写 `auth.epub` / `new_member.epub`，因服务器无绑定、客户端 TOFU，受害者与 MITM 建立棘轮 → **端到端被清零，且不破解任何密钥**。

**修复**：服务器在 `auth` 处验证 `id_sig=Sign(epub||room)`（身份 + 房间归属），或上 X3DH prekey 绑定；默认 `wss` + 强制证书指纹锁；GUI 暴露指纹输入。

---

## 🟡 F3-4 房间完全开放，无准入控制（元数据泄露 + 赋能 F3-2/F3-3）

**证据**（`server_v2.py:152-205`）
```
room = (payload.get("room") or "lobby").strip()[:30]
```
任何人发 `auth` 带任意 `room` 即加入；无密码 / 邀请 / ACL。`who_online`（`:351-360`）、`new_member`（`:203-205`）向成员回传全员 `epub` 与在线状态；客户端还会在认证后主动 `NotifyRoomIAmHere`（`MainWindow.xaml.cs:91-92` / `ChatSessionV2.cs:173-176`）再广播一次自己的 `epub`。

**影响**
- 攻击者猜到/得知房间名即可加入，拿到全员公钥、在线状态、消息时序/大小（流量分析）；并注入自身 `epub` 成为合法「对端」。
- 这是 F3-2（放大 DoS）、F3-3（MITM）的直接前提。

**修复**：房间需邀请令牌 / 口令 / 服务签名；`new_member` / `who_online` 仅回传必要字段，并考虑隐藏在线时序。

---

## 🟡 F3-5 `connect` 无认证 + `MAX_CLIENTS=200` → 预认证槽位耗尽 DoS

**证据**（`server_v2.py:131-136`）：`connect` 只查 `len(sessions) >= MAX_CLIENTS` 即放行；`auth` 是独立事件，`disconnect` 才清理。

**攻击**：攻击者（**无需认证**）并发保持 200 个已 `connect` 但未 `auth` 的连接 → 合法用户 `connect` 直接被拒（`:134 return False`）。设计上「三不」不存 IP，故难以按 IP 限速。

**修复**：对 `connect` 加轻量挑战 / 限速；或 `auth` 超时未完成的连接主动踢；即便不持久化也可用滑动窗口做内存级源计数。

---

## 🟡 F3-6 `dh_pub` 未认证 —— **修正 Pass2#3：非永久 desync，仍有真实弱点**

经复核 `DoubleRatchet.cs`：
- 所有状态变更（含 DH 切换分支 `:344-390` 的四字段更新）都在 `lock(_lock)` 内（`:120, 250, 300, 402`）。
- **结论：不存在并发竞态**。verification HTML 里说的「四字段非原子更新」是**旧版**说法，当前已被锁消除——此点上一轮我误引，特此纠正。

但仍存在问题：`TryRecv` 对 `dh_pub` **无认证**即切换整条接收链。
- 恶意房间成员发送 `dh_pub=X`（已知 X 私钥）→ 受害者接收链切到攻击者已知状态，可注入一条可解密消息；当对端发来正确 `dh_pub` 时受害者自动切回、状态自愈 → **非永久 desync**，但可被用于混淆 / 单次伪造注入。
- **升级条件**：在网络 MITM（F3-3）下，攻击者可改写每个消息的 `dh_pub`，使受害者棘轮持续跟随攻击者 → 等效接管接收链。

**修复**：`dh_pub` 变更须由对端 Ed25519 身份签名（或纳入消息 AEAD 的 AAD 并由 `sig` 覆盖）；拒绝未签名的 `dh_pub` 切换。

---

## 🟢 F3-7 CUDA 占位 `ecc_kernel.cu`（脚枪，非默认路径）

**证据**（`ecc_kernel.cu:103-109`）：`x25519_scalar_mult_base` 仅 `pub_out[i] = priv[i] ^ 0x5A`。注释声明默认走 C# `Curve25519.cs`，本文件仅编译演示用。

**风险**：一旦该 DLL 被编译发布并误接，公钥可被一行 XOR 还原私钥 → 灾难性。属供应链 / 脚枪风险。

**修复**：删除或加 `#error` 禁止发布；发布构建从 CI 排除 cuda 路径。

---

## 🟢 F3-8 TLS 复核（坐实 Pass2 的 GUI 发现）+ 信息类

**SocketIoClient TLS 行为**（`SocketIoClient.cs:36-87`）
- `UseTls` 默认 `false` → 默认明文 `ws://`。
- `AllowSelfSigned` 默认 `false`（严格）。
- 仅当 `UseTls=true` 才挂 `RemoteCertificateValidationCallback`：若 `AllowSelfSigned` → 接受任意证书；若设了 `ServerCertSha256` → 指纹 pin；若两者皆无 → 拒绝。
- **GUI 复核**（`MainWindow.xaml.cs:68-71`）：勾选 TLS 时 `_session.UseTls=true` **且** `_session.AllowSelfSigned=true`，并且 GUI **没有** `ServerCertSha256` 输入入口 → 用户只能选「明文」或「加密但不认证」两种不安全模式。这就是 Pass2 那条 HIGH 的精确落点。

**其他信息类**
- `server_v2.py:168` `if b3:` → 不带 `b3` 跳过握手完整性自检（服务器本就不要求拥有性，影响低）。
- `server_v2.py:86` `cors_allowed_origins="*"` → 任意网页可跨域连服务器（桌面客户端为主，web 攻击面有限，但配合开放房间可远程探测/加入）。

---

## 攻击链串联：为什么「端到端」会被清零

1. 默认 `ws://` 明文，或 GUI 勾 TLS → 信任任意证书（F3-8）。
2. 攻击者网络位置可 MITM，或只需 `auth{room:"victim"}` 即可**开放加入**任意房间（F3-4）。
3. 服务器 `auth` 不验 `id_sig`、不要求 epub 拥有性（F3-3）→ MITM 改写 `auth.epub` 为攻击者公钥；`new_member` 广播的也是攻击者 epub。
4. 受害者用攻击者 epub 建棘轮（`RegisterPeer`，`ChatSessionV2.cs:184-204`），MITM 持对应私钥 → **双向可读写「端到端」消息**。
5. 全程服务器零校验（F3-1 死代码闸门；`relay_slice` 无校验 F3-2），MITM 还能用 `relay_slice` 放大 DoS（F3-2）/ 槽位耗尽（F3-5）。
6. 原语（XChaCha20-Poly1305 / Ed25519 / BLAKE3 / 低阶点防护）全部正确——但**认证密钥交换的缺失**让这一切归零。

---

## 修复优先级（按 ROI）

| # | 项 | 级别 | 关键文件 |
|---|----|------|----------|
| 1 | 默认 `wss` + 证书指纹锁（GUI 暴露指纹输入，移除「TLS=信任任意」） | HIGH | `MainWindow.xaml.cs:68-71`, `SocketIoClient.cs:76-87` |
| 2 | `auth` 服务器侧校验 `id_sig=Sign(epub||room)`（或 X3DH prekey） | HIGH | `server_v2.py:152-205` |
| 3 | 房间准入（令牌 / 邀请） | MED | `server_v2.py:152-205` |
| 4 | `relay_slice` 加与 `relay_message` 同等的完整性校验 + `data`≤524B + 会话字节配额 | HIGH | `server_v2.py:287-331` |
| 5 | `connect` 预认证限速 / 超时踢 | MED | `server_v2.py:131-136` |
| 6 | `dh_pub` 变更须签名 | MED | `DoubleRatchet.cs:344-390`, `ChatSessionV2.cs` |
| 7 | 清理 `ecc_kernel.cu` 占位、收紧 CORS、`b3` 改强制 | LOW | `ecc_kernel.cu`, `server_v2.py:86,168` |

## 三轮总结论
- Pass1 的两个致命漏洞确认已**正确修复**；密码学原语经三轮机检无误。
- 剩余风险**全部集中在系统性根因**：传输未认证 + 服务器零认证中转 + 房间开放。原语再强也救不了没有认证的密钥交换。
- 最该先堵的两件事：**① 默认 wss + 指纹锁（关掉 GUI 的「TLS=信任任意」）；② `auth` 做服务器侧 `id_sig` 验证**。其余是收尾与 DoS 加固。
