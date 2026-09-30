# E2E 加密聊天 V2 — 全项目 Bug 深度分析报告

> 分析范围:`cryptolib/`、`server/`、`E2EChatClient/`、`installer/`、`run_client.bat`
> 分析方式:逐文件静态审计 + 实际编译 + 运行时 PoC 验证
> 编译状态:E2EChatClient 0 错误 0 警告;Installer 0 错误(1 个 WinForms DPI 警告);server 可正常启动。

---

## 总览

| 严重级 | 数量 | 摘要 |
|---|---|---|
| **P0 致命(安全/协议级)** | 3 | Double Ratchet 失效、Zip Slip 漏洞、私钥副本未清零 |
| **P1 高危(功能性)** | 3 | 密码清零死代码、TryDispatchAck 抛异常、UI 控件重叠 |
| **P2 中危(边界/质量)** | 8 | HashExtended 错误、int.Parse 崩溃、Debug 启动等 |
| **P3 低危(死代码/设计)** | 4 | 静态字段共享、未使用变量等 |

---

## P0 致命级 Bug

### 🔴 BUG-1: Double Ratchet 退化为对称棘轮(协议级失效)

**文件:** `E2EChatClient/Net/V2/ChatSessionV2.cs` 第 629–632 行 + 第 319–327 行
**已用独立 PoC 验证**

**问题:**

`SendMessageAsync` 依赖 `_peerLastDhPub != ratchet.PeerDhPub` 来决定是否触发 `DhRatchetForSend()`(换我方 DH keypair):

```csharp
// ChatSessionV2.cs L319-327
_peerLastDhPub.TryGetValue(sid, out var lastKnown);
if (lastKnown != null && ratchet.PeerDhPub != null
    && !BytesEqual(lastKnown, ratchet.PeerDhPub))
{
    ratchet.DhRatchetForSend(ratchet.PeerDhPub);
    _peerLastDhPub[sid] = (byte[])ratchet.PeerDhPub.Clone();
}
```

但 `ProcessEnvelope` / `HandleChatMessage` 在 `TryRecv` 之后**立即同步更新** `_peerLastDhPub`:

```csharp
// ChatSessionV2.cs L629-632
if (!_peerLastDhPub.TryGetValue(fromSid, out var lastDh)
    || !BytesEqual(lastDh, theirDhPub)) {
    _peerLastDhPub[fromSid] = (byte[])theirDhPub.Clone();   // ← 破坏检测语义
}
```

同时 `DoubleRatchet.TryRecv` 在对端换 DH pub 时也会切换 `_peerDhPub = theirDhPub.Clone()`(`DoubleRatchet.cs` L374)。

**后果链:**
1. TryRecv 后:`ratchet.PeerDhPub = theirDhPub`
2. ProcessEnvelope 后:`_peerLastDhPub = theirDhPub`
3. 两者**永远相等** → `DhRatchetForSend` **永远不被调用**
4. 双方永远停留在初始 ephemeral DH pub,只走对称棘轮

**安全影响:**
- README §4 宣称"已从对称棘轮+双链升级为完整 Double Ratchet",**实际不是**。
- 前向安全不完整:当前 chain key 泄露后,攻击者可推导未来所有 msg key(因为没有 DH 轮换刷新 chain 起点)。
- 后向安全(past secrecy)仍由 zeroize 保护,但 Signal 协议的核心设计被绕过。

**修复:**

`_peerLastDhPub` 应该是"我方**上次发送时**用的 peer DH pub",**只**在 `DhRatchetForSend` 后更新:

```csharp
// ProcessEnvelope / HandleChatMessage 中删除这段:
// if (!_peerLastDhPub.TryGetValue(...) || ...) { _peerLastDhPub[fromSid] = ...; }

// SendMessageAsync 保持不变:
if (!BytesEqual(lastKnown, ratchet.PeerDhPub)) {
    ratchet.DhRatchetForSend(ratchet.PeerDhPub);
    _peerLastDhPub[sid] = (byte[])ratchet.PeerDhPub.Clone();
}
```

---

### 🔴 BUG-2: Installer 解压存在 Zip Slip 路径穿越漏洞

**文件:** `installer/InstallEngine.cs` 第 72–87 行

**问题:**

```csharp
string rel = entry.FullName.Replace('/', '\\');
string dst = Path.Combine(targetDir, rel);
// ↓ 没有验证 dst 是否在 targetDir 内
if (rel.EndsWith("\\") || entry.Length == 0 && string.IsNullOrEmpty(entry.Name)) {
    Directory.CreateDirectory(dst);
} else {
    Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
    using (var src = entry.Open())
    using (var outFs = File.Create(dst)) { src.CopyTo(outFs); }
}
```

**攻击场景:**

恶意 `payload.zip` 包含 entry:
```
../../../Windows/System32/evil.dll
```
`rel` = `..\..\..\Windows\System32\evil.dll`
`dst` = `Path.Combine("C:\Program Files\E2EChatClient", rel)` → 解析到 `C:\Windows\System32\evil.dll`

**影响:**
- 攻击者构造的 installer 可向任意位置写文件(System32、启动目录、ProgramData 等)
- 配合 self-contained 单文件 installer 的高权限运行场景,可植入恶意 DLL/exe

**修复:**

```csharp
string fullTarget = Path.GetFullPath(targetDir) + Path.DirectorySeparatorChar;
string fullDst = Path.GetFullPath(dst);
if (!fullDst.StartsWith(fullTarget, StringComparison.OrdinalIgnoreCase))
    throw new IOException($"Entry escapes target dir: {entry.FullName}");
```

---

### 🔴 BUG-3: X25519 私钥副本未 zeroize,内存泄漏到 GC 堆

**文件:** `E2EChatClient/Crypto/Curve25519.cs` 第 53 行

**问题:**

```csharp
public static byte[] ComputeSharedSecret(byte[] myPrivateKey, byte[] peerPublicKey)
{
    ...
    byte[] k = CopyClamped(myPrivateKey);    // ← 私钥副本
    byte[] shared = ScalarMult(k, peerPublicKey);
    if (IsAllZero(shared)) {
        CryptographicOperations.ZeroMemory(shared);
        throw new CryptographicException(...);
    }
    return shared;
    // ↑ k (clamped 私钥) 从未 zeroize
}
```

`CopyClamped` 在堆上分配了 32 字节私钥副本。函数返回后,`k` 没有任何引用,但**字节内容仍驻留在 GC 堆**直到垃圾回收。

**影响:**
- 内存 dump(如 procdump、WinDbg、pagefile)可读出 clamped 私钥
- 与 README §3"所有临时私钥在内存中使用后立即 ZeroMemory"的安全承诺矛盾
- `IsValidPublicKey` 中 `scalar8` 是固定值不需要清,但 `CopyClamped` 的私钥副本必须清

**修复:**

```csharp
byte[] k = CopyClamped(myPrivateKey);
try {
    byte[] shared = ScalarMult(k, peerPublicKey);
    if (IsAllZero(shared)) {
        CryptographicOperations.ZeroMemory(shared);
        throw new CryptographicException(...);
    }
    return shared;
} finally {
    CryptographicOperations.ZeroMemory(k);
}
```

`IsValidPublicKey` 内 `ScalarMult(scalar8, ...)` 同理,`scalar8` 虽然非敏感,但 `test` 已 zeroize(已有 finally),OK。

---

## P1 高危级 Bug

### 🟠 BUG-4: gen_self_signed_cert.py 密码清零是死代码

**文件:** `server/gen_self_signed_cert.py` 第 106–110 行

**问题:**

```python
if isinstance(key_password, bytes):
    try:
        import ctypes
        ctypes.memmove(
            (ctypes.c_char * len(key_password)).from_address_copy(id(key_password)),  # ← 不存在的方法
            b"\x00" * len(key_password),
            len(key_password))
    except Exception:
        pass
```

**已验证:**

```
AttributeError: type object 'c_char_Array_14' has no attribute 'from_address_copy'
```

`ctypes.Array` 类型有 `from_address`、`from_buffer`、`from_buffer_copy`,**没有** `from_address_copy`。这行代码每次必抛 `AttributeError`,被 `except Exception: pass` 吞掉。**密码永远不清零。**

**影响:**
- 用户输入的私钥密码留在 Python 堆上,直到 GC 回收
- 与 README §6.3 "用完即清" 的声明矛盾
- 但 Python 的 bytes 对象本身就难以安全 zeroize(可能被 intern/共享),即使 API 存在 `id()` 也只清对象头(破坏 Python 对象),数据仍可能在别处

**修复(务实方案):**

改用 `bytearray` 全程,zeroize 用 `ctypes.memset`:

```python
def _ask_password() -> bytearray:
    while True:
        pw = getpass.getpass("私钥加密口令 (>= 12 字符): ")
        ...
        return bytearray(pw.encode("utf-8"))

# 使用处:
key_password_bytes = bytes(key_password)   # 一次性副本给 cryptography
encrypted_key = priv.private_bytes(..., serialization.BestAvailableEncryption(key_password_bytes))
del key_password_bytes

# zeroize bytearray:
import ctypes
ctypes.memset(ctypes.addressof((ctypes.c_char * len(key_password)).from_buffer(key_password)),
              0, len(key_password))
key_password.clear()
```

---

### 🟠 BUG-5: SocketIoClient.TryDispatchAck 重复调用 EnumerateArray 抛异常

**文件:** `E2EChatClient/Net/SocketIoClient.cs` 第 295–299 行

**问题:**

```csharp
using var doc = JsonDocument.Parse(rest.Substring(i));
if (doc.RootElement.ValueKind == JsonValueKind.Array &&
    doc.RootElement.EnumerateArray().MoveNext())        // ← 第一个新 enumerator,MoveNext 一次
{
    var first = doc.RootElement.EnumerateArray().Current;  // ← 第二个新 enumerator,未 MoveNext!
    tcs.TrySetResult(first);
}
```

每次调用 `EnumerateArray()` 返回**新的** enumerator。`if` 里的 enumerator 已 MoveNext 一次,但 `Current` 在**另一个**新 enumerator 上访问(还没 MoveNext),抛 `InvalidOperationException`。

**已用独立 PoC 验证:**

```
BUG 确认: InvalidOperationException: Operation is not valid due to the current state of the object.
```

**影响:**
- `EmitWithAckAsync` 在 ack payload 是数组时**永远**收不到正确结果
- 项目主链路当前不用 `EmitWithAckAsync`(用 `OnAuthResult` 事件 + TCS),所以主链路无影响,但**未来误用即炸**
- 异常被外层 `catch (Exception ex) { tcs.TrySetException(ex); }` 吞掉,调用方看到 ack 超时/异常

**修复:**

```csharp
using var doc = JsonDocument.Parse(rest.Substring(i));
if (doc.RootElement.ValueKind == JsonValueKind.Array)
{
    var en = doc.RootElement.EnumerateArray();
    if (en.MoveNext())
        tcs.TrySetResult(en.Current);
    else
        tcs.TrySetResult(default);
}
else tcs.TrySetResult(default);
```

---

### 🟠 BUG-6: MainWindow.xaml 中 CertShaBox 和 ConnBtn 同格重叠

**文件:** `E2EChatClient/UI/MainWindow.xaml` 第 47 行 + 第 49 行

**问题:**

```xml
<TextBox   Grid.Column="10" x:Name="CertShaBox" Width="200" .../>
<TextBlock Grid.Column="11" x:Name="ConnStatus" .../>
<Button    Grid.Column="10" x:Name="ConnBtn" Content="连接" .../>
```

`CertShaBox` 和 `ConnBtn` 都指定 `Grid.Column="10"`(且该列 `Width="Auto"`)。WPF Grid 中同列控件会**重叠堆叠**,Auto 列宽取最大子控件宽度(200 = CertShaBox),ConnBtn (Width=80) 被定位在 CertShaBox 之上,**遮挡指纹输入框**。

**影响:**
- 用户勾选 TLS 后无法输入证书指纹 → 无法连接(因为 BUG 触发 "指纹缺失" 弹窗)
- TLS 功能在 GUI 中**完全不可用**

**修复:**

`ConnBtn` 移到空闲列(看 ColumnDefinitions,Column 12 是 `200`、Column 13 是 `Auto`,都未用):

```xml
<Button Grid.Column="12" x:Name="ConnBtn" Content="连接" .../>
```

或者重排整个顶部面板,把指纹框和按钮分开。

---

## P2 中危级 Bug

### 🟡 BUG-7: Blake3Hash.HashExtended 扩展输出用零填充,不是真 XOF

**文件:** `E2EChatClient/CryptoV2/Blake3.cs` 第 43–53 行

**问题:**

```csharp
public static byte[] HashExtended(byte[] input, int outLen) {
    var h = NuBlake3.Hasher.New();
    h.Update(input);
    var hash = h.Finalize();                          // 只拿 32B
    byte[] src = hash.AsSpan().ToArray();
    if (outLen <= 0) return Array.Empty<byte>();
    if (outLen <= src.Length) return src[..outLen];
    byte[] big = new byte[outLen];                    // ← outLen > 32 时,超出部分是 0
    Buffer.BlockCopy(src, 0, big, 0, Math.Min(src.Length, big.Length));
    return big;
}
```

BLAKE3 是 XOF(可扩展输出函数),`outLen > 32` 时应该继续从压缩函数 squeeze 更多字节,而不是零填充。

**影响:**
- 若调用方期望 ≥ 33 字节的派生密钥,后段全是 0 → 密钥强度骤降
- 当前项目内未发现调用 `HashExtended(input, >32)` 的位置,属**潜在地雷**

**修复:**

用 BLAKE3 NuGet 的 XOF API(`Hasher.Finalize(Span<byte>)` 或 seek 模式),或者直接抛异常拒绝 `outLen > 32`。

---

### 🟡 BUG-8: DrainRecvChainIntoSkipped 跳号超过 MAX_SKIPPED_KEYS 后会话失同步

**文件:** `E2EChatClient/CryptoV2/DoubleRatchet.cs` 第 319–339 行

**问题:**

```csharp
while (_recvN < n) {
    ...
    _skippedTotal++;
    _recvN++;
    if (_skippedTotal > MAX_SKIPPED_KEYS) break;   // ← break 时 _recvN < n
}
// 此时 _recvN != n,但代码继续用 _recvN 取 msg key
byte[] mk = null!;
try {
    mk = HkdfSha512.Expand(_recvChainKey,
        Encoding.UTF8.GetBytes("msg/" + _recvN), 32);   // ← 用的是 _recvN 不是 n
```

当 `_recvN + 1 ≤ n ≤ _recvN + MAX_GAP`(最大 2000)且跳号超过 `MAX_SKIPPED_KEYS=1000` 时,break 后 `_recvN ≠ n`。代码继续用 `_recvN` 取 msg key,但发送方用 `n` 派生 → **永远解密失败**。

更糟的是 `_recvChainKey` 已经推进了 1001 次,后续所有消息也解不开,**会话永久卡死**。

**影响:**
- 攻击者/网络丢包 1000+ 条后,整个会话 ratchet 失同步,只能重建会话
- 实际聊天场景跳号 1000+ 极罕见,但攻击者可主动构造(伪装 sender 发 envelope 带大 n)

**修复:**

break 后检查 `_recvN != n` 则返回 `GapTooLarge`,保持 `_recvChainKey` 一致:

```csharp
while (_recvN < n) {
    ...
    if (_skippedTotal > MAX_SKIPPED_KEYS) {
        // 回滚 chain: 重新派生 (这里 chain 已推进,无法简单回滚,所以只能拒收并保 chain)
        return new DecryptOutcome {
            Verdict = RatchetVerdict.GapTooLarge,
            Reason = $"skipped keys full ({_skippedTotal}>{MAX_SKIPPED_KEYS}), n={n} unreachable"
        };
    }
}
```

**注意:** 当前代码 `_recvChainKey` 已在 break 前推进了 1001 次,严格回滚不可行(HKDF 单向)。所以正确做法是**先预估 skipped 占用,再决定是否推进**。

---

### 🟡 BUG-9: SocketIoClient 重连用同一 ClientWebSocket 会抛异常

**文件:** `E2EChatClient/Net/SocketIoClient.cs` 第 49 行 + 第 97 行

**问题:**

```csharp
private ClientWebSocket _ws = new();   // 字段级只创建一次

public async Task ConnectAsync()
{
    ...
    await _ws.ConnectAsync(url, _cts.Token);   // ← 如果 _ws 已 Closed/Aborted,这里抛 InvalidOperationException
}
```

`ClientWebSocket` 一旦 `CloseAsync` / `Dispose`,状态机不可重启。再次 `ConnectAsync` 抛 `InvalidOperationException: Already started`。

**影响:**
- `ChatSessionV2.AuthAsync` → `_io.ConnectAsync()`。若用户点"断开"再点"连接"(同一 session),失败
- 但 `MainWindow` 在断开时 `_session.Dispose(); _session = null;`,下次连接会 new 一个 `ChatSessionV2` → new 一个 `SocketIoClient` → new 一个 `_ws`。所以主流程能绕开,**但 AuthAsync 被同一 session 调用两次会炸**

**修复:**

```csharp
public async Task ConnectAsync()
{
    if (_ws.State != WebSocketState.None) {
        _ws.Dispose();
        _ws = new ClientWebSocket();
    }
    ...
}
```

---

### 🟡 BUG-10: MainWindow.xaml.cs int.Parse 未捕获 FormatException

**文件:** `E2EChatClient/UI/MainWindow.xaml.cs` 第 66 行 + 第 452 行

**问题:**

```csharp
int port = int.Parse(PortBox.Text.Trim());   // ← 用户输入 "abc" 直接 FormatException
```

两处(`ConnBtn_Click` 和 `CreateRoomBtn_Click`)。

**影响:** 用户误输入非数字端口,应用直接崩溃(未处理异常)。虽然有外层 try-catch 在 `ConnBtn_Click` 底部,但 `int.Parse` 在 try 块**之前**(第 66 行在 `try` 之前的准备代码)。

**修复:**

```csharp
if (!int.TryParse(PortBox.Text.Trim(), out int port) || port < 1 || port > 65535) {
    MessageBox.Show("端口必须是 1-65535 的数字");
    return;
}
```

---

### 🟡 BUG-11: TrafficObfuscator.Reassembler 拼接后 ciphertext 未完全 zeroize

**文件:** `E2EChatClient/CryptoV2/TrafficObfuscator.cs` 第 158–161 行

**问题:**

```csharp
byte[] result = new byte[origLen];
Buffer.BlockCopy(full, 4, result, 0, (int)origLen);
CryptographicOperations.ZeroMemory(full.AsSpan(0, Math.Min(4, full.Length)));   // ← 只清前 4B
return result;
```

`full` 包含 `4B length header + ciphertext`。代码只清了前 4 字节(length header),**ciphertext 主体没清**。

**影响:**
- ciphertext 留在 GC 堆,虽然本身是密文不算最高敏感,但攻击者拿到 ciphertext 可以做流量分析关联
- 与项目 "用完即清" 的整体安全风格不一致

**修复:**

```csharp
CryptographicOperations.ZeroMemory(full.AsSpan());   // 清整个 full
```

---

### 🟡 BUG-12: ecc_kernel.cu CUDA kernel 启动参数顺序颠倒(dead code)

**文件:** `cryptolib/ecc_kernel.cu` 第 108 行

**问题:**

```cpp
int threads = 256;
int blocks = (count + threads - 1) / threads;
batch_keygen_kernel<<<threads, blocks>>>(count, d_out);   // ← 顺序颠倒
```

CUDA 语法是 `kernel<<<gridDim, blockDim>>>`:
- `gridDim` = block 数量
- `blockDim` = 每个 block 的 thread 数

这里把 `threads` (256) 当成 gridDim,`blocks` 当成 blockDim。**完全颠倒**。

**影响(假设去掉 #error 启用 GPU 路径):**
- 当 `count > 256` 时,`blocks > 1`,`blockDim.x = blocks` 可能超过 GPU 单 block 最大线程数(1024)→ launch 失败
- 即便不失败,`blockIdx.x * blockDim.x + threadIdx.x` 算出的 idx 分布混乱,可能重复处理或漏处理

**修复:**

```cpp
batch_keygen_kernel<<<blocks, threads>>>(count, d_out);
```

**备注:** 文件头部有 `#error` 保护,当前不会被编译。属 dead code 中的 bug,但保留错误的"骨架代码"有误导风险。

---

### 🟡 BUG-13: ecc_kernel.cu 私钥生成非随机(dead code)

**文件:** `cryptolib/ecc_kernel.cu` 第 71–72 行

**问题:**

```cpp
uint8_t priv[32];
for (int i = 0; i < 32; i++)
    priv[i] = (uint8_t)((idx * 31 + i * 7 + 0x9e) & 0xff);   // ← 完全确定性
```

私钥用固定公式从 `idx` 派生,任何人可重现**所有**批量生成的"私钥"。

**影响:** 若 GPU 路径启用,生成的密钥对**毫无安全性**。

**备注:** 同样有 `#error` 保护,dead code。

---

### 🟡 BUG-14: run_client.bat 启动 Debug 版本而非 Release

**文件:** `run_client.bat` 第 7 行

**问题:**

```bat
E2EChatClient\bin\Debug\net10.0-windows\E2EChatClient.exe
```

启动 Debug 构建:
- 未优化代码,X25519/ChaCha20 等热路径慢数倍
- 携带 `.pdb` 调试符号,内存 dump 可读更多内部状态(变量名、行号)
- `bin\Debug` 目录默认发布时**包含调试断言**(虽然项目没用 Debug.Assert)

**修复:**

```bat
if exist E2EChatClient\bin\Release\net10.0-windows\E2EChatClient.exe (
    E2EChatClient\bin\Release\net10.0-windows\E2EChatClient.exe
) else (
    E2EChatClient\bin\Debug\net10.0-windows\E2EChatClient.exe
)
```

---

## P3 低危级 Bug

### 🔵 BUG-15: SocketIoClient._nextAck 是 static 字段

**文件:** `E2EChatClient/Net/SocketIoClient.cs` 第 55 行

```csharp
private static int _nextAck = 1;   // ← static,多实例共享
```

**影响:** 若未来有多个 `SocketIoClient` 实例(当前只有一个),ack id 计数器互相干扰。

**修复:** 改为实例字段。

---

### 🔵 BUG-16: server_v2.py 房密码指数退避 backoff_s 计算后未使用

**文件:** `server/server_v2.py` 第 419–420 行

```python
backoff_s = min(ROOM_PW_FAIL_WINDOW_SEC,
                2 ** (fails - ROOM_PW_FAIL_MAX))   # 第 5→1s, 6→2s, 7→4s...
log.warning("room pw brute-force lockout: ... (next allowed in >=%ds)", backoff_s)
await sio.emit("auth_response", {
    "ok": False,
    "reason": "too many room password attempts, retry later",   # ← 没告诉客户端等多久
}, to=sid)
await sio.disconnect(sid)
```

`backoff_s` 计算后只用于 log,**没有**:
- 写入响应让客户端知道等多久
- 服务端实际 sleep / 延迟 disconnect
- 持久化"该房下次允许 auth 的时间"

**影响:** 退避策略只起 log 作用,攻击者重连后仍可立即再次试错(只是被 fail_list 计数器拒)。

**修复:** 把 backoff_s 放进响应:`"reason": f"retry in {backoff_s}s"`,并且 server 端记录 `next_allowed_auth[room] = now + backoff_s`,auth 时检查。

---

### 🔵 BUG-17: server_v2.py 中 log.info 调用是死代码

**文件:** `server/server_v2.py` 第 114 行 + 第 320、350 行

```python
log.setLevel(logging.WARNING)
...
log.info("connect sid=%s subnet=%s", sid, subnet)     # ← WARNING 级别下不输出
log.info("disconnect sid=%s", sid)                     # ← 同上
```

`e2e-v2` logger 设为 WARNING,所有 `log.info` 永远不输出。属**死代码**,易误导维护者。

**修复:** 要么改成 `log.debug`,要么删除,要么把 logger 级别调回 INFO。

---

### 🔵 BUG-18: server_v2.py `except (InvalidSignature, Exception)` 冗余

**文件:** `server/server_v2.py` 第 78 行

```python
except (InvalidSignature, Exception):
    return False
```

`InvalidSignature` 是 `Exception` 的子类,`except (InvalidSignature, Exception)` 等价于 `except Exception`。冗余但语义上想强调"验签失败是预期路径"。可改为:

```python
except InvalidSignature:
    return False
except Exception:
    return False   # 或单独 log 未知异常
```

---

## 其他发现(非 bug 但值得注意)

### CryptoLibBridge.IsGpuAvailable 中 AllocHGlobal(0)

```csharp
IntPtr buf = Marshal.AllocHGlobal(0);   // 分配 0 字节
int r = gpu_batch_keygen_native(0, buf, 0);
```

`AllocHGlobal(0)` 行为依赖 .NET 实现(可能返回非零指针或抛异常)。探测 GPU 用 count=0 是 OK,但更安全的写法是 `IntPtr.Zero`。

### ChatSessionV2._sliceSender 的 sender 覆盖

`_sliceSender[sidSeed] = from;` 在每次收到分片时都覆盖。如果两个不同 `from` 用了同一个 `sidSeed`(CSPRNG 8B,概率 1/2^64),后到的覆盖前到,导致 ProcessEnvelope 用错 sender。属**理论边界**,实际不可能。

### installer payload.zip 无签名校验

README §6.4 已声明供应链风险。当前 payload.zip 内是合法的 E2EChatClient 二进制(36 entries,含 Blake3.dll / NSec.Cryptography.dll / runtimes)。**不签名 = 可被替换**,建议未来加入 SHA256 校验 + 公钥签名。

---

## 修复优先级建议

| 顺序 | Bug | 工作量 | 影响面 |
|---|---|---|---|
| 1 | BUG-1 (DH Ratchet) | 2 行代码 | 整个加密协议 |
| 2 | BUG-2 (Zip Slip) | 3 行代码 | installer 安全 |
| 3 | BUG-6 (UI 重叠) | 1 行 XAML | TLS 功能可用性 |
| 4 | BUG-3 (私钥 zeroize) | 5 行代码 | 内存安全 |
| 5 | BUG-4 (密码清零) | 10 行代码 | 密码安全 |
| 6 | BUG-5 (TryDispatchAck) | 5 行代码 | 未来 API 正确性 |
| 7 | BUG-8 (跳号失同步) | 5 行代码 | 极端场景鲁棒性 |
| 8 | BUG-9 (重连) | 4 行代码 | 边缘场景 |
| 9 | BUG-10 (int.Parse) | 4 行代码 | UI 崩溃 |
| 10 | BUG-14 (Release 启动) | 5 行 bat | 性能 |

---

## 附:验证过的关键 PoC

### PoC 1: DH Ratchet 失效(独立 C# 测试)

```csharp
_peerLastDhPub[sid] = initialEpub;
_peerDhPub[sid] = initialEpub;
// TryRecv 后:
_peerDhPub[sid] = theirDhPub;
_peerLastDhPub[sid] = theirDhPub;   // ChatSessionV2 的更新
// 检测:
Console.WriteLine(BytesEqual(_peerLastDhPub[sid], _peerDhPub[sid]));  // True → 永远不触发 DhRatchetForSend
```

### PoC 2: from_address_copy 不存在(Python)

```python
import ctypes
arr = ctypes.c_char * 5
arr.from_address_copy(0)   # AttributeError: type object 'c_char_Array_5' has no attribute 'from_address_copy'
```

### PoC 3: EnumerateArray 两次调用抛异常(C#)

```csharp
using var doc = JsonDocument.Parse("[{\"ok\":true}]");
if (doc.RootElement.ValueKind == JsonValueKind.Array &&
    doc.RootElement.EnumerateArray().MoveNext())
{
    var first = doc.RootElement.EnumerateArray().Current;   // InvalidOperationException
}
```

---

## 编译/运行验证

```
E2EChatClient: dotnet build  → 0 错误 0 警告
Installer:     dotnet build  → 0 错误(1 个 DPI 警告,非 bug)
server:        python server_v2.py --port 33333  → 正常启动,socket.io handshake OK
现有实例:      PID 268 已监听 32759(说明 server 至少在生产中可用)
```

---

**报告生成时间:** 2026-07-22
**分析工具:** 静态代码审计 + Roslyn 编译 + Python ctypes PoC + C# 独立测试工程
