# E2E 加密聊天 V2 (端口 32759)

Signal-style 端对端加密聊天系统。V2 安全栈: X25519 + XChaCha20-Poly1305 + BLAKE3 + Ed25519 + Double Ratchet (HKDF-SHA512)。

## V2 安全栈

| 组件 | 算法 | 说明 |
|---|---|---|
| 密钥交换 | X25519 | 临时会话, 用完 zeroize |
| 对称加密 | XChaCha20-Poly1305 | AEAD, 24B nonce |
| 哈希 | BLAKE3 | 替换 MD5, 32B 输出 |
| 签名 | Ed25519 | 每条消息 64B 签名 |
| 棘轮 | Double Ratchet (HKDF-SHA512) | 双链对称棘轮, 每条消息独立派生新密钥 |
| 流量混淆 | 512B 定长分片 + 0~150ms 抖动 | 抗大小/时序分析 |

## 整体结构

```
E:\launcher\
├── server\                    服务器 (Python, python-socketio AsyncServer + uvicorn ASGI)
│   ├── server_v2.py           32759 端口 V2 服务器 (三不原则: 不存IP/时间/指纹)
│   ├── requirements.txt       python-socketio + uvicorn + cryptography (已剔除 V1 flask 残留)
│   └── run_server.bat
│
├── E2EChatClient\             客户端 (C# WPF, .NET 10)
│   ├── E2EChatClient.csproj
│   ├── App.xaml
│   ├── Crypto\                V2 与 V1 共用模块
│   │   └── Curve25519.cs       手写 X25519 (含低阶点防御, V1/V2 共用)
│   ├── CryptoV2\              V2 加密
│   │   ├── Blake3.cs           手写 BLAKE3 (1:1 C 参考移植)
│   │   ├── XChaCha20Poly1305.cs  AEAD (HChaCha20 + ChaCha20 + Poly1305)
│   │   ├── Ed25519.cs          NSec.Cryptography (libsodium 后端)
│   │   ├── DoubleRatchet.cs    HKDF-SHA512 双链棘轮 (含异常路径密钥 zeroize)
│   │   └── TrafficObfuscator.cs  512B 定长分片 + 时间抖动
│   ├── Native\
│   │   └── CryptoLibBridge.cs  (只读探测 GPU/DLL 状态, V2 加密主链路不依赖本 DLL;
│   │                              cryptolib/ 历史 stub 已改硬失败, 详见 cryptolib/*.cpp)
│   ├── Net\
│   │   ├── SocketIoClient.cs   手写 Socket.IO v5 over WebSocket (默认端口 32759)
│   │   └── V2\
│   │       └── ChatSessionV2.cs  V2 会话层 (Double Ratchet + 分片 + 身份钉定 TOFU)
│   ├── UI\
│   │   ├── MainWindow.xaml
│   │   └── MainWindow.xaml.cs
│   └── app.manifest
│
├── cryptolib\                  GPU 路径 (已用 #error 禁用占位编译, 非主链路依赖)
│
└── README.md
```

## 1. 启动服务器

```cmd
cd E:\launcher\server
run_server.bat
```

监听 `0.0.0.0:32759`。**"三不"原则**:
- **不存 IP**: request.remote_addr 仅用于实时连接, 断开立即丢弃
- **不存时间戳**: ts 仅用于瞬时限流计数, 5s 窗口作废即扔
- **不存设备指纹**: 无 banned 字典, 无指纹计算
- **零持久化**: 不写文件, 所有状态在内存, 重启即清零

服务器职责:
- 转发握手 (auth / new_member_request / new_member)
- 转发 `relay_slice` → `chat_slice` (纯中转, 不校验完整性 — 校验在接收方重组后做)
- 转发 `relay_message` → `chat_message` (旧路径, 含 BLAKE3 校验)
- 冒充身份防护: epub 与 session 注册不符 → 踢连接
- BLAKE3 完整性校验 (仅 relay_message 路径): 不符 → 丢消息不踢

## 2. 启动客户端

```cmd
E:\launcher\run_client.bat
```

主界面:
- 顶部: 服务器地址 / 端口 / 昵称 / 房间 → 点击「连接」
- 上线后自动生成临时 X25519 公钥, 列在右边成员列表 + BLAKE3 指纹
- 输入框回车或点击「发送 →」即端对端加密发出
- 右下「安全事件」实时显示 BLAKE3 校验、ECDH 派生、棘轮推进、篡改告警

## 3. V2 安全模型

### 握手 (最小化)

```
Alice → server: auth { epub=ephemeral_pub_b64, blake3=BLAKE3(epub_b64), room, id=identity_pub_b64 }
server → Alice: auth_response { sid, room, members=[{sid, epub}, ...], hash_algo }
server → Bob:   new_member { sid=Alice, epub=Alice_epub }
```

握手包仅含 32B 临时公钥 + BLAKE3 校验头, 所有固定字段硬编码, 不传冗余字符串。

### 每条消息 (Alice → Bob)

```
1. ratchet.RatchetForSend() → msgKey32B  (HKDF-SHA512 派生, 旧 chain 立即 zeroize)
2. XChaCha20-Poly1305.Encrypt(key=msgKey, nonce=随机24B, plaintext, aad=Alice_epub)
3. ctB64 = Base64(cipher)
4. b3 = BLAKE3(ctB64_utf8_bytes) hex  (与服务器一致)
5. sig = Ed25519.Sign(identity_priv, cipher_raw_bytes)  (64B)
6. envelope = { epub, id, ct, sig, b3, n }
7. wrapped = 4B长度头 + envelope JSON
8. slices = 512B 定长分片 (尾块 CSPRNG 填充)
9. 每个 slice: emit("relay_slice", {target, data=b64(slice)}) + 0~150ms 抖动
```

### 服务器转发 (relay_slice)

```
纯中转: forward { from, data } → emit("chat_slice", forward, to=target)
不做完整性校验 (校验在接收方重组后做)
```

### 接收侧 Bob

```
1. Reassembler 累积 512B 分片, 收齐后返回完整 envelope bytes
2. 解析 envelope JSON: { epub, id, ct, sig, b3, n }
3. BLAKE3 自校: BLAKE3(ctB64_utf8) == b3 ?  否 → 检测到篡改, 丢
4. Ed25519 验签: Verify(id_pub, cipher_raw, sig) ?  否 → 验签失败, 丢
5. 注册对端 (若首次): ECDH(Bob_priv, Alice_epub) → shared → DoubleRatchet(shared, Bob_epub, Alice_epub)
6. ratchet.RatchetForRecv() → msgKey  (与 Alice 的 send chain 同步)
7. XChaCha20-Poly1305.Decrypt(msgKey, cipher, aad=Alice_epub) → plaintext
8. 显示明文
```

### 密钥派生安全 (针对 GLM 5.2 叮嘱)

- 所有随机数使用系统级 CSPRNG (`RandomNumberGenerator` → 底层 getrandom/BCryptGenRandom)
- **严禁**使用 MAC 地址/硬盘序列号/时间戳做种子
- 所有临时私钥在内存中使用后立即 `CryptographicOperations.ZeroMemory` 清零

## 4. 双棘轮方向决定 (双链对称棘轮)

双方公钥字典序决定方向, 避免双向密钥重用:

```
iAmA = (my_epub < peer_epub)  // 字典序
chainA = HKDF-Expand(HKDF-Extract(shared), "E2EChat/chainA", 32)
chainB = HKDF-Expand(HKDF-Extract(shared), "E2EChat/chainB", 32)

iAmA: send_chain = chainA, recv_chain = chainB
iAmB: send_chain = chainB, recv_chain = chainA
```

=> Alice 的 send_chain == Bob 的 recv_chain (同为 chainA), 反之亦然。

每条消息:
```
msg_key = HKDF-Expand(chain, "msg/" + n, 32)
chain   = HKDF-Expand(chain, "advance", 32)   // 旧 chain 立即 zeroize (前向安全)
```

## 5. 流量混淆

### 512B 定长分片

所有消息 (无论长短) 切分为 512B 数据块, 末块用 CSPRNG 随机数补足。
攻击者无法通过数据包大小判断是"你好"还是传文件。每条消息最多浪费 511B 带宽。

### 0~150ms 时间抖动

每个分片发送前引入 0~150ms 随机延迟, 彻底打乱发送时间规律。
零带宽消耗, 让流量分析攻击失效。

## 6. ⚠ 重要安全须知 (Pass2-F6 / 2026-07-15)

### 6.1 默认明文 `ws://` — 默认配置是"明文优先, 默认关 TLS"
默认 `UseTls=false`. **这意味着 auth.epub、成员关系、消息外壳在网络上裸奔**——链路上的任何人 (ISP/同一 Wi-Fi/企业网代理) 都可被动读取元数据. 这是有意的设计取舍 (默认无需证书即可联调), **但生产部署必须**:
- 服务器侧: `python server_v2.py --tls-cert cert.pem --tls-key key.pem --tls-key-pw '<口令>'`
- 客户端侧: 勾选 "TLS" 并把 `gen_self_signed_cert.py` 打印的证书 SHA256 指纹粘进 GUI 指纹框 (留空会拒连, 见 6.2)

### 6.2 GUI 的 TLS 严格指纹锁 (F1 已修)
**别再"勾 TLS 即信任任意自签"**——这是历史 footgun. 现在:
- 勾 TLS 但指纹框留空 → **直接拒连** (防"加密但无认证"的降级)
- 仅指纹完全匹配的证书才接受; 不匹配即断, 不会静默放过

### 6.3 自签证书私钥现已加密 (F6 已修)
`gen_self_signed_cert.py` 已改:
- 私钥用 AES-256 + PBKDF2 加密 (口令 ≥ 12 字符), 不再 `NoEncryption()` 明文落盘
- 有效期从 3650 天缩到 365 天 (1 年), 缩短泄露暴露窗口
- 交互式 prompt 或 `--password-stdin` 提供. server 启动时通过 `--tls-key-pw` 透传 uvicorn

### 6.4 供应链警告 (dist/ 二进制不可审计)
`dist/WXLauncher.exe` 是**预编译二进制**, 若不是你自己从源码构建, 即存在**供应链/植入风险**:
- 攻击者替换或植入后门后, 加密层虽然正确, 但二进制可在加载前/启动期被劫持
- 生产/敏感部署: **永远从源码** `dotnet build -c Release` 重编客户端, 不信任随包发布的 `.exe`
- 校验源码: `git log -- inspect/committer -- E2EChatClient/CryptoV2/*`

### 6.5 带外指纹比对 (TOFU 不够时的主动防线)
TOFU (Pass4-F4-2) 仅在**首次连接无 MITM** 时安全. 真正抗主动 MITM 需带外核对:
- 客户端连接后, **双击右侧成员列表中的成员** → 弹窗显示该对端 epub 的完整 64 字符 BLAKE3 指纹
- 经由**别的信道 (电话/当面/PGP 签名)** 与该成员核对此指纹
- 完全一致 → 真; 不一致 → 你正在被中间人, **立即断开** 并改用 `wss://` + 严格指纹锁部署

## 7. 故障排查

| 现象 | 检查 |
|---|---|
| 客户端连不上 | `python server\server_v2.py` 看是否报错, 端口 32759 是否被占 |
| 显示 "CryptoLib.dll 缺失" | 没影响, 会自动走 C# 内置 Cipher (V2 主链路不依赖该 DLL) |
| 编 DLL 时报 `x25519 ...PLACEHOLDER` / `hybrid_* not implemented` 的 `#error` | Pass4-F4-4 修复: cryptolib/ 占位实现已硬失败, 防止半成品 DLL 被随包发布. V2 客户端不走该 DLL, 详见 `cryptolib/ecc_kernel.cu` 头注释 |
| 安全事件栏显示 "XChaCha20 解密失败" | 双方棘轮不同步, 可能消息丢失导致 chain 错位 |
| 安全事件栏显示 "Ed25519 验签失败" | 身份公钥被篡改或中间人攻击 |
| 安全事件栏显示 "检测到篡改(BLAKE3)" | 密文被中间人篡改 |
| 安全事件栏显示 "身份钉定失败 (id_pub 不一致)" | Pass4-F4-2 TOFU: 同一 sid 切换了 Ed25519 身份公钥, 视为冒充已拒 |
| 安全事件栏显示 "棘轮临时密钥异常 zeroize" | Pass4-F4-1: HKDF/OOM 异常下临时密钥已 zeroize, 防滞留托管堆 |
| 没看到对方成员 | 等 `new_member_request` 触发; 或多次「断开→连接」 |
