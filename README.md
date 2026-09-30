# E2EChat V2

端对端加密聊天，一个 Python 服务端 + 一个 Windows 客户端，跑在局域网或你自己租的 VPS 上。默认端口 **32759**。

密钥交换是 X25519 与 ML-KEM-1024 的混合，消息走双棘轮，每条消息单独签名。服务端按"三不"写：不存 IP、不存时间戳、不存设备指纹，进程重启内存清零。

仓库名 `telegram-promax` 是历史原因，跟 Telegram 没关系，按名字找东西会找错。

## 密码学栈

| 环节 | 用什么 | 备注 |
|---|---|---|
| 密钥交换 | X25519 + ML-KEM-1024 混合 | 手写 X25519，含低阶点防御；PQ 部分见 `CryptoV2/MlKemHybrid.cs` |
| 混合派生 | HKDF-SHA512 | `IKM = dh ‖ kem_ss`，salt 全零 64B，info `E2EChat/pq-hybrid-seed`，出 32B 根密钥 |
| 棘轮 | Double Ratchet（HKDF-SHA512 双链） | 每条消息派生新密钥，旧链立即清零 |
| 对称加密 | XChaCha20-Poly1305 | AEAD，24 字节随机 nonce，AAD 绑临时公钥 |
| 签名 | Ed25519（NSec.Cryptography / libsodium） | 每条密文一个 64B 签名 |
| 完整性与指纹 | BLAKE3 | 替代原来的 MD5，32B |
| 证书信任 | 自签 + SHA256 指纹钉定 | `Net/CertPinStore.cs`，不做 CA 链校验 |
| 流量特征 | 512B 定长分片 + 0~150ms 抖动 | 尾块用 CSPRNG 填充 |

随机数一律走系统 CSPRNG（`RandomNumberGenerator`，底层是 `BCryptGenRandom`）。当初专门确认过这件事，别改回用 MAC 地址、硬盘序列号或者时间戳当种子。临时私钥用完 `CryptographicOperations.ZeroMemory` 清零，异常路径也清。

## PQ 握手是怎么协商的

双方各自生成一对 ML-KEM-1024 密钥，公钥随 `auth` 上报。会话建立时：

1. 两边都先算 X25519 共享密钥。
2. 检查对端有没有 `kpub`，长度不等于 `PUBLIC_KEY_BYTES` 或者 base64 解不出来，一律当"没有 PQ"。
3. 有 PQ 的话，**谁做封装方由临时公钥的字典序决定**（`CompareOrdinal(my_epub_b64, peer_epub_b64) < 0`）。这条规则保证两边不会同时封装、也不会同时等着。
4. 封装方 `Encapsulate(peer_kpub)` 得到 `(kem_ct, kem_ss)`，合成根密钥、起棘轮，然后把 `kem_ct` 用单独事件发给对端。
5. 解封方先把 `(epub, dh_shared)` 挂进 `_pendingPq`，收到 `kem_ct` 后 `Decapsulate` 合成同一把根密钥，起棘轮，再把期间攒下的密文排空解密。
6. 对端是旧版本、没上报 `kpub` 的，降级成纯 X25519，并且在"安全事件"栏打一条警告。

也就是说降级是静默可发生的，只是界面上会提示。真要强制全 PQ，得自己加策略。

## 目录

```
.
├── server/
│   ├── server_v2.py            32759 端口，python-socketio AsyncServer + uvicorn
│   ├── gen_self_signed_cert.py 生成加密私钥的自签证书
│   └── run_server.bat
├── E2EChatClient/              C# WPF，.NET 10
│   ├── Crypto/Curve25519.cs    手写 X25519，V1/V2 共用
│   ├── CryptoV2/               Blake3 / XChaCha20Poly1305 / Ed25519 / DoubleRatchet
│   │                           / MlKemHybrid / TrafficObfuscator / GpuKeyPool / IdentityStore
│   ├── Net/                    SocketIoClient（手写 Socket.IO v5 over WebSocket）
│   │   └── V2/ChatSessionV2.cs 会话层：混合握手、棘轮、分片、身份钉定
│   ├── UI/                     MainWindow
│   └── Native/CryptoLibBridge.cs   只探测 GPU/DLL 状态，主链路不依赖
├── cryptolib/                  GPU 侧的 CUDA 内核与 C 封装，非主链路
├── installer/                  WinForms 安装器，payload.zip 作为嵌入资源打进去
└── BUG_ANALYSIS_REPORT.md / BUG_FIX_REPORT.md   两轮审计的问题清单和修复记录
```

`cryptolib/` 里那些没实现的占位函数用 `#error` 硬失败处理了，编译不过去是故意的——防止半成品 DLL 被顺手打进发布包。V2 客户端不加载这个 DLL，看到"CryptoLib.dll 缺失"提示可以忽略。

## 跑起来

服务端：

```cmd
cd server
run_server.bat
```

客户端要么直接跑编译产物，要么：

```cmd
run_client.bat
```

界面顶部填服务器地址、端口、昵称、房间，点连接。连上后自动生成临时 X25519 密钥，右侧成员列表带 BLAKE3 指纹，回车发送。右下角"安全事件"实时报 BLAKE3 校验、棘轮推进、验签失败、篡改告警。

## 部署前必须知道的几件事

**默认是明文 `ws://`。** `UseTls` 默认 `false`，这是为了方便不开证书就能联调，代价是握手里的临时公钥、成员关系、消息外壳在链路上裸奔——同 Wi-Fi、ISP、企业网关都能看元数据。生产环境必须：

- 服务端 `python server_v2.py --tls-cert cert.pem --tls-key key.pem --tls-key-pw '<口令>'`
- 客户端勾上 TLS，并把 `gen_self_signed_cert.py` 打印的证书 SHA256 指纹粘进指纹框

**勾了 TLS 但指纹留空会直接拒连。** 这是修掉的一个坑：以前"勾 TLS 就信任任意自签"，等于加密但没认证，中间人递一张自签证书就过去了。现在只接受指纹完全匹配的证书。

**私钥现在带口令。** `gen_self_signed_cert.py` 用 AES-256 + PBKDF2 加密私钥，口令要求 12 字符以上，交互式输入或者 `--password-stdin`。证书有效期从 3650 天缩到 365 天。

**要抗主动中间人，得带外核对指纹。** TOFU 只在"第一次连接时没有中间人"这个前提下成立。双击右侧成员，弹窗给出该对端临时公钥的完整 64 字符 BLAKE3 指纹，通过电话、当面、或者另一条已认证信道核对。不一致就立刻断开，换 `wss://` 加严格指纹锁重来。

**发布出去的 exe 不可审计。** 安装器里的 `payload.zip` 没有签名校验，谁都能替换。要么从源码 `dotnet build -c Release` 自己编，要么就别把它当可信分发用。

## 已知没做的

- `SocketIoClient.CLIENT_GATE_TOKEN` 是一个硬编码常量，只用来挡浏览器直连和 curl、Postman 这类通用客户端，不是认证，而且它就在公开仓库里。
- 服务端零持久化意味着没有任何封禁能力，也意味着重启后房间状态全丢。
- 限流是 5 秒瞬窗口，不做慢速统计。
- 没有前向安全之外的"事后安全"（SFs / 丢弃历史私钥）处理。
- GPU 那条路（`cryptolib/`、`GpuKeyPool`）只是密钥池和探测，没接管主链路。

## 构建与发布

产物不进仓库，全部挂在 Releases 上。仓库的 `.gitignore` 已经排除了 `bin/`、`obj/`、`installer/Payload/*.zip`。

完整重编是三步，顺序不能错，因为安装器是**把 payload.zip 当嵌入资源编译进去**的：

```cmd
dotnet publish E2EChatClient/E2EChatClient.csproj -c Release -o E2EChatClient/bin/Release/publish
rem 用 publish 目录里的内容重打 installer\Payload\payload.zip（保持相对路径，安装器按目录结构解压）
dotnet publish installer/Installer.csproj -c Release -o installer/bin/Publish
```

安装器是自包含单文件 win-x64，开了压缩，出来 60MB 上下。客户端 publish 是依赖框架的，目标机要装 .NET 10 Windows Desktop 运行时。

**别拿旧产物当新的用。** 之前 `installer/bin/Publish/Installer.exe` 是 7 月 17 日的构建，里面不含 9 月那批加密修复，而它当时正是 Releases 上挂的那一个。发布前对一下时间戳和提交。

## 排错

| 现象 | 先看哪 |
|---|---|
| 连不上 | 服务端有没有报错、32759 有没有被占、防火墙 |
| CryptoLib.dll 缺失 | 正常，V2 主链路不走这个 DLL |
| 编 cryptolib 报 `#error` | 故意的，占位实现不允许编译 |
| XChaCha20 解密失败 | 双方棘轮不同步，多半是丢包导致链错位 |
| Ed25519 验签失败 | 身份公钥被换，或者你正在被中间人 |
| 检测到篡改(BLAKE3) | 密文在路上被改过 |
| 身份钉定失败 (id_pub 不一致) | 同一个 sid 换了 Ed25519 身份公钥，按冒充处理，已拒 |
| 一直等不到 kem_ct | 对端没上报 PQ 公钥，会降级成纯 X25519，看安全事件栏 |
| 列表里看不到对方 | 等 `new_member_request`，或者断开重连一次 |
