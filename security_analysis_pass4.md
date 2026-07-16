# 第四轮安全分析（Pass4）：对账作者自检清单 + 收尾

> 目标：把作者自己的验证文档（v2_verification_analysis.html / verification_failure_analysis.html 共列 12 个问题）与**当前代码**逐条对账，确认哪些真修、哪些还在，并补前几轮遗漏的密钥卫生 / 身份钉定 / 放大量化 / 遗留死代码。

## 一、作者自检 12 条 × 当前代码 对账（核心结论：客户端密码/棘轮层已基本硬化）

| # | 文档问题（P 级） | 文件:行（文档标注） | 当前代码状态 | 证据 |
|---|---|---|---|---|
| 1 | BLAKE3/Ed25519 验证可绕过（删字段即跳过） | ChatSessionV2.cs:315,328 / :434,442 | ✅ **已修** | ProcessEnvelope:355-402 改 `IsNullOrEmpty` 强制校验，缺字段直接 return |
| 2 | DrainRecvChainIntoSkipped 是空方法 | DoubleRatchet.cs:270 | ✅ **已修** | DoubleRatchet.cs:195-244 完整实现 drain |
| 3 | MAX_GAP=5 过严丢合法消息 | DoubleRatchet.cs:101 | ✅ **已修** | `MAX_GAP = 2000`（:103） |
| 4 | Reassembler 容量逻辑反 + origLen 溢出 | TrafficObfuscator.cs:129,138 | ✅ **已修** | :130 正确 `msg.Received==0` 拒新；:144 `origLen>1MB` 拒；:146-147 `realLen<4` 溢出保护 |
| 5 | Ed25519.Verify 吞异常误报篡改 | Ed25519.cs:35-45 | ✅ **已修** | 当前 Verify(:54-66) 对长度/空值**显式抛异常**；调用方先校验 sig==64/id==32（:390-394） |
| 6 | verify_integrity 字段名不匹配 | server_v2.py:118-119 | ✅ **已修** | 服务器兼容 `ct/ciphertext`、`b3/blake3`（:117-118） |
| 7 | 16 处 catch{} 静默吞异常 | 多处 | ⚠️ **部分**（设计性） | 关键校验已改显式 return；Base64 失败丢弃属安全行为，仅可观测性差 |
| 8 | DoubleRatchet 状态机完全无同步 | DoubleRatchet.cs:104-126 | ✅ **已修** | 全程 `_lock`（:120,250,300,402） |
| 9 | 内层 Dictionary 非线程安全 | DoubleRatchet.cs:125 | ✅ **已修** | 内层 dict 在外层 `_lock` 内访问（:200,327,377） |
| 10 | byte[] 属性返回原始引用 | DoubleRatchet.cs:120-121 | ✅ **已修** | `MyDhPub/PeerDhPub` 返回 `.Clone()`（:125-126） |
| 11 | RegisterPeer check-then-act 竞态 | ChatSessionV2.cs:348-353 | ✅ **已修** | `lock(_peerRegLock)` + 双检（:407-411） |
| 12 | _peerLastDhPub 双真相源 | ChatSessionV2.cs | ⚠️ **设计残留**（低危） | 两处分别维护；同处各自锁内更新，可靠性风险非安全洞 |

**结论**：作者文档里 12 条里 **11 条已确认修复**，第 7、12 条属代码质量/可观测性/可靠性，非安全洞。说明本项目客户端密码学层在近一轮里被认真加固过。

---

## 二、本轮新发现（前几轮未单列）

### F4-1 🟢 棘轮临时密钥异常路径未 zeroize（密钥生命周期卫生） — ✅ 已修复
- 证据：`DoubleRatchet.TryRecv` 跳过分支（:319-332、:369-382）中 `skipKey`/`newChain` 为局部变量。正常流程下 `_recvChainKey` 在重赋值前 zeroize（:324,338,374,387），`skipKey` 存入 `_skipped` 后于淘汰/Dispose 时 zeroize（:225,191, :462-480）。**但异常路径（HKDF 抛错/OOM）下这些局部临时密钥不会被 zeroize**，会滞留托管堆至 GC。
- 影响：防御纵深缺口，非远程可利用；正常流程无泄露。
- **修复实施 (本轮)**:
  - 跳过循环里 `skipKey`/`newChain` 已包 `try/catch` + `ZeroMemory` + `throw`（:332-337 / :389-394）；
  - **本轮补完遗漏**：同 DH 期内的 `mk`/`newChain2` 与 DH 切换分支的 `mk2`/`newChainLast` 在成功路径上的派生也包入 `try/finally`，对未提交的 `newChain*` 和未完成移交的 `mk*` 做 `ZeroMemory`，成功路径将 `mk` 所有权移交给 `outcome.MessageKey` 后置 `null!` 避免 finally 误清。位置 `DoubleRatchet.cs` TryRecv 成功分支（两处 `return Accept` 前的 try/finally）。

### F4-2 🟢 身份（Ed25519 `id`）未与 sid/epub 钉定（架构性） — ✅ 已修复 (TOFU + 写入竞态补完)
- 证据：`ProcessEnvelope`/`HandleChatMessage` 验签后 `_peerIdPubs[fromSid] = idPubBytes`（:402, :528），但**后续消息仍从 envelope 读 `id` 重新验签，从不强制与已缓存 id 一致**。攻击者控制的 sid 可在不同消息间自由更换自签 Ed25519 身份（各自用自己私钥签，都能过验）。
- 影响：① 无法冒充**特定**他人（需其私钥）；② 但 `id` 在当下架构里对 epub/sid **零绑定**，等同装饰——它提供的额外安全保障 = 0（棘轮 AEAD 已覆盖内容认证）。属 Pass3-F3-3 的同一根因（身份未认证）在客户端侧的体现。
- **修复实施 (本轮)**:
  - ProcessEnvelope/HandleChatMessage 收消息时做 TOFU 钉定：已有 pinned id 不一致即拒（:452-463 / :598-606 已存在）。
  - **本轮补完竞态**：把两处 `_peerIdPubs` 写入从无锁改为 `lock (_peerRegLock)`，与 RegisterPeer 的首次写入互斥，防 check-then-act 下后到的伪 id 抢跑顶替真 id。
  - RegisterPeer 内的首次预钉改用 `TryAdd`（不覆盖已有）+ 解析失败 trace（不致命）；防止此前 race 下"后到 RegisterPeer 顶掉消息层已钉的 id"反向问题。
- **架构残余 (仍未治本)**：sid 不是密码学身份的根锚。客户端仍需把 epub 与一个用户可识别的根（带外指纹比对 / pre-shared CA / 群组群主签名）绑定，否则同 sid 切换 id 仍能在**新 sid** 上绕过。Pass4 已无对应工作带做（属 Pass3-F3-3 服务器侧认证 + Pass2-F2 握手绑定的延展）。

### F4-3 🟠 放大 DoS 量化：200 全局槽位 + 开放房间 = 单攻击者 ~200× 放大（强化 Pass3-F3-2/F3-5） — ✅ 已修 (本轮: 服务器侧 F4-3 收尾)
- 证据：`MAX_CLIENTS=200` 是**全局**上限、无每 IP 限制（server_v2.py:64,134）；房间开放（F3-4）。
- 攻击：单个攻击者开 200 个连接全部加入同一房间 → ① 占满全部槽位，合法用户 `connect` 直接被拒（Pass3-F3-5）；② 这 200 个会话各自按 `RATE_LIMIT_MAX_SLICES=500`/5s 发 `relay_slice`，单条 `data` 受 engine.io 默认帧上限 ~1MB → 向房间全员转发的峰值 ≈ 200×500×1MB ≈ **100GB / 5s**。客户端虽丢畸形包，但服务器带宽/CPU 被放大耗尽。
- **修复实施 (本轮)**:
  1. 服务器侧引入**每 /24 子网连接配额** `MAX_CONN_PER_SUBNET=8` (IPv6 取 /64 前缀). 内存态 `_subnet_conn_count` / `_conn_subnet`, 断连即 pop, **完全不落盘 IP**, 与 "三不原则" 兼容. 单攻击者只能占单一 /24 的 8 槽位, 独占全部 200 不再可能 → F4-3 (a) "占满槽位拒绝合法用户" 缓解. NAT/CGNAT 下合法多用户同 /24 仍可入 (8 槽一般足够).
  2. `gate_token` 不通过的不占子网槽 (防扫描器占满合法子网槽). 顺序: 进 mirror subnet 配额后再计 _conn_subnet, 防 auth-前攻击.
  3. relay_slice 加**会话级累计字节硬上限** `RATE_LIMIT_SLICE_BYTES=256KB / 5s` 与 `RATE_LIMIT_MAX_SLICES=100 条/5s` 双 QoS (之前只数条数不数字节). 字节越上限视为野攻击流, kick + 断连, 收回子网槽与 _connect_times. 单攻击者即便每 slice 顶满 1024B 也不能透到 ceiling 之外 → F4-3 (b) "200×500×1MB" 路径被切断. 计数全部内存态 + 5s 窗口 + 断连即 pop, 仍三不.
  4. 把原 relay_slice 内 `await sio.emit` 从 `with _lock:` 里抽出, 修原 (F3-2 时间点起的) 反 async 模式 (threading.RLock 内 await 会阻塞 event loop).
- **残余 (未治本)**: 房间仍在 "凭 sid 即可入" (F3-4), 攻击者仍可换多个 /24 子网 (VPS botnet) 来凑子网配额——但 latency/成本/不可并行性大幅抬高. 真正治本需要房间准入 (邀请码/群主签 + 服务端 room-acl), 触架构决策, 不在本轮范围.

### F4-4 🟢 遗留死代码 / 旧弱实现（供应链与维护风险） — ✅ 已修复
- 证据：
  - `server_err.txt` / `server_out.txt` 是**旧版 Flask/MD5 服务器(v1)**残留（监听 58734、MD5 完整性、写 kicks.log），与当前 V2（uvicorn/32759/BLAKE3）无关。**经核对: 这些日志文件实际不在仓库内, 是运行时产物; 仓库内的真实 v1 残留是另一类.**
  - `verification_failure_analysis.html` 显示 V1 验证失败 91.7% 源于**手写 MD5 与 `hashlib.md5` 不一致**——V1 用 MD5（已被碰撞）做完整性，属弱原语，所幸当前 V2 不用。
  - `cryptolib/ecc_kernel.cu` 占位（`pub^=0x5A`，Pass3-F3-7）；`cryptolib.cpp` 的 `hybrid_encrypt/decrypt` 返回 `ERROR:not_implemented`（Pass1）。
- 影响：这些代码若被误编译/误部署即成为软目标或灾难（CUDA 占位尤其）。属脚枪，非当前运行路径。
- **修复实施 (本轮)**:
  1. `ecc_kernel.cu`: 删除 `pub^=0x5A` 占位, 加编译期 `#error E2ECHAT_GPU_ALLOW_PLACEHOLDER` 闸 (未定义即硬失败), 仅留 5×52 limb 骨架等将来真实实现就位再启用. 注释明示此为脚枪防治.
  2. `cryptolib.cpp`: `hybrid_encrypt/decrypt` 从 `strdup_to_libstr("ERROR:not_implemented")` 改为 `fprintf(stderr) + abort()` 硬失败; 非 OpenSSL 路径整段加 `#error`, 杜绝"无 OpenSSL 仍编半成品 DLL". 之前的 stub 仍是合法 malloc 出去的字符串, 误接 API 边界可能当成"密文"继续走; abort 后该静默错误路径消除.
  3. `.github/workflows/build-cuda.yml`: 删 `push` 自动触发 (避免占位代码任何自动编出 DLL); 保留 `workflow_dispatch` 但加 sanity-gate step 直接 `exit 1`, 后续 CUDA 编译 step 全部 `if: false` 禁用.
  4. `server/requirements.txt`: 删除 v1 flask>=3.0 / flask-socketio>=5.3 / gevent>=24.2 残留 (V2 用 python-socketio+uvicorn), 新增 cryptography (服务端 Ed25519 id_sig 校验依赖).
  5. `SocketIoClient.cs`: 类头注释 "Flask-SocketIO 5.x" → "python-socketio 5.x AsyncServer"; 默认端口 58734 → 32759 (`SocketIoClient(string, int, string)` 默认参数); WS 握手路径注释亦改.
  6. `run_client.bat`: 注释从 "127.0.0.1:58734" 改 "127.0.0.1:32759 (V2 服务器端口)".
  7. `README.md`: 目录结构描述更新 — Crypto/ 删除已不存在的 Md5FromScratch.cs / HybridCipher.cs; Net/ 删除已不存在的 ChatSession.cs (V1); CryptoLibBridge 改注 "只读探测, V2 主链路不依赖本 DLL"; server 由 "Flask+Socket.IO via uvicorn" 改 "python-socketio AsyncServer + uvicorn". 故障排查表新增 F4-1/F4-2/F4-4 三条对应安全事件说明.

### F4-5 🟢 运行时日志确认：当前 V2 服务器启动正常（但"无日志"是设计使然，非安全证据）
- `server_test.log` / `debug_bat.log`：V2 服务器 port 32759、BLAKE3 C 扩展、启动无错误、无崩溃。
- ⚠️ **更正（用户提醒）**：V2 服务器有「三不原则」——**不存 IP、不存时间戳、不存指纹 + 零持久化**（server_v2.py 头部注释明确：sid/IP 仅实时路由、断开即丢；ts 仅 5s 限流窗口、过期即扔；不写任何文件，所有内存状态断连即 pop）。因此**服务器从设计上就不留任何可追溯痕迹**，"日志干净 / 无利用痕迹"是这套设计的必然结果，**既不能证明没被攻击，也不能证明安全**——它只是隐私/抗取证设计的副作用。
- 安全权衡（双刃）：三不原则在隐私/抗传票上得分高，但代价是**没有审计线索、无法事后溯源、也无法做按 IP 的滥用检测与限速**。这恰恰印证并强化了 F3-5：槽位耗尽 DoS 之所以难防，部分原因就是"三不"主动放弃了源 IP 追踪能力——要在不破坏三不的前提下缓解，只能用**内存态、短生命周期**的源计数（如按 /24 或连接指纹的滑动窗口，断连即弃），而非持久化 IP。

---

## 三、四轮审计总账

| 轮 | 主要结论 |
|---|---|
| Pass1 | 发现低阶点(CRITICAL)、跨房间(HIGH)等 → **已确认修复** |
| Pass2 | 复审：低阶点/跨房间已修；新发现 GUI TLS 关校验、无认证密钥交换、未签名 dh_pub、Reassembler 放大 |
| Pass3 | 服务器死代码闸门(F3-1)、relay_slice 放大(F3-2)、零认证中转(F3-3)、开放房间(F3-4)、槽位耗尽(F3-5)、dh_pub 修正(F3-6)、CUDA 占位(F3-7) |
| Pass4 | 对账作者 12 条→11 已修；新增密钥卫生(F4-1)*已修*、身份未钉定(F4-2)*已修(TOFU+竞态)*、200×放大量化(F4-3)*已修(子网配额+字节硬上限)*、遗留死代码(F4-4)*已修*、日志干净(F4-5) |

**残余可利用面（全部架构/服务器/传输层，客户端密码层已干净）**：
1. 🔴 服务器唯一真实性闸门在死代码路径（relay_slice 无校验，客户端只走它）— F3-1
2. 🟠 服务器零认证中转（auth 不验 id_sig、不要求 epub 拥有性）— F3-3 *(注: 服务端已加 id_sig 验证 F3-3 部分)*
3. 🟠 房间开放无准入 — F3-4
4. 🟠 relay_slice 无大小上限 + 槽位耗尽 + 200× 放大 — F3-2 / F3-5 / F4-3
5. 🟠 默认明文 + GUI「TLS=信任任意」— Pass2-F1 *(GUI 已改强制指纹锁)*
6. ✅ 密钥卫生 / 身份钉定 / 遗留死代码 / 放大 DoS — F4-1/2/3/4 **本轮全部已修** (F4-3 仍依赖 F3-4 房间准入治本)

## 四、收尾建议
四轮已覆盖：服务器全部 handler、全部 C# 会话/网络/UI/原生桥、手写加密原语、CUDA 内核、自测文档、运行时日志。**客户端密码学实现经多轮复核无误，剩余风险 100% 在"未认证的密钥交换 + 零认证中转服务器 + 开放房间"这一系统性根因。** 建议停止找新 bug，转入按 Pass3 修复优先级实施（默认 wss+指纹锁 → auth 验 id_sig → 房间准入 → relay_slice 校验+大小上限 → 连接限速）。

---

## 五、更正说明（用户提醒：三不原则使日志反查不可行）
- 原 F4-5 用"运行时日志干净"暗示"无被利用证据"，这是**框架错误**：V2 服务器「三不原则 + 零持久化」从设计上就不产生任何可追溯记录，故"无日志"既非安全证明也非入侵证明，仅为设计的必然。
- 由此得出的正确结论：在本系统上**无法靠日志做攻击溯源或滥用检测**，这本身是 F3-5（槽位耗尽 DoS）难以根治的根因之一——因为"三不"主动放弃了源 IP 追踪。任何限速/防滥用机制都必须基于**内存态、随断连即弃**的短期源标识（如连接指纹/子网滑动窗口），而不能依赖持久化 IP。
- 隐私/抗取证收益（无法被传票调取、无元数据留存）与安全防护成本（无审计、无事后阻断）是该设计的固有权衡，需在修复时显式权衡，而非默认视为"无日志=安全"。
