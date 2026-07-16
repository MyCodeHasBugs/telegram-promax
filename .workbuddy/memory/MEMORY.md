# 项目长期记忆 — E2E 加密聊天 (launcher)

## 部署模型 / 威胁模型
- **闭环私有部署**: 只有用户自己的客户端能连用户自己的服务器; 客户端有限制,
  且**不允许多开**。现实对手只有 **客户端↔服务器之间的网络 MITM / 被动监听**。
- 恶意房间成员 / 跨房间 / 槽位耗尽 / 放大 DoS 等"需不可信对端或大量并发"的面不成立。
- 安全工作重心 = **传输层认证 (wss + 证书指纹锁)** + **密钥交换认证 (已在握手/每消息层做)**。

## 已被正确修复 (截至 2026-07-16, 勿重复报)
- 低阶点攻击 (X25519 cofactor 校验, Curve25519.cs:46-95) ✅
- 跨房间投递 (relay 按 room 校验 target, 跨房即踢) ✅
- F4-1 临时密钥 zeroize / F4-2 身份 TOFU 钉定+写入锁 / F4-4 CUDA+死代码 #error 闸 ✅
- **F3-3 密钥交换认证**: 服务端 `auth` 强验 Ed25519 `id_sig` 绑定 (epub,room)
  (server_v2.py:321-336 + _verify_id_sig:63-78); 客户端握手对 (epub,room) 签名
  (ChatSessionV2.cs:148-166)。MITM 改写 auth.epub 被服务器拒。✅
- **F2 dh_pub 防失同步**: 每消息 Ed25519 签 (dh_pub||n||cipher), 改 dh_pub 即验签失败 ✅
- **GUI TLS footgun 已根除**: 勾 TLS 必须填证书 SHA256 指纹, 否则拒连;
  `AllowSelfSigned` 强制 false (MainWindow.xaml.cs:70-83)。明文 ws:// 改为强制
  informed-consent 弹窗 (同文件:88-104)。✅
- 连接闸门 token (X-E2EChat-Client header) + 未 auth 8s 回收 + 每 /24 子网配额 8 ✅
- relay_slice: 单 slice >1024B 拒 + 100/5s 条数 + 256KB/5s 字节双限 + 跨房踢 ✅
- 身份 pinning 走 `_peerRegLock` 与 RegisterPeer 互斥; HandleNewMember 不覆盖已注册 sid 的 epub ✅

## 仍需注意 (闭环模型下, 网络路径是唯一真实暴露面)
- 🔴 **若实际跑 ws:// 明文**: 链路主动 MITM 仍可元数据窃听 + 传输帧注入 (假 new_member/
  server_event 致 DOS); `id_sig` 保护 E2E 密文但不认证传输帧。治本 = 服务器加
  `--tls-cert/--tls-key` + 客户端 wss + 粘贴指纹; 最好直接禁明文模式。
- 🟠 **首次连接 TOFU MITM**: 若攻击者恰在首次连接链路上且用户未做带外指纹核对,
  可顶替身份。自有服务器可预共享证书指纹 (永远 wss+pin, 不用明文) 闭环此洞;
  GUI 已加 epub 完整 BLAKE3 指纹双击带外核对作兜底。
- 🟡 **服务器自签证书私钥明文落盘、10 年有效期**: 主机被攻陷→可对该客户端 MITM
  (客户端 pin 该证书)。护好私钥; 考虑缩短有效期 / 自签 CA。
- 🟡 **dist/ 预编译二进制**: 若非自源码构建, 存在供应链风险, 应自构建。

## 三不原则 (现状)
- 仍保留"不持久化 IP/时间戳/指纹", 但新增 **内存态 /24 子网配额 (F4-3,
  server_v2.py:202-219)**, 断连即 pop, 不落盘。与"用内存态短期源标识"建议一致,
  DoS 防护在该约束下已闭环。

## 项目结构速记
- 客户端: E2EChatClient/ (C#), 主链路走 C# Curve25519.cs / DoubleRatchet.cs;
  cryptolib.dll 仅只读探测, 非主链路。
- 服务器: server/server_v2.py (python-socketio AsyncServer + uvicorn, 端口 32759,
  BLAKE3 C 扩展)。客户端只发 `relay_slice`, 不发 `relay_message`; 服务端/客户端
  均不校验 relay_slice 信封 (E2E 完整性交由客户端 ProcessEnvelope 强制)。
