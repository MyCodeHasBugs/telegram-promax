"""
端对端加密聊天服务器 v2  (Signal-style 安全栈)
==============================================================

端口: 32759
架构: python-socketio 原生 AsyncServer + uvicorn (ASGI)
       (已弃用 flask_socketio + werkzeug, 因 Python 3.14 + Werkzeug 处理 polling
        keep-alive 时抛 `AssertionError: write() before start_response`, 导致
        engine.io handshake 偶发性失败).

"三不"原则 (核心):
  1. 不存 IP     (request.remote_addr / sid 仅用于实时挂 source, 断开立刻丢)
  2. 不存时间戳  (ts 仅用于瞬时限流计数, 5s 窗口作废即扔)
  3. 不存指纹    (上版用 md5(pubkey) 作 banned 字典, 这版彻底取消)

完整性校验:
  客户端 metadata.blake3 = BLAKE3(ciphertext) 32-byte hex (64 字符)
  服务器验:
    - sender_pub 与 session 注册一致  ⇒ 否则踢 (冒充)
    - 重算 BLAKE3 与 metadata.blake3 比 ⇒ 不一致则丢消息 (中间人可能嫁祸)

哈希算法:
  强制 BLAKE3 (32-byte hex output). 优先用 PyPI `blake3` 包 (与官方 Rust 实现同源,
  与客户端 CryptoV2/Blake3.cs 字节级一致). 启动时跑 self-check, 不一致立刻拒绝启动.

零持久化:
  * 不写文件
  * 所有内存状态: sessions / rooms / rate_log, 断连后立即从字典中 pop
"""

import sys
import time
import uuid
import base64

# ============================================================
#  BLAKE3 (强制: 32-byte hex output)
# ============================================================
import blake3 as _blake3_mod

_HAVE_FASTMODULE = True


def _hash32(b: bytes) -> str:
    return _blake3_mod.blake3(b).hexdigest()


HASH_ALGO = "BLAKE3"

# ============================================================
#  Ed25519 服务端认证 (F3-3 修复)
#  ----------------------------------------------------------
#  在握手阶段强制验客户端发来的 (id_pub, id_sig) 对 (epub, room) 的
#  Ed25519 签名, 阻止网络中间人改写 auth.epub (否则可 MITM 棘轮).
#  用 cryptography 包 (gen_self_signed_cert 已依赖).
# ============================================================
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


def _verify_id_sig(id_pub_b64: str, id_sig_b64: str, epub_b64: str, room: str) -> bool:
    """验 Ed25519(id_priv, bytes(epub_b64 + "@" + room)) == id_sig.
    返回 True/False. 任意一步异常都返回 False."""
    try:
        id_pub_bytes = base64.b64decode(id_pub_b64, validate=True)
        id_sig_bytes = base64.b64decode(id_sig_b64, validate=True)
    except Exception:
        return False
    if len(id_pub_bytes) != 32 or len(id_sig_bytes) != 64:
        return False
    try:
        pk = Ed25519PublicKey.from_public_bytes(id_pub_bytes)
        pk.verify(id_sig_bytes, (epub_b64 + "@" + room).encode("utf-8"))
        return True
    except (InvalidSignature, Exception):
        return False

try:
    if (_hash32(b"")
            != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"):
        print("[FATAL] BLAKE3 self-check failed: BLAKE3(\"\") hash mismatch",
              flush=True)
        sys.exit(1)
except Exception as _ex:
    print(f"[FATAL] BLAKE3 self-check crash: {_ex}", flush=True)
    sys.exit(1)

# ============================================================
#  配置
# ============================================================
HOST                    = "0.0.0.0"
PORT                    = 32759
MAX_CLIENTS             = 200
RATE_LIMIT_WINDOW       = 5
RATE_LIMIT_MAX          = 25
RATE_LIMIT_MAX_SLICES   = 100   # F3-2: 从 500 降到 100 /5s, 抗放大 DoS
# F4-3: relay_slice 会话级字节硬上限. 当前单 slice ≤ 1024B (见 relay_slice 内),
# 但老逻辑只数 slice *个数* 不数字节, 单条 slice 仍可发 ~1KB → 100×1KB=100KB /5s.
# 更严的做法: 5s 窗口内每会话累计 data 字节 ≤ RATE_LIMIT_SLICE_BYTES,
# 超额即 kick+断连, 切断"短头大号"放大. 默认 256KB/5s 仍足够合法长消息.
RATE_LIMIT_SLICE_BYTES = 256 * 1024   # 5s 内 relay_slice 累计字节上限

# ============================================================
#  python-socketio 原生 AsyncServer + ASGI
# ============================================================
import logging                                                  # noqa: E402
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("e2e-v2")
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.INFO)
log.setLevel(logging.WARNING)

import socketio                                                  # noqa: E402
import asyncio                                                   # noqa: E402

# AsyncServer (asyncio). async_mode 让我们用 ASGI app.
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins="*",
    ping_timeout=20,
    ping_interval=10,
    logger=False,
    engineio_logger=False,
)

# ============================================================
#  内存状态 (零持久化)
# ============================================================
sessions:        dict[str, dict] = {}   # sid -> {sid, epub, room, login_ts}
rooms:           dict[str, set]  = {}   # room -> set(sid)
rate_log:        dict[str, list] = {}   # sid -> list[float]   (relay_message)
rate_log_slices: dict[str, list] = {}   # sid -> list[float]   (relay_slice)
# F4-3: relay_slice 字节硬上限的滑动窗口累计 (sid -> list[int] 字节). 与
# rate_log_slices 同窗, 同步过期. 断连时由 disconnect 一并清掉.
rate_log_slice_bytes: dict[str, list] = {}

# N1 修复 (2026-07-16): 房密码 brute-force 防护. auth handler 加独立失败计数,
# 不复用 relay_message 的 rate_log (那条只在校验过 auth 之后才起作用, 房密码错
# 阶段根本进不到 relay_message). 每房每 5 分钟窗口 5 次失败即拒 + 指数退避.
# 全内存态, 不落盘.
ROOM_PW_FAIL_MAX        = 5
ROOM_PW_FAIL_WINDOW_SEC = 300   # 5 min
_room_pw_failures: dict[str, list] = {}   # room -> list[float] timestamps of failures

# F3-4 房间准入: room -> {owner_sid, password_hash, created_at}
#   password_hash = BLAKE3(room || ":" || password_hex).hex (加 room 名做域分离, 防撞表)
#   全内存态, 不落盘; room 空 (所有 owner/member 都断开) 即 pop (disconnect 末尾清).
# 默认 "lobby" 是无密码房间 (向下兼容老客户端).
room_metadata: dict[str, dict] = {}

import threading                                                 # noqa: E402
_lock = threading.RLock()

# F3-5: 记 connect 时间, 未 auth 超时回收, 防 slot 耗尽 DoS
_connect_times: dict[str, float] = {}

# F5 房主踢人: 被踢者 10 分钟内不可再加入该房. 全内存态, 房间空即清, 不落盘.
# 用 id_pub (Ed25519 身份公钥) 作禁入键 — sid 重连即变, epub 每会话换,
# 唯有 id_pub 跨重连稳定且经 id_sig 验证不可伪造.
KICK_BAN_SECONDS = 600   # 10 分钟
_room_kicks: dict[str, dict[str, float]] = {}   # room -> {id_pub_b64 -> expiry_ts}


def _cleanup_expired_kicks(room: str) -> None:
    """清理本房过期的踢出禁令. 调用方需持 _lock."""
    kicks = _room_kicks.get(room)
    if not kicks:
        return
    now = _now()
    expired = [k for k, exp in kicks.items() if exp <= now]
    for k in expired:
        kicks.pop(k, None)
    if not kicks:
        _room_kicks.pop(room, None)


def _now() -> float:
    return time.time()


async def _reap_unauthed_loop():
    """每 2s 清一次: connect 后 MAX_UNAUTH_SECONDS 内未 auth 的 sid 踢掉."""
    while True:
        await asyncio.sleep(2)
        now = _now()
        to_kick = []
        with _lock:
            for c_sid, ts in list(_connect_times.items()):
                if now - ts > MAX_UNAUTH_SECONDS and c_sid not in sessions:
                    to_kick.append(c_sid)
                    _connect_times.pop(c_sid, None)
        for c_sid in to_kick:
            try:
                await sio.disconnect(c_sid)
                log.warning("reaped unauthed sid=%s (no auth within %ds)",
                             c_sid, MAX_UNAUTH_SECONDS)
            except Exception:
                pass


# ============================================================
#  完整性检查 (relay_message 路径)
# ============================================================
def verify_integrity(envelope: dict, session_epub: str) -> tuple[bool, str]:
    epub = envelope.get("epub", "")
    if epub != session_epub:
        return False, "epub 与 session 注册不一致 (冒充满)"

    cipher = envelope.get("ct") or envelope.get("ciphertext") or ""
    b3     = envelope.get("b3")  or envelope.get("blake3")    or ""
    if not cipher or not b3:
        return False, "缺 cipher/blake3"

    calc = _hash32(cipher.encode("utf-8"))
    if calc != b3:
        return False, f"blake3 mismatch s={calc[:8]} c={b3[:8]}"
    return True, "ok"


# ============================================================
#  客户端身份闸门 (protocol pinning)
#  ----------------------------------------------------------
#  浏览器/socketio-default client 都不会带自定义 HTTP header,
#  我们要求 connect 时 HTTP_X_E2ECHAT_CLIENT == 一个 hard-coded token.
#  token 在客户端 EXE 内嵌 (反编译可拿到, 但挡浏览器 + 通用 sio 客户端零成本).
#  token 与 client Ed25519 id 锁 + 单实例锁合力: 单机单 client, 攻击者需逆
#  EXE 才能伪造一条 connect, 但还要签 id_sig 才进 auth, 攻击成本极高.
# ============================================================
CLIENT_GATE_TOKEN = "E2EChat/v2/client-auth-token-3f8a7c1d9b5e4d2a"
MAX_UNAUTH_SECONDS = 8  # F3-5: connect 后 8s 内必须 auth, 否则踢


def _hash_room_password(room: str, password: str) -> str:
    """F3-4: 房间密码哈希. 用 room 名做域分离 (同密码不同房间哈希不同),
    防 rainbow table. 返回 BLAKE3 64 字符 hex. 走同库 _hash32 通道."""
    sep = b"\x00E2EChat/room-pw-domain\x00"   # 常量分隔, 防拼接歧义
    data = room.encode("utf-8") + sep + password.encode("utf-8")
    return _hash32(data)

# ============================================================
#  F4-3: 内存态源标识 (遵守"三不": IP 不落盘 / 不记时间戳 / 断连即弃)
#  ----------------------------------------------------------
#  V2 "三不原则"主动放弃了持久化 IP 追踪, 这正是 F3-5 (槽位耗尽) 与
#  F4-3 (200× 放大 DoS) 难根治的根因之一——任何防滥用都只能基于内存态、
#  断连即弃的短期源标识. 本节引入两个原位计数器:
#    * _subnet_conn_count:  /24 子网 -> 当前活跃 connect 数
#                           (而非每 IP, 因 NAT/CGNAT 下合法多用户会命中同 IP)
#                           MAX_CONN_PER_SUBNET 防单攻击者独占 200 槽位.
#    _conn_subnet:          sid -> 它的 /24 子网 (供 disconnect 时减计数)
#
#  IP/子网只活在内存 dict 里, 不写文件, 不记时间戳, 断连即 pop.
#  合法多 NAT 用户同 /24 仍可连 (默认 8 个仍足够), 攻击者单 /24 想独占
#  全部 200 槽位被阻断 -> F4-3 缓解.
# ============================================================
MAX_CONN_PER_SUBNET = 8          # 每 /24 最多 8 个活跃连接 (含 NAT 合法用户)
_subnet_conn_count: dict[str, int] = {}   # /24 -> count, 内存态断连即 pop
_conn_subnet:        dict[str, str] = {}   # sid   -> /24,  断连时回填计数


def _subnet_24(remote_addr: str) -> str:
    """把 IPv4 压到 /24 子网; IPv6 取 /64 前缀; 异常默认全员 (zero-subnet).

    注意: 这里 *不存 IP 本身*, 只存子网前缀作短期内存态源标识. 子网字符串本身
    也不是身份指纹 (NAT 多用户共占同一子网前缀)."""
    if not remote_addr:
        return "0.0.0.0/0"
    try:
        if ":" in remote_addr:
            # IPv6: 取前 4 个 hextet 作 /64 前缀 (NAT/CGNAT 合法多用户共占)
            parts = remote_addr.split(":")
            if len(parts) >= 4:
                return ":".join(parts[:4]) + "::/64"
            return remote_addr + "/64"
        # IPv4: 取前 3 octet /24
        octets = remote_addr.split(".")
        if len(octets) >= 3:
            return ".".join(octets[:3]) + ".0/24"
        return remote_addr + "/24"
    except Exception:
        return "0.0.0.0/24"


@sio.event
async def connect(sid, environ):
    # F4-3: 每 /24 子网连接配额. 仅取 REMOTE_ADDR 的 /24 (IPv6 取 /64) 作
    # 内存态短期源标识; 不落盘, 不记时间戳, 超额即拒, 防单子网独占 200 槽位.
    remote_addr = environ.get("REMOTE_ADDR", "") or ""
    subnet = _subnet_24(remote_addr)
    with _lock:
        if len(sessions) >= MAX_CLIENTS:
            return False
        # F3-5: 统计未 auth 的连接数 (sessions 在 auth 后才填入; 此处只数 connect 槽位)
        if len(sio.environ) > MAX_CLIENTS + 50:  # socketio 内部 environ dict
            return False
        # F4-3: 子网配额. 注: _connect_times 已先于 _conn_subnet 写入,
        # 故即便未过 auth 阶段也会占子网槽 (符合 "5s 不 auth 即踢" 的期限内
        # 单子网连入 8 条仍触发拒绝的设计意图, 超额拒在 connect 时即生效).
        if _subnet_conn_count.get(subnet, 0) >= MAX_CONN_PER_SUBNET:
            log.warning("connect rejected: subnet %s has %d conns (>= %d), sid=%s",
                        subnet, _subnet_conn_count.get(subnet, 0),
                        MAX_CONN_PER_SUBNET, sid)
            return False

    # ===== 方案 A: 客户端身份闸门 =====
    # 浏览器/socketio-default 都不带 X-E2EChat-Client header -> 直接拒
    gate_token = environ.get("HTTP_X_E2ECHAT_CLIENT", "")
    if gate_token != CLIENT_GATE_TOKEN:
        log.warning("connect rejected: missing/invalid X-E2EChat-Client header (sid=%s)", sid)
        return False

    # F4-3: 已过身份闸门 + 已过子网配额 -> 写入子网计数与 connect 时间.
    # 顺序很重要: gate_token 不通过的不占子网配额 (防扫描器占满合法子网槽).
    with _lock:
        _connect_times[sid] = _now()
        _conn_subnet[sid] = subnet
        _subnet_conn_count[subnet] = _subnet_conn_count.get(subnet, 0) + 1
    log.debug("connect sid=%s subnet=%s", sid, subnet)


@sio.event
async def disconnect(sid):
    with _lock:
        me = sessions.pop(sid, None)
        if me:
            room = me["room"]
            rooms.get(room, set()).discard(sid)
            if not rooms.get(room):
                rooms.pop(room, None)
                # F3-4: 房间空了 (含 owner 已离线) 自动清 room_metadata.
                # 防人离开后房间密码"挂在内存里" 无限重连即占名; 但 attacker 可重创建,
                # 接受 (此设计语义: 房间非持久, 仅 owner 在线期间有密码门槛).
                room_metadata.pop(room, None)
                # F5: 房间空了, 踢出禁令一并清 (新房同名为不同上下文, 不继承旧禁令).
                _room_kicks.pop(room, None)
        rate_log.pop(sid, None)
        rate_log_slices.pop(sid, None)
        rate_log_slice_bytes.pop(sid, None)   # F4-3: 清字节滑动窗口
        _connect_times.pop(sid, None)  # F3-5: connect slot 回收
        # F4-3: 子网配额回填 (connect 写入过 _conn_subnet 才在这里减)
        subnet = _conn_subnet.pop(sid, None)
        if subnet is not None:
            n = _subnet_conn_count.get(subnet, 0) - 1
            if n <= 0:
                _subnet_conn_count.pop(subnet, None)
            else:
                _subnet_conn_count[subnet] = n
    log.debug("disconnect sid=%s", sid)


@sio.event
async def auth(sid, payload):
    if not isinstance(payload, dict):
        await sio.emit("auth_response", {"ok": False, "reason": "bad payload"}, to=sid)
        await sio.disconnect(sid)
        return

    epub = payload.get("epub", "")
    b3   = payload.get("blake3", "")
    room = (payload.get("room") or "lobby").strip()[:30]
    # PQ: ML-KEM-1024 公钥透传 (b64). 客户端互检微信; 服务端仅保存+转发.
    kpub = (payload.get("kpub") or "")[:8192]

    if not epub or len(epub) < 16:
        await sio.emit("auth_response", {"ok": False, "reason": "epub missing/short"}, to=sid)
        await sio.disconnect(sid)
        return

    # F3-3 critical: 强制 Ed25519 (id_pub, id_sig) 与 (epub, room) 绑定验证.
    # 之前只取 epub+room, 无任何对端身份认证 -> ws MITM 改 epub 即可解整条链.
    id_pub_b64 = payload.get("id", "")
    id_sig_b64 = payload.get("id_sig", "")
    if not id_pub_b64 or not id_sig_b64:
        await sio.emit("auth_response", {
            "ok": False, "reason": "missing id_pub/id_sig — identity binding required"
        }, to=sid)
        await sio.disconnect(sid)
        return
    if not _verify_id_sig(id_pub_b64, id_sig_b64, epub, room):
        await sio.emit("auth_response", {
            "ok": False, "reason": "Ed25519 id_sig invalid (possible MITM)"
        }, to=sid)
        await sio.disconnect(sid)
        return

    if b3:
        try:
            if _hash32(epub.encode("utf-8")) != b3:
                await sio.emit("auth_response", {
                    "ok":    False,
                    "reason": f"handshake blake3 mismatch (server={HASH_ALGO})",
                }, to=sid)
                await sio.disconnect(sid)
                return
        except Exception as ex:
            await sio.emit("auth_response", {"ok": False, "reason": f"hash error: {ex}"}, to=sid)
            await sio.disconnect(sid)
            return

    # F3-4 房间准入: 该 room 已被设密码则必须对上, 否则拒. lobby 默认无密码 (公开房).
    # N1 修复 (2026-07-16): 独立房密码失败计数 + 滑窗限流. 原注释称 "rate_log 闸门限制",
    # 但 rate_log 只在 relay_message 里消费, auth 不查; 旧实现下房密码可被高速穷举.
    room_pw = payload.get("room_password", "") or ""
    if not isinstance(room_pw, str):
        room_pw = ""
    with _lock:
        meta = room_metadata.get(room)
        fail_list = _room_pw_failures.setdefault(room, [])
        # 滑动窗口过期
        while fail_list and _now() - fail_list[0] > ROOM_PW_FAIL_WINDOW_SEC:
            fail_list.pop(0)
    if meta and meta.get("password_hash"):
        if not room_pw or _hash_room_password(room, room_pw) != meta["password_hash"]:
            with _lock:
                fail_list.append(_now())
                fails = len(fail_list)
            # 指数退避: 第 5 次起在 5 分钟内全拒 (含本次); 第 6+ 起也直接拒.
            if fails >= ROOM_PW_FAIL_MAX:
                backoff_s = min(ROOM_PW_FAIL_WINDOW_SEC,
                                2 ** (fails - ROOM_PW_FAIL_MAX))   # 第 5→1s, 6→2s, 7→4s...
                log.warning("room pw brute-force lockout: room=%s fails=%d/%d in %ds "
                            "(next allowed in >=%ds)",
                            room, fails, ROOM_PW_FAIL_MAX,
                            ROOM_PW_FAIL_WINDOW_SEC, backoff_s)
                # BUG-16 修复: backoff_s 之前只用于 log, 没在响应中告知客户端.
                #   修复: 把 retry_s 放入响应, 客户端可据此提示用户等待.
                await sio.emit("auth_response", {
                    "ok": False,
                    "reason": f"too many room password attempts, retry in {backoff_s}s",
                    "retry_s": backoff_s,
                }, to=sid)
                # 退避期内连接斩断, 让攻击者每次都得重连 + 客户端闸门 token 验签 (id_sig)
                await sio.disconnect(sid)
                return
            await sio.emit("auth_response", {
                "ok": False,
                "reason": f"room password incorrect (attempt {fails}/{ROOM_PW_FAIL_MAX} in {ROOM_PW_FAIL_WINDOW_SEC}s)",
            }, to=sid)
            # 注意: 不直接 disconnect, 让客户端输错密码重试; 输错本身不是攻击.
            # 但已锁定的房会由上面的 fail_list 长度判断拒.
            return
    # 密码对 (或房非加密): 清本房失败窗口, 攻击者得手一次不长期留 fingerprint.
    if room in _room_pw_failures:
        with _lock:
            _room_pw_failures.pop(room, None)

    # F5 踢出禁入检查: 若该 id_pub 在本房的踢出禁令期内, 拒绝加入.
    # id_pub 已由上面 id_sig 验证 (不可伪造), 故用 id_pub 作禁入键.
    with _lock:
        _cleanup_expired_kicks(room)
        ban_exp = _room_kicks.get(room, {}).get(id_pub_b64)
    if ban_exp:
        remain = int(ban_exp - _now())
        await sio.emit("auth_response", {
            "ok": False,
            "reason": f"你已被房主踢出, {remain}s 后才可再加入该房",
        }, to=sid)
        await sio.disconnect(sid)
        return

    # F5 房主重连认领: 若本 sid 的 id_pub 与 room_metadata.owner_id_pub 一致,
    # 更新 owner_sid 为当前 sid (sid 重连即变), 并在 auth_response 标记 is_owner.
    is_owner = False
    with _lock:
        meta = room_metadata.get(room)
        if meta and meta.get("owner_id_pub") == id_pub_b64:
            meta["owner_sid"] = sid
            is_owner = True
        sessions[sid] = {
            "sid":      sid,
            "epub":     epub,
            "id_pub":   id_pub_b64,  # F3-3: 绑定后下发给房间其他成员
            "room":     room,
            "kpub":     kpub,        # PQ: 随成员广播透传
            "login_ts": _now(),
        }
        rooms.setdefault(room, set()).add(sid)

    member_list = [{"sid": o,
                     "epub": sessions[o]["epub"],
                     "id":   sessions[o]["id_pub"],
                     "kpub": sessions[o].get("kpub", "")}
                   for o in rooms.get(room, set())
                   if o != sid and o in sessions]

    await sio.emit("auth_response", {
        "ok":        True,
        "sid":       sid,
        "room":      room,
        "members":   member_list,
        "hash_algo": HASH_ALGO,
        "is_owner":  is_owner,
    }, to=sid)

    for o in list(rooms.get(room, set())):
        if o != sid:
            await sio.emit("new_member",
                {"sid": sid, "epub": epub, "id": id_pub_b64, "kpub": kpub}, to=o)


@sio.event
async def list_rooms(sid, _=None):
    """F3-4: 返回当前所有房间 (含是否加密 + 在线人数). 不暴露成员 epub."""
    me = sessions.get(sid)
    # 必须先 auth 才能列房间 (防匿名枚举在线房间名)
    if not me:
        await sio.emit("server_event", {"type": "reject", "reason": "no auth"}, to=sid)
        return
    with _lock:
        out = []
        for rm, members in rooms.items():
            meta = room_metadata.get(rm)
            out.append({
                "name":         rm,
                "has_password": bool(meta and meta.get("password_hash")),
                "members":      len([s for s in members if s in sessions]),
            })
    await sio.emit("room_list", out, to=sid)


@sio.event
async def create_room(sid, payload):
    """F3-4: 创建带密码的房间. 调用者成为 owner, 之后该 room 必须对上密码才能 join.
    返回 auth_response (复用 OnAuthResult 通道) 让客户端 1 次握手即知结果."""
    if not isinstance(payload, dict):
        await sio.emit("auth_response", {"ok": False, "reason": "bad payload"}, to=sid)
        return

    epub = payload.get("epub", "")
    room = (payload.get("room") or "").strip()[:30]
    kpub = (payload.get("kpub") or "")[:8192]   # PQ: ML-KEM-1024 公钥透传
    if not room:
        await sio.emit("auth_response", {"ok": False, "reason": "room name empty"}, to=sid)
        return
    if room == "lobby":
        # lobby 是默认公开房, 不允许被设密码 (向下兼容 + 防占用)
        await sio.emit("auth_response", {
            "ok": False, "reason": "lobby 是保留公开房名, 不能占用. 换个房名."
        }, to=sid)
        return

    id_pub_b64 = payload.get("id", "")
    id_sig_b64 = payload.get("id_sig", "")
    if not id_pub_b64 or not id_sig_b64 \
            or not _verify_id_sig(id_pub_b64, id_sig_b64, epub, room):
        await sio.emit("auth_response", {
            "ok": False, "reason": "missing id_pub/id_sig OR Ed25519 sig invalid"
        }, to=sid)
        return

    pw = payload.get("room_password", "") or ""
    if not isinstance(pw, str) or len(pw) < 4:
        await sio.emit("auth_response", {
            "ok": False, "reason": "password must be >= 4 chars (or empty for public room)"
        }, to=sid)
        return

    pw_hash = _hash_room_password(room, pw) if pw else ""

    with _lock:
        # N1 附带 (2026-07-16): 已有同名的房间 (无论是否加密) 且 owner 不是本 sid -> 拒.
        # 原条件 only 在 existing 是密码房时拒, 让攻击者可在活跃公开房名上盖章设密码 + 抢 owner.
        # 现在只要是已有房间 (existing non-None) 且 owner 非本 sid 即拒, 公开房也防盖戳.
        existing = room_metadata.get(room)
        already_live = room in rooms and len(rooms[room]) > 0
        if already_live and (not existing or existing.get("owner_sid") != sid):
            await sio.emit("auth_response", {
                "ok": False,
                "reason": f"room '{room}' already in use; pick another name",
            }, to=sid)
            return
        # owner 是本 sid 的同房可改密码 (允许改 pw 但不创建新房记录原地覆写)
        room_metadata[room] = {
            "owner_sid":      sid,
            "owner_id_pub":   id_pub_b64,   # F5: 房主重连认领用 (sid 重连即变, id_pub 稳定)
            "password_hash":  pw_hash,
            "created_at":     _now(),
        }

    # 创建成功, 让本 sid 也加入该房 (复用 auth 已注册流程)
    with _lock:
        sessions[sid] = {
            "sid":      sid,
            "epub":     epub,
            "id_pub":   id_pub_b64,
            "kpub":     kpub,        # PQ
            "room":     room,
            "login_ts": _now(),
        }
        rooms.setdefault(room, set()).add(sid)

    member_list = [{"sid": o,
                     "epub": sessions[o]["epub"],
                     "id":   sessions[o]["id_pub"],
                     "kpub": sessions[o].get("kpub", "")}
                   for o in rooms.get(room, set())
                   if o != sid and o in sessions]

    await sio.emit("auth_response", {
        "ok":        True,
        "sid":       sid,
        "room":      room,
        "members":   member_list,
        "hash_algo": HASH_ALGO,
        "is_owner":  True,
    }, to=sid)

    for o in list(rooms.get(room, set())):
        if o != sid:
            await sio.emit("new_member",
                {"sid": sid, "epub": epub, "id": id_pub_b64, "kpub": kpub}, to=o)


@sio.event
async def kick_member(sid, payload):
    """F5: 房主踢出房间内某成员. 被踢者 10 分钟内不可再加入该房.
    仅 room_metadata.owner_sid == sid 可执行; target 必须在同房且非 self.
    禁令以 target 的 id_pub 为键写入 _room_kicks, disconnect 不会清 (房间仍在)."""
    me = sessions.get(sid)
    if not me:
        await sio.emit("server_event", {"type": "reject", "reason": "no auth"}, to=sid)
        return
    if not isinstance(payload, dict):
        return
    target_sid = payload.get("target_sid", "")
    room = me["room"]

    # 锁内: 只做校验 + 写禁令, 收集结果. 锁外才做 I/O (与 relay_slice 同模式,
    # 不在 threading.RLock 持锁时 await, 防阻塞其他等待锁的线程).
    # deny_reason 非 None = 校验失败; target_id_pub 非 None = 校验通过可踢.
    deny_reason: str | None = None
    target_id_pub: str | None = None
    with _lock:
        meta = room_metadata.get(room)
        if not meta or meta.get("owner_sid") != sid:
            deny_reason = "only owner can kick"
        elif not target_sid or target_sid == sid:
            deny_reason = "invalid target (cannot kick self)"
        else:
            target_session = sessions.get(target_sid)
            if not target_session or target_session.get("room") != room:
                deny_reason = "target not in this room"
            else:
                target_id_pub = target_session.get("id_pub", "")
                if not target_id_pub:
                    deny_reason = "target has no id_pub"
                else:
                    # 写入踢出禁令 (10 分钟). 已有同 id_pub 的旧禁令覆写 (重新计时).
                    _room_kicks.setdefault(room, {})[target_id_pub] = _now() + KICK_BAN_SECONDS

    # 锁外做 I/O
    if deny_reason is not None:
        await sio.emit("server_event",
                       {"type": "kick_denied", "reason": deny_reason}, to=sid)
        return

    # 校验通过: 通知被踢者
    await sio.emit("server_event",
                   {"type": "kicked", "reason": "removed by room owner",
                    "room": room, "ban_seconds": KICK_BAN_SECONDS}, to=target_sid)
    # 通知房间其他成员 (成员列表需移除被踢者)
    for o in list(rooms.get(room, set())):
        if o != sid and o != target_sid:
            await sio.emit("server_event",
                           {"type": "member_kicked", "sid": target_sid, "room": room}, to=o)
    # 通知房主成功
    await sio.emit("server_event",
                   {"type": "kick_ok", "target_sid": target_sid}, to=sid)
    # 断开被踢者 (disconnect handler 会清 sessions/rooms, 但禁令已写入 _room_kicks)
    await sio.disconnect(target_sid)


@sio.event
async def new_member_request(sid, _):
    me = sessions.get(sid)
    if not me:
        return
    for o in list(rooms.get(me["room"], set())):
        if o != sid:
            await sio.emit("new_member",
                {"sid": sid, "epub": me["epub"], "id": me.get("id_pub", ""),
                 "kpub": me.get("kpub", "")}, to=o)


@sio.event
async def kem_ct(sid, payload):
    """PQ 握手: 封装方把 ML-KEM 密文中继给解封方 (仅限同房)."""
    me = sessions.get(sid)
    if not me:
        return
    if not isinstance(payload, dict):
        return
    target = payload.get("to", "")
    ct     = payload.get("ct", "")
    if not target or not ct or len(ct) > 8192:
        return
    ts = sessions.get(target)
    if not ts or ts.get("room") != me["room"]:
        return
    await sio.emit("kem_ct", {"from": sid, "ct": ct}, to=target)


@sio.event
async def relay_message(sid, envelope):
    me = sessions.get(sid)
    if not me:
        await sio.emit("server_event", {"type": "reject", "reason": "no auth"}, to=sid)
        await sio.disconnect(sid)
        return

    now = _now()
    log_list = rate_log.setdefault(sid, [])
    while log_list and now - log_list[0] > RATE_LIMIT_WINDOW:
        log_list.pop(0)
    if len(log_list) >= RATE_LIMIT_MAX:
        await sio.emit("server_event", {"type": "rate_limit"}, to=sid)
        return
    log_list.append(now)

    if not isinstance(envelope, dict):
        return

    try:
        ok, reason = verify_integrity(envelope, me["epub"])
    except KeyError as ke:
        await sio.emit("server_event",
                        {"type": "message_dropped", "reason": f"missing field: {ke}"},
                        to=sid)
        return
    if not ok:
        if "冒充满" in reason:
            await sio.emit("server_event", {"type": "kick", "reason": reason}, to=sid)
            await sio.disconnect(sid)
        else:
            await sio.emit("server_event", {"type": "message_dropped", "reason": reason}, to=sid)
        return

    target = envelope.get("target", "ALL")
    forward = {
        "from":    sid,
        "epub":    envelope.get("epub", ""),
        "id":      envelope.get("id", ""),
        "dh_pub":  envelope.get("dh_pub", ""),
        "ct":      envelope.get("ct") or envelope.get("ciphertext") or "",
        "sig":     envelope.get("sig") or envelope.get("ed25519") or "",
        "b3":      envelope.get("b3") or envelope.get("blake3") or "",
        "n":       envelope.get("n", 0),
    }

    if target == "ALL":
        for o in list(rooms.get(me["room"], set())):
            if o != sid:
                await sio.emit("chat_message", forward, to=o)
    else:
        # CRITICAL: 房间归属校验. 否则跨房间可投毒 + 触发对端低阶点攻击或其他 client-side 注入.
        # 仅当 target 与 sid 在同一 room 才允许定向投递.
        target_session = sessions.get(target)
        if not target_session:
            await sio.emit("server_event", {"type": "recipient_offline", "target": target}, to=sid)
        elif target_session.get("room") != me["room"]:
            # 跨房间投递: 视为攻击行为, 直接踢 + 断连
            log.warning("cross-room delivery blocked: sid=%s room=%s -> target=%s target_room=%s",
                        sid, me["room"], target, target_session.get("room"))
            await sio.emit("server_event",
                          {"type": "kick", "reason": "cross-room delivery forbidden"},
                          to=sid)
            await sio.disconnect(sid)
        else:
            await sio.emit("chat_message", forward, to=target)


@sio.event
async def relay_slice(sid, envelope):
    me = sessions.get(sid)
    if not me:
        await sio.emit("server_event", {"type": "reject", "reason": "no auth"}, to=sid)
        await sio.disconnect(sid)
        return

    if not isinstance(envelope, dict):
        return

    target = envelope.get("target", "ALL")
    data = envelope.get("data", "")
    if not data:
        return

    # F3-2: 严格长度上限. 客户端单分片为 12B header + 512B body = 524B,
    # base64 编码后 ~700 chars. 拒绝超大分片, 阻断放大 DoS.
    # 上限 1024B (容许重组/扩展余量, 但远低于 500MB 攻击假设).
    MAX_SLICE_DATA_LEN = 1024
    if len(data) > MAX_SLICE_DATA_LEN:
        log.warning("oversized slice rejected: sid=%s len=%d", sid, len(data))
        await sio.emit("server_event",
                       {"type": "kick", "reason": f"slice > {MAX_SLICE_DATA_LEN}B"},
                       to=sid)
        await sio.disconnect(sid)
        return

    # F4-3: relay_slice 双 QoS — (a) F3-2 的条数硬上限 100/5s;
    # (b) 新增会话级累计字节硬上限 RATE_LIMIT_SLICE_BYTES / 5s.
    # 单攻击者即便每 slice 都顶满 1024B, 也只能透到 RATE_LIMIT_SLICE_BYTES
    # 即被踢 + 断连, 单流放大倍数从 200×500×1MB 降到 ≤ ceiling ×房间 N.
    now = _now()
    exceeded = None   # ("count" | "bytes", ...info)
    with _lock:
        log_list = rate_log_slices.setdefault(sid, [])
        while log_list and now - log_list[0] > RATE_LIMIT_WINDOW:
            log_list.pop(0)
        byte_list = rate_log_slice_bytes.setdefault(sid, [])
        while byte_list and now - byte_list[0][1] > RATE_LIMIT_WINDOW:
            byte_list.pop(0)
        window_bytes = sum(b[0] for b in byte_list)
        if len(log_list) >= RATE_LIMIT_MAX_SLICES:
            exceeded = ("count", len(log_list), window_bytes)
        elif window_bytes + len(data) > RATE_LIMIT_SLICE_BYTES:
            exceeded = ("bytes", len(log_list), window_bytes + len(data))
        else:
            log_list.append(now)
            byte_list.append((len(data), now))
    # 锁外做 I/O: 不要在 threading.RLock 持锁时 await (反 async 模式).
    if exceeded is not None:
        kind, n_count, n_bytes = exceeded
        log.warning("relay_slice rate-limited: sid=%s kind=%s slices=%d bytes=%d",
                    sid, kind, n_count, n_bytes)
        await sio.emit("server_event",
                       {"type": "rate_limit",
                        "reason": "slice count or bytes ceiling hit"}, to=sid)
        if kind == "bytes":
            # 视为野攻击流: kick + 断连, 收回 _connect_times / 子网槽.
            await sio.emit("server_event",
                           {"type": "kick",
                            "reason": f"slice bytes > {RATE_LIMIT_SLICE_BYTES}/5s"},
                           to=sid)
            await sio.disconnect(sid)
        return

    # F3-1: prior 是 server 端 verify_integrity 装在 relay_message 但 client
    # 实际只走 relay_slice -> server 完全不校验消息.
    # 现在方案: server 端不验 envelope 内容 (因 envelope 在 client 端 Reassembler 拼齐才有意义),
    # 但要校验 (a) from 字段 = sid (不可冒充他人发); (b) 跨房间投递拒绝;
    # 端到端的 BLAKE3/Ed25519 完整性由 client ProcessEnvelope 已强制.

    forward = {"from": sid, "data": data}

    if target == "ALL":
        for o in list(rooms.get(me["room"], set())):
            if o != sid:
                await sio.emit("chat_slice", forward, to=o)
    else:
        # CRITICAL: 同 relay_message, 跨房间投递必须拒绝 + 踢
        target_session = sessions.get(target)
        if not target_session:
            await sio.emit("server_event", {"type": "recipient_offline", "target": target}, to=sid)
        elif target_session.get("room") != me["room"]:
            log.warning("cross-room slice blocked: sid=%s room=%s -> target=%s target_room=%s",
                        sid, me["room"], target, target_session.get("room"))
            await sio.emit("server_event",
                          {"type": "kick", "reason": "cross-room slice forbidden"},
                          to=sid)
            await sio.disconnect(sid)
        else:
            await sio.emit("chat_slice", forward, to=target)


@sio.event
async def typing(sid, _):
    me = sessions.get(sid)
    if not me:
        return
    for o in list(rooms.get(me["room"], set())):
        if o != sid:
            await sio.emit("typing", {"sid": sid}, to=o)


@sio.event
async def client_error(sid, payload):
    if isinstance(payload, dict) and payload.get("severity") == "tamper":
        pass
    await sio.emit("server_event", {"type": "client_error_acked"}, to=sid)


@sio.event
async def who_online(sid, _):
    me = sessions.get(sid)
    if not me:
        return
    await sio.emit("online_list", {
        "room":   me["room"],
        "members": [{"sid": s, "epub": sessions[s]["epub"]}
                     for s in rooms.get(me["room"], set()) if s in sessions],
    }, to=sid)


@sio.event
async def heartbeat(sid, _=None):
    await sio.emit("heartbeat_ack", {"sid": sid}, to=sid)


# ============================================================
#  启动 (uvicorn + ASGI App)
# ============================================================
# socketio.ASGIApp 把 AsyncServer 包装成 ASGI 应用. uvicorn 直接 run 即可.
# 健康检查 (HTTP GET /) 由 socketio 默认 404 (我们不再附带 Flask, 因为 Flask + Werkzeug
# 在 Python 3.14 上 polling handshake 有 'write() before start_response' bug).
app = socketio.ASGIApp(sio)

# uvicorn startup hook 启动 reaper task 清未 auth 的 dormant 连接 (防 F3-5 slot 耗尽)
async def _startup_hook():
    asyncio.create_task(_reap_unauthed_loop())

# 把 startup event 注册包装一下 ASGI lifecycle
_app_run = app

async def _app_with_lifespan(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await _startup_hook()
                    await send({"type": "lifespan.startup.complete"})
                except Exception as ex:
                    await send({"type": "lifespan.startup.failed", "message": str(ex)})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    else:
        await _app_run(scope, receive, send)

app = _app_with_lifespan


def _auto_self_signed_cert() -> tuple[str, str, bytes]:
    """零交互自签证书引导: 证书不存在即用 cryptography 现场生成,
    私钥落地 AES-256 加密, 口令 = uuid4, 进程内即用即弃不落盘.
    返回 (cert_path, key_path, passphrase_bytes)."""
    import os, secrets, datetime
    from cryptography import x509 as _cx
    from cryptography.hazmat.primitives import hashes as _ch
    from cryptography.hazmat.primitives import serialization as _cs
    from cryptography.hazmat.primitives.asymmetric import ec as _ce
    from cryptography.x509.oid import NameOID as _NOID

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
    os.makedirs(out_dir, exist_ok=True)
    cert_path = os.path.join(out_dir, "cert.pem")
    key_path  = os.path.join(out_dir, "key.pem")

    priv = _ce.generate_private_key(_ce.SECP256R1())
    sub  = _cx.Name([_cx.NameAttribute(_NOID.COMMON_NAME, "E2EChat-V2 local TLS")])
    now  = datetime.datetime.now(datetime.timezone.utc)
    cert = (_cx.CertificateBuilder()
            .subject_name(sub).issuer_name(sub)
            .public_key(priv.public_key())
            .serial_number(_cx.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(_cx.SubjectAlternativeName([_cx.DNSName("*")]), critical=False)
            .sign(priv, _ch.SHA256()))

    pw = bytearray(secrets.token_hex(32).encode("utf-8"))
    enc_key = priv.private_bytes(
        encoding=_cs.Encoding.PEM,
        format=_cs.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=_cs.BestAvailableEncryption(bytes(pw)))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(_cs.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(enc_key)
    return cert_path, key_path, bytes(pw)


def main():
    import argparse
    ap = argparse.ArgumentParser(description="E2E-Chat-V2 server")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    # TLS/WSS 选项: 默认 **开启**. --no-tls 才回退明文 (本地调试用)
    ap.add_argument("--no-tls", action="store_true",
                    help="禁用 TLS (明文 ws://, 仅本地调试; 默认开 wss)")
    ap.add_argument("--tls-cert",  default=None,
                    help="TLS 证书路径 (.pem); 不给则自动生成自签证书")
    ap.add_argument("--tls-key",   default=None,
                    help="TLS 私钥路径 (.pem); 与 --tls-cert 配套")
    ap.add_argument("--tls-key-pw", default=None,
                    help="TLS 私钥解密口令 (可省)")
    args = ap.parse_args()

    use_tls = not args.no_tls
    tls_pw: bytes | None = None

    if use_tls:
        cert_file = args.tls_cert
        key_file  = args.tls_key
        if cert_file and key_file:
            # 用户手工指定: 信任其加密体系, 口令从 CLI 来
            tls_pw = args.tls_key_pw.encode("utf-8") if args.tls_key_pw else None
        else:
            # 未指定 → 自动生成自签证书 (零交互, 口令落内存不落盘)
            cert_file, key_file, tls_pw_bytes = _auto_self_signed_cert()
            tls_pw = tls_pw_bytes
        print(f"[e2e-v2] TLS 自签证书就绪: {cert_file}", flush=True)
        print(f"  [TOFU] 客户端勾 TLS 后留空指纹即可自动钉定首次连接指纹", flush=True)

    scheme = "wss" if use_tls else "ws"
    log.warning("E2E-Chat-V2 starting on %s://%s:%d (hash=%s, tls=%s)",
                scheme, args.host, args.port, HASH_ALGO, use_tls)

    print(f"[e2e-v2] BLAKE3 mode: {HASH_ALGO} (C-extension={_HAVE_FASTMODULE})",
          flush=True)
    print(f"[e2e-v2] sample hash: BLAKE3('hello')={_hash32(b'hello')}",
          flush=True)

    try:
        import uvicorn
        kwargs = dict(host=args.host, port=args.port,
                      log_level="warning",
                      ws="websockets-sansio",
                      http="h11")
        if use_tls:
            kwargs["ssl_certfile"] = cert_file
            kwargs["ssl_keyfile"]  = key_file
            if tls_pw:
                kwargs["ssl_keyfile_password"] = tls_pw.decode("utf-8")
        uvicorn.run(app, **kwargs)
    except ImportError:
        print("[fallback] uvicorn not installed.", flush=True)
        sys.exit(1)
    except FileNotFoundError as ex:
        print(f"[FATAL] TLS 证书加载失败: {ex}", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
