// HKDF-SHA512 + 真 Double Ratchet (Signal-protocol-style)
// =================================================================
// 已从"对称棘轮 + 双链"升级为完整 Double Ratchet:
//   * DH ratchet  :  对端每次单向发消息换发 DH 公钥, 我方必跟上一次 DH ECDH,
//                   重置 chain + 把丢的那段 drain 出来塞 skipped keys
//   * Symm ratchet:  同 DH 期内, counter n 每条 HKDF-Expand 推进一次, 旧 chain zeroize
//   * Skipped keys:  丢消息时把 (dh_pub, n) → msg_key 缓存起来, 后续乱序/重传
//                   到这个 n 仍可解开, 容量上限 MAX_SKIPPED_KEYS (1000)
//   * 重放防御  :  TryRecv(theirDhPub, n) 返回 verdict, n <= recvN 且不在 skipped
//                   里 => replay 直接拒
//   * 严格模式  :  n > curN + MAX_GAP (2000) 即视为异常/重放/DoS, 拒收
//
// 安全属性:
//   * 前向安全:  旧 chain_key + 旧 DH 私钥 用完即 zeroize
//   * 后向安全:  对端换 DH 公钥后, 即使我方旧 DH 私钥被截获也无法解密新链消息
//   * 跳号重组:  skipped keys 缓存允许乱序/丢失 1 -> 1000 条消息后仍可恢复
//   * 抗重放:  curN单调推进, 已收过的 n 在 skipped 表外一律拒绝
//   * 线程安全:  所有公开方法用 _lock 保护, 内部可重入
//
// 密钥派生: 系统级 CSPRNG(RandomNumberGenerator -> getrandom/BCryptGenRandom),
//           严禁 MAC/HDD/时间戳做种子. 所有临时 DH 私钥用完 zeroize.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

using E2EChatClient.Crypto;

namespace E2EChatClient.CryptoV2;

/// <summary>
/// HKDF-SHA512 (RFC 5869), 用 .NET 内置 HMACSHA512
/// </summary>
public static class HkdfSha512
{
    public static byte[] Extract(byte[] salt, byte[] ikm) {
        using var h = new HMACSHA512(salt ?? new byte[64]);
        return h.ComputeHash(ikm);
    }

    public static byte[] Expand(byte[] prk, byte[] info, int length) {
        if (length <= 0) return Array.Empty<byte>();
        using var h = new HMACSHA512(prk);
        int hashLen = 64;
        int n = (length + hashLen - 1) / hashLen;
        byte[] okm = new byte[n * hashLen];
        byte[] t = new byte[0];
        byte[] oneByte = new byte[1];
        for (int i = 1; i <= n; i++) {
            using var ms = new System.IO.MemoryStream();
            ms.Write(t, 0, t.Length);
            ms.Write(info ?? Array.Empty<byte>(), 0, info?.Length ?? 0);
            oneByte[0] = (byte)i;
            ms.Write(oneByte, 0, 1);
            byte[] buf = ms.ToArray();
            t = h.ComputeHash(buf);
            Buffer.BlockCopy(t, 0, okm, (i - 1) * hashLen, hashLen);
        }
        byte[] result = new byte[length];
        Buffer.BlockCopy(okm, 0, result, 0, length);
        CryptographicOperations.ZeroMemory(okm.AsSpan());
        CryptographicOperations.ZeroMemory(t.AsSpan());
        return result;
    }
}

/// <summary>
/// 接收裁决
/// </summary>
public enum RatchetVerdict {
    /// <summary> 正常接受, 已推进 recv chain / 已从 skipped 取出 </summary>
    Accept,
    /// <summary> 已收过的 n, 且不在 skipped 表 => 重放 </summary>
    Replay,
    /// <summary> n 超出 curN + MAX_GAP => DoS / 异常 </summary>
    GapTooLarge,
    /// <summary> envelope 内 dh_pub 字段长度非法 </summary>
    BadDhPub,
    /// <summary> 复用对方同一个 DH pub (mismatch 期望由 envelope 给的) </summary>
    DhMismatch,
}

/// <summary>
/// 解密结果
/// </summary>
public struct DecryptOutcome {
    public RatchetVerdict Verdict;
    public byte[]? MessageKey;  // Accept 时有效
    public string? Reason;
}

/// <summary>
/// 真 Double Ratchet: DH 棘轮 + 对称棘轮 + skipped message keys 缓存
/// 所有公开方法线程安全 (内部用 _lock 互斥, C# lock 可重入)
/// </summary>
public sealed class DoubleRatchet : IDisposable
{
    // 缓存上限
    public const int MAX_SKIPPED_KEYS = 1000;
    // n 超过当前 curN + MAX_GAP 视为异常/DoS, 直接拒
    public const long MAX_GAP = 2000;

    // 根 chain (HKDF root key 由 ECDH 输出派生, 每次 DH 轮换都重置)
    byte[] _rootKey;        // 32B
    // 当前 send / recv chain
    byte[] _sendChainKey;   // 32B (iAmA 持有 chainA 送出 / iAmB 持有 chainB 送出)
    byte[] _recvChainKey;   // 32B
    // 当前我方 DH keypair (每次 RatchetForSend 时若轮换则换新)
    byte[] _myDhPriv;       // 32B
    byte[] _myDhPub;        // 32B
    // 对端 "上一份已用" DH 公钥 (用来探测对方何时换了 DH pub)
    byte[] _peerDhPub;      // 32B

    long _sendN;
    long _recvN;
    bool _iAmA;

    // 线程安全: 所有状态变更都在 _lock 内完成
    private readonly object _lock = new();

    public long SendCounter { get { lock (_lock) return _sendN; } }
    public long RecvCounter { get { lock (_lock) return _recvN; } }
    public byte[] MyDhPub   { get { lock (_lock) return _myDhPub != null ? (byte[])_myDhPub.Clone() : null!; } }
    public byte[] PeerDhPub { get { lock (_lock) return _peerDhPub != null ? (byte[])_peerDhPub.Clone() : null!; } }

    // skipped: (peerDhPubHex, n) -> msgKey 32B
    // 仅在对端 DH pub 切换 / 我方 DH pub 切换时, 把丢的那段对称 chain drain 出来塞这里
    // 内层用普通 Dictionary, 由 _lock 保护线程安全
    readonly ConcurrentDictionary<string, Dictionary<long, byte[]>> _skipped = new();
    int _skippedTotal;

    /// <summary>
    /// 初始化: 由 ECDH 共享密钥 + 双方公钥构造
    /// </summary>
    public DoubleRatchet(byte[] sharedSecret, byte[] myDhPub, byte[] peerDhPub) {
        if (sharedSecret == null || sharedSecret.Length != 32)
            throw new ArgumentException("sharedSecret must be 32B");
        if (myDhPub == null || myDhPub.Length != 32)
            throw new ArgumentException("myDhPub must be 32B");
        if (peerDhPub == null || peerDhPub.Length != 32)
            throw new ArgumentException("peerDhPub must be 32B");

        _iAmA = CompareLex(myDhPub, peerDhPub) < 0;

        // 根 chain: PRK = HKDF-Extract(salt=0^64, ikm=sharedSecret)
        byte[] prk = HkdfSha512.Extract(new byte[64], sharedSecret);
        _rootKey = HkdfSha512.Expand(prk, Encoding.UTF8.GetBytes("E2EChat/root"), 32);
        // 初始 chain = HKDF-Expand(rootKey, "chainA" / "chainB", 32) — 方向与 iAmA 决定
        byte[] chainA = HkdfSha512.Expand(_rootKey, Encoding.UTF8.GetBytes("E2EChat/chainA"), 32);
        byte[] chainB = HkdfSha512.Expand(_rootKey, Encoding.UTF8.GetBytes("E2EChat/chainB"), 32);
        _sendChainKey = (byte[])(_iAmA ? chainA : chainB).Clone();
        _recvChainKey = (byte[])(_iAmA ? chainB : chainA).Clone();
        CryptographicOperations.ZeroMemory(prk);
        CryptographicOperations.ZeroMemory(chainA);
        CryptographicOperations.ZeroMemory(chainB);

        _myDhPub = (byte[])myDhPub.Clone();
        _peerDhPub = (byte[])peerDhPub.Clone();
        _myDhPriv = new byte[32];
        _sendN = 0;
        _recvN = 0;
        _skippedTotal = 0;
    }

    /// <summary>
    /// 设定我方 DH 私钥 (与 myDhPub 配套). 仅初始化时由会话层用 ephemeral priv 注入一次.
    /// </summary>
    public void SetMyDhPriv(byte[] priv32) {
        if (priv32 == null || priv32.Length != 32) throw new ArgumentException("priv 32B");
        lock (_lock) {
            if (_myDhPriv != null) CryptographicOperations.ZeroMemory(_myDhPriv);
            _myDhPriv = (byte[])priv32.Clone();
        }
    }

    /// <summary>
    /// 更新我方 DH 公钥 (与 SetMyDhPriv 配套). DH ratchet 轮换时由会话层主动调用
    /// (priv 已通过 SetMyDhPriv 注入, pub 跟上). 旧 pub zeroize.
    /// </summary>
    public void UpdateMyDhPub(byte[] pub32) {
        if (pub32 == null || pub32.Length != 32) throw new ArgumentException("pub 32B");
        lock (_lock) {
            if (_myDhPub != null) CryptographicOperations.ZeroMemory(_myDhPub);
            _myDhPub = (byte[])pub32.Clone();
        }
    }

    /// <summary>
    /// 把当前 recv chain (从 recvN 到 recvN+limitN) 的 msg keys drain 进 skipped 表,
    /// 上限 MAX_SKIPPED_KEYS. 用于 DH 轮换时, 给"还没到的旧 counter" 留钥匙.
    /// 必须在 _lock 内调用.
    /// </summary>
    void DrainRecvChainIntoSkipped(byte[] oldPeerDhPub, int limitN) {
        if (limitN <= 0) return;
        if (_recvChainKey == null) return;

        string key = BytesHex(oldPeerDhPub);
        var map = _skipped.GetOrAdd(key, _ => new Dictionary<long, byte[]>());

        long drained = 0;
        long targetN = _recvN + limitN;
        for (long n = _recvN; n < targetN && _skippedTotal < MAX_SKIPPED_KEYS; n++) {
            byte[] mk = HkdfSha512.Expand(_recvChainKey,
                Encoding.UTF8.GetBytes("msg/" + n), 32);
            byte[] newChain = HkdfSha512.Expand(_recvChainKey,
                Encoding.UTF8.GetBytes("advance"), 32);
            CryptographicOperations.ZeroMemory(_recvChainKey);
            _recvChainKey = newChain;
            map[n] = mk;
            _skippedTotal++;
            drained++;
        }
        _recvN += drained;

        // 超额清掉最老
        while (_skippedTotal > MAX_SKIPPED_KEYS) {
            bool removed = false;
            foreach (var kv in _skipped) {
                if (kv.Value.Count > 0) {
                    long oldest = long.MaxValue;
                    foreach (var k in kv.Value.Keys) if (k < oldest) oldest = k;
                    if (oldest != long.MaxValue) {
                        CryptographicOperations.ZeroMemory(kv.Value[oldest]);
                        kv.Value.Remove(oldest);
                        _skippedTotal--;
                        removed = true;
                        break;
                    }
                }
            }
            if (!removed) break; // 防死循环
        }
    }

    /// <summary>
    /// drain 旧 recv chain 的 MAX_GAP 把钥匙进 skipped 表 (DH 轮换时调用)
    /// 必须在 _lock 内调用.
    /// </summary>
    void DrainRecvChainIntoSkipped(byte[] oldPeerDhPub) {
        int limit = (int)Math.Min(MAX_GAP, MAX_SKIPPED_KEYS);
        DrainRecvChainIntoSkipped(oldPeerDhPub, limit);
    }

    /// <summary>
    /// 发送消息前: 用 send_chain + send_n 派生 message_key, 推进 send_chain.
    /// 用法: 调用方先取 myDhPub, 把它放进 envelope.dh_pub, 然后调 RatchetForSend.
    /// </summary>
    public byte[] RatchetForSend() {
        lock (_lock) {
            if (_sendChainKey == null) throw new ObjectDisposedException(nameof(DoubleRatchet));

            byte[] msgKey = HkdfSha512.Expand(_sendChainKey,
                Encoding.UTF8.GetBytes("msg/" + _sendN), 32);
            byte[] newChain = HkdfSha512.Expand(_sendChainKey,
                Encoding.UTF8.GetBytes("advance"), 32);

            CryptographicOperations.ZeroMemory(_sendChainKey);
            _sendChainKey = newChain;
            _sendN++;
            return msgKey;
        }
    }

    /// <summary>
    /// 兼容旧调用 (只走对称棘轮推进), 不再单独使用
    /// </summary>
    public byte[] RatchetForRecv() {
        lock (_lock) {
            byte[] mk;
            if (!_TryConsumeSkipped(_peerDhPub, _recvN, out mk)) {
                mk = HkdfSha512.Expand(_recvChainKey,
                    Encoding.UTF8.GetBytes("msg/" + _recvN), 32);
                byte[] newChain = HkdfSha512.Expand(_recvChainKey,
                    Encoding.UTF8.GetBytes("advance"), 32);
                CryptographicOperations.ZeroMemory(_recvChainKey);
                _recvChainKey = newChain;
            }
            _recvN++;
            return mk;
        }
    }

    /// <summary>
    /// 接收裁决 + 取 message key:
    ///   1. dh pub 不合法                  -> BadDhPub
    ///   2. n > curN + MAX_GAP             -> GapTooLarge
    ///   3. 已收过的 n 且不在 skipped       -> Replay
    ///   否则                              -> Accept + 推进 recv chain / 切 DH
    ///
    /// 注意: 调用方传 envelope.dh_pub (发送方 myDhPub), 若 == 我方记录的 peerDhPub
    ///       表示对端 DH 未轮换 (我们沿当前 recv chain 推进);
    ///       若 != 则表示对端换了 DH pub, 我们先 drain 旧 chain, 切新 chain, 再取 n=0 这把.
    /// </summary>
    public DecryptOutcome TryRecv(byte[]? theirDhPub, long n) {
        if (theirDhPub == null || theirDhPub.Length != 32)
            return new DecryptOutcome { Verdict = RatchetVerdict.BadDhPub, Reason = "dh pub 32B required" };

        lock (_lock) {
            if (_recvChainKey == null)
                return new DecryptOutcome { Verdict = RatchetVerdict.BadDhPub, Reason = "disposed" };

            // a) 是否走 skipped 表 (旧 peerDhPub + 老 counter)
            if (BytesEqual(theirDhPub, _peerDhPub)) {
                // 同 DH 期内
                if (n < _recvN) {
                    // 重放: 老 counter. 先查 skipped 是否有
                    if (_TryConsumeSkipped(_peerDhPub, n, out var mkOld)) {
                        _skippedTotal--;
                        return new DecryptOutcome { Verdict = RatchetVerdict.Accept, MessageKey = mkOld };
                    }
                    return new DecryptOutcome { Verdict = RatchetVerdict.Replay, Reason = $"n={n} < recvN={_recvN}" };
                }
                if (n > _recvN + MAX_GAP)
                    return new DecryptOutcome { Verdict = RatchetVerdict.GapTooLarge, Reason = $"n={n} > {_recvN}+{MAX_GAP}" };

                // n 在 [_recvN, _recvN + MAX_GAP] 范围, 跳号 => drain 缺的那几把进 skipped, 然后取 n
                while (_recvN < n) {
                    byte[] skipKey = HkdfSha512.Expand(_recvChainKey,
                        Encoding.UTF8.GetBytes("msg/" + _recvN), 32);
                    byte[] newChain = HkdfSha512.Expand(_recvChainKey,
                        Encoding.UTF8.GetBytes("advance"), 32);
                    try {
                        CryptographicOperations.ZeroMemory(_recvChainKey);
                        _recvChainKey = newChain;
                        string k = BytesHex(_peerDhPub);
                        var map = _skipped.GetOrAdd(k, _ => new Dictionary<long, byte[]>());
                        map[_recvN] = skipKey;
                        _skippedTotal++;
                        _recvN++;
                    } catch {
                        // F4-1: 异常路径 (e.g. OOM) 也要 zeroize 临时密钥, 防滞留托管堆到 GC
                        CryptographicOperations.ZeroMemory(skipKey);
                        CryptographicOperations.ZeroMemory(newChain);
                        throw;
                    }
                    if (_skippedTotal > MAX_SKIPPED_KEYS) break;
                }
                // 此时 _recvN == n
                byte[] mk = null!;
                byte[] newChain2 = null!;
                try {
                    mk = HkdfSha512.Expand(_recvChainKey,
                        Encoding.UTF8.GetBytes("msg/" + _recvN), 32);
                    newChain2 = HkdfSha512.Expand(_recvChainKey,
                        Encoding.UTF8.GetBytes("advance"), 32);
                    CryptographicOperations.ZeroMemory(_recvChainKey);
                    _recvChainKey = newChain2;
                    _recvN++;
                    var outcome = new DecryptOutcome { Verdict = RatchetVerdict.Accept, MessageKey = mk };
                    mk = null!;             // 所有权已移交给 outcome, 别在 finally 里清
                    return outcome;
                } finally {
                    // F4-1: 异常路径 (HKDF 抛错/OOM) 也要 zeroize 临时密钥,
                    //       防滞留托管堆到 GC. 成功路径 mk 已被调用方接管, 这里只清未提交的 newChain2.
                    if (newChain2 != null && !ReferenceEquals(newChain2, _recvChainKey))
                        CryptographicOperations.ZeroMemory(newChain2);
                    if (mk != null) CryptographicOperations.ZeroMemory(mk);
                }
            }

            // b) 对端换了 DH pub => DH ratchet recv
            // 检查 n 不能过大 (否则 DoS)
            if (n > MAX_GAP)
                return new DecryptOutcome { Verdict = RatchetVerdict.GapTooLarge, Reason = $"new-dh n={n} > {MAX_GAP}" };

            // drain 旧 chain 的剩余部分 (从 _recvN 到 _recvN + MAX_GAP) 到 skipped 表
            // 这样 DH 轮换前丢的消息后续仍可解密
            byte[] oldPeerDhPub = _peerDhPub;
            DrainRecvChainIntoSkipped(oldPeerDhPub);

            // 切新 root/chain:
            _peerDhPub = (byte[])theirDhPub.Clone();

            // ECDH(我方旧 priv, 对端新 pub) -> 新 root + recv chain
            byte[] dhOut1 = Curve25519.ComputeSharedSecret(_myDhPriv, _peerDhPub);
            byte[] prk1 = HkdfSha512.Extract(_rootKey, dhOut1);
            CryptographicOperations.ZeroMemory(dhOut1);
            byte[] newRoot1 = HkdfSha512.Expand(prk1, Encoding.UTF8.GetBytes("E2EChat/root"), 32);
            _recvChainKey = HkdfSha512.Expand(prk1, Encoding.UTF8.GetBytes("E2EChat/chain" + (_iAmA ? "B" : "A")), 32);
            CryptographicOperations.ZeroMemory(prk1);
            CryptographicOperations.ZeroMemory(_rootKey);
            _rootKey = newRoot1;
            _recvN = 0;

            // 取 n (=0 首条) 或 n (允许跳号)
            while (_recvN < n) {
                byte[] skipKey = HkdfSha512.Expand(_recvChainKey,
                    Encoding.UTF8.GetBytes("msg/" + _recvN), 32);
                byte[] newChain = HkdfSha512.Expand(_recvChainKey,
                    Encoding.UTF8.GetBytes("advance"), 32);
                try {
                    CryptographicOperations.ZeroMemory(_recvChainKey);
                    _recvChainKey = newChain;
                    string k = BytesHex(_peerDhPub);
                    var map = _skipped.GetOrAdd(k, _ => new Dictionary<long, byte[]>());
                    map[_recvN] = skipKey;
                    _skippedTotal++;
                    _recvN++;
                } catch {
                    // F4-1: 异常路径 zeroize 临时密钥
                    CryptographicOperations.ZeroMemory(skipKey);
                    CryptographicOperations.ZeroMemory(newChain);
                    throw;
                }
                if (_skippedTotal > MAX_SKIPPED_KEYS) break;
            }
            byte[] mk2 = null!;
            byte[] newChainLast = null!;
            try {
                mk2 = HkdfSha512.Expand(_recvChainKey,
                    Encoding.UTF8.GetBytes("msg/" + _recvN), 32);
                newChainLast = HkdfSha512.Expand(_recvChainKey,
                    Encoding.UTF8.GetBytes("advance"), 32);
                CryptographicOperations.ZeroMemory(_recvChainKey);
                _recvChainKey = newChainLast;
                _recvN++;
                var outcome = new DecryptOutcome { Verdict = RatchetVerdict.Accept, MessageKey = mk2 };
                mk2 = null!;
                return outcome;
            } finally {
                // F4-1: 异常路径 zeroize 临时密钥 (同上分支)
                if (newChainLast != null && !ReferenceEquals(newChainLast, _recvChainKey))
                    CryptographicOperations.ZeroMemory(newChainLast);
                if (mk2 != null) CryptographicOperations.ZeroMemory(mk2);
            }
        }
    }

    /// <summary>
    /// 我方下次 RatchetForSend 前主动 DH 轮换:
    ///   1. 换我方新 keypair (GeneratePrivateKey)
    ///   2. 用我方新 priv + 当前 _peerDhPub => ECDH => 新 root + 新 send chain (n=0)
    /// 调用时机: 会话层在 RatchetForSend 之前判断 _peerDhPub 变了 -> 调一次这个;
    ///          对端 TryRecv 已完成"recv 切换", 这里只关心主动换 keypair + 推 send chain.
    /// </summary>
    public void DhRatchetForSend() {
        lock (_lock) {
            if (_peerDhPub == null || _peerDhPub.Length != 32)
                throw new InvalidOperationException("peer dh pub not set");

            // (1) 换我方新 keypair
            if (_myDhPriv != null) CryptographicOperations.ZeroMemory(_myDhPriv);
            _myDhPriv = Curve25519.GeneratePrivateKey();
            if (_myDhPub != null) CryptographicOperations.ZeroMemory(_myDhPub);
            _myDhPub = Curve25519.GeneratePublicKey(_myDhPriv);

            // (2) 用我方新 priv + peer pub -> ECDH -> 新 root + 新 send chain
            byte[] dhOut = Curve25519.ComputeSharedSecret(_myDhPriv, _peerDhPub);
            byte[] prk = HkdfSha512.Extract(_rootKey, dhOut);
            CryptographicOperations.ZeroMemory(dhOut);
            byte[] newRoot = HkdfSha512.Expand(prk, Encoding.UTF8.GetBytes("E2EChat/root"), 32);
            _sendChainKey = HkdfSha512.Expand(prk, Encoding.UTF8.GetBytes("E2EChat/chain" + (_iAmA ? "A" : "B")), 32);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(_rootKey);
            _rootKey = newRoot;
            _sendN = 0;
        }
    }

    /// <summary>
    /// 兼容旧签名 (theirKnownDhPub 参数忽略, 由内部 _peerDhPub 决定).
    /// </summary>
    public void DhRatchetForSend(byte[] theirKnownDhPub) => DhRatchetForSend();

    bool _TryConsumeSkipped(byte[] dhPub, long n, out byte[] mk) {
        string k = BytesHex(dhPub);
        mk = null!;
        if (!_skipped.TryGetValue(k, out var map)) return false;
        if (!map.TryGetValue(n, out var key)) return false;
        mk = key;
        map.Remove(n);
        if (map.Count == 0) _skipped.TryRemove(k, out _);
        return true;
    }

    static int CompareLex(byte[] a, byte[] b) {
        for (int i = 0; i < a.Length && i < b.Length; i++) {
            if (a[i] != b[i]) return a[i] - b[i];
        }
        return a.Length - b.Length;
    }

    static bool BytesEqual(byte[] a, byte[] b) {
        if (a == null || b == null) return a == b;
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    static string BytesHex(byte[] a) {
        var sb = new StringBuilder(a.Length * 2);
        const string H = "0123456789abcdef";
        foreach (var b in a) { sb.Append(H[(b >> 4) & 0xf]); sb.Append(H[b & 0xf]); }
        return sb.ToString();
    }

    public void Dispose() {
        lock (_lock) {
            if (_sendChainKey != null) CryptographicOperations.ZeroMemory(_sendChainKey);
            if (_recvChainKey != null) CryptographicOperations.ZeroMemory(_recvChainKey);
            if (_rootKey != null) CryptographicOperations.ZeroMemory(_rootKey);
            if (_myDhPriv != null) CryptographicOperations.ZeroMemory(_myDhPriv);
            if (_myDhPub != null) CryptographicOperations.ZeroMemory(_myDhPub);
            if (_peerDhPub != null) CryptographicOperations.ZeroMemory(_peerDhPub);
            _sendChainKey = _recvChainKey = _rootKey = null!;
            _myDhPriv = _myDhPub = _peerDhPub = null!;
            foreach (var kv in _skipped) {
                foreach (var mk in kv.Value.Values) {
                    if (mk != null) CryptographicOperations.ZeroMemory(mk);
                }
                kv.Value.Clear();
            }
            _skipped.Clear();
            _skippedTotal = 0;
        }
    }
}
