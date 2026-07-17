// 512B 定长分片 + 0~150ms 时间抖动发送层
// ============================================
// 目的:
//   * 攻击者无法通过数据包大小判断是"你好"还是"传输10MB文件"
//   * 攻击者无法通过发送间隔判断是否活跃 / 是否各自发消息 / 是否打字
//
// 分片格式:
//   原始 ciphertext bytes -> 切分为 ceil(L/512) 个分片, 最后一块用 CSPRNG 随机数补到 512B
//   每分片单元: {
//      sid_seed(8B): 父消息的全局 id, 用于使接收方按顺序拼接
//      index(2B):    be-uint16 该分片 index
//      total(2B):    be-uint16 总片数
//      payload(512B): 加密的内容(尾块含随机填充)
//   }
//   拼接: receiver 看到所有 total 片收齐后, 前 (total-1) 块都是 512B, 最后一块截 original_len - (total-1)*512
//
// 时间抖动:
//   * 每个分片发送前 sleep 0~150ms 随机
//   * 不要发送太多分片以避免累积延迟
//
// 重放/DoS 防御 (Reassembler):
//   * partial 表加超时清理 (默认 30s 累积不齐自动 evict)
//   * partial 表加容量上限 MAX_PARTIAL_TABLE (阻止对端用永远收不齐的消息爆内存)
//   * 同 sidSeed 收到 index >= total 的分片直接丢 (异常)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace E2EChatClient.CryptoV2;

public static class TrafficObfuscator
{
    public const int SLICE_BYTES = 512;
    public const int HEADER_BYTES = 12;   // 8 (sid_seed) + 2 (index) + 2 (total)
    public const int MAX_SLICES = 0xffff; // uint16 上限
    public const int MAX_JITTER_MS = 150;

    /// <summary>
    /// 把 bytes 分片为 512B 长切片, 末块用 CSPRNG 填到 512B
    /// </summary>
    public static List<byte[]> Slice(byte[] data, byte[] sidSeed) {
        if (data.Length > MAX_SLICES * SLICE_BYTES)
            throw new ArgumentException("data > max allowed");
        if (sidSeed.Length != 8) throw new ArgumentException("sid_seed must be 8B");

        int total = (data.Length + SLICE_BYTES - 1) / SLICE_BYTES;
        if (total == 0) total = 1;
        if (total > MAX_SLICES) throw new ArgumentException("total > 65535");
        var list = new List<byte[]>(total);
        for (int i = 0; i < total; i++) {
            int off = i * SLICE_BYTES;
            int len = Math.Min(SLICE_BYTES, data.Length - off);
            byte[] slice = new byte[SLICE_BYTES];
            Buffer.BlockCopy(data, off, slice, 0, len);
            if (len < SLICE_BYTES) {
                // 尾块用 CSPRNG 填随机
                byte[] rnd = new byte[SLICE_BYTES - len];
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(rnd);
                Buffer.BlockCopy(rnd, 0, slice, len, rnd.Length);
            }

            byte[] packet = new byte[HEADER_BYTES + SLICE_BYTES];
            Buffer.BlockCopy(sidSeed, 0, packet, 0, 8);
            packet[8]  = (byte)((i     >> 8) & 0xff);
            packet[9]  = (byte)( i           & 0xff);
            packet[10] = (byte)((total >> 8) & 0xff);
            packet[11] = (byte)( total        & 0xff);
            Buffer.BlockCopy(slice, 0, packet, HEADER_BYTES, SLICE_BYTES);

            list.Add(packet);
        }
        return list;
    }

    /// <summary>
    /// 接收端累积分片, 返回原始 data 若该 sid 已收齐所有 total 帧
    ///
    /// LRU/超时清理:
    ///   * 若同一 sidSeed 在 PARTIAL_TIMEOUT_SEC 内收不齐 -> 自动移除, 防内存增长
    ///   * partial 表上限 MAX_PARTIAL_TABLE -> 满则 evict 最老的
    ///   * 异常分片 (index >= total, total=0, 副本) -> 直接丢
    /// </summary>
    public class Reassembler {
        class PartialMsg {
            public int Total;
            public byte[][]? Parts;
            public int Received;
            public long CreatedTick;  // Environment.TickCount64, 用于超时
        }
        const int MAX_PARTIAL_TABLE = 256;
        const long PARTIAL_TIMEOUT_SEC = 30;
        const int MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB 上限, 防止 origLen 伪造导致 OOM

        readonly ConcurrentDictionary<ulong, PartialMsg> _table = new();
        long _lastSweepTick = Environment.TickCount64;

        public byte[]? Push(byte[] packet) {
            if (packet.Length != HEADER_BYTES + SLICE_BYTES)
                throw new ArgumentException("packet len");

            // 周期清理 (每 10s 触发一次)
            long now = Environment.TickCount64;
            if (now - _lastSweepTick > 10000) {
                _lastSweepTick = now;
                SweepExpired();
            }

            ulong sid = 0;
            for (int i = 0; i < 8; i++) sid |= ((ulong)packet[i]) << (i * 8);
            int idx   = (packet[8]  << 8) | packet[9];
            int total = (packet[10] << 8) | packet[11];

            if (total <= 0 || total > MAX_SLICES) return null;
            if (idx < 0 || idx >= total) return null;

            var msg = _table.GetOrAdd(sid, _ => new PartialMsg {
                Total = total,
                Parts = new byte[total][],
                Received = 0,
                CreatedTick = Environment.TickCount64,
            });
            // 与首次登记的 total 不一致 (可能攻击者伪造同 sid 不同 total)
            if (msg.Total != total) return null;
            // 容量上限达到且当前 sid 是新消息 -> 不收 (防止 DoS 爆内存)
            if (_table.Count > MAX_PARTIAL_TABLE && msg.Received == 0)
                return null;

            if (msg.Parts![idx] == null) msg.Received++;
            msg.Parts[idx] = packet;
            if (msg.Received != msg.Total) return null;

            // 拼齐
            byte[] first = msg.Parts[0]!;
            uint origLen = ((uint)first[HEADER_BYTES]     << 24) |
                           ((uint)first[HEADER_BYTES + 1] << 16) |
                           ((uint)first[HEADER_BYTES + 2] <<  8) |
                           (uint)first[HEADER_BYTES + 3];

            if (origLen > MAX_MESSAGE_SIZE) return null;

            int realLen = 4 + (int)origLen;
            if (realLen < 4) return null; // 溢出检查
            byte[] full = new byte[realLen];
            int remaining = realLen;
            for (int i = 0; i < msg.Total; i++) {
                byte[] p = msg.Parts[i]!;
                int copy = Math.Min(SLICE_BYTES, remaining);
                Buffer.BlockCopy(p, HEADER_BYTES, full, realLen - remaining, copy);
                remaining -= copy;
            }
            _table.TryRemove(sid, out _);

            byte[] result = new byte[origLen];
            Buffer.BlockCopy(full, 4, result, 0, (int)origLen);
            CryptographicOperations.ZeroMemory(full.AsSpan(0, Math.Min(4, full.Length)));
            return result;
        }

        void SweepExpired() {
            long now = Environment.TickCount64;
            var toRemove = new List<ulong>();
            foreach (var kv in _table) {
                long elapsedSec = (now - kv.Value.CreatedTick) / 1000;
                if (elapsedSec > PARTIAL_TIMEOUT_SEC) toRemove.Add(kv.Key);
            }
            foreach (var s in toRemove) {
                if (_table.TryRemove(s, out var pm)) {
                    if (pm.Parts != null)
                        foreach (var p in pm.Parts)
                            if (p != null) CryptographicOperations.ZeroMemory(p);
                }
            }
            // 容量上限: 一直 evict 最老直到 <= MAX_PARTIAL_TABLE
            while (_table.Count > MAX_PARTIAL_TABLE) {
                ulong oldestSid = 0;
                long oldestTick = long.MaxValue;
                foreach (var kv in _table) {
                    if (kv.Value.CreatedTick < oldestTick) {
                        oldestTick = kv.Value.CreatedTick;
                        oldestSid = kv.Key;
                    }
                }
                if (oldestSid == 0) break;
                if (_table.TryRemove(oldestSid, out var pmOld)) {
                    if (pmOld?.Parts != null)
                        foreach (var p in pmOld.Parts)
                            if (p != null) CryptographicOperations.ZeroMemory(p);
                }
            }
        }

        /// <summary>测试用: 当前 partial 表大小</summary>
        public int PendingCount => _table.Count;

        /// <summary>强制清理超时 (测试用)</summary>
        public void ForceSweep() => SweepExpired();
    }

    /// <summary>
    /// 在每一个分片发送前 sleep 0~150ms 随机, 输出端通过回调函数 emit
    /// </summary>
    public static async Task SendWithJitter(
        IEnumerable<byte[]> slices, Func<byte[], Task> emitFn,
        int maxJitterMs = MAX_JITTER_MS, CancellationToken ct = default) {
        using var rng = RandomNumberGenerator.Create();
        byte[] b2 = new byte[2];
        foreach (var pkt in slices) {
            rng.GetBytes(b2);
            int jitter = (b2[0] | (b2[1] << 8)) % (maxJitterMs + 1);
            if (jitter > 0) {
                try { await Task.Delay(jitter, ct); }
                catch (TaskCanceledException) { return; }
            }
            await emitFn(pkt);
        }
    }

    /// <summary>
    /// 辅助: 把原始密文包成 "len4B + ciphertext", 便于 Reassembler 截尾
    /// </summary>
    public static byte[] WrapWithLengthHeader(byte[] data) {
        byte[] buf = new byte[4 + data.Length];
        uint L = (uint)data.Length;
        buf[0] = (byte)(L >> 24);
        buf[1] = (byte)(L >> 16);
        buf[2] = (byte)(L >>  8);
        buf[3] = (byte)(L);
        Buffer.BlockCopy(data, 0, buf, 4, data.Length);
        return buf;
    }

    public static byte[] GenerateSidSeed() {
        byte[] sid = new byte[8];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(sid);
        return sid;
    }
}
