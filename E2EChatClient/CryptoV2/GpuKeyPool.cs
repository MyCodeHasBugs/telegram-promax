// GpuKeyPool — GPU 批量预生成 X25519 会话密钥池
// ============================================================
// cryptolib.dll 编译 CUDA 版后 (见 ecc_kernel.cu 头注释), 这里自动
// 预生成一批会话密钥, ChatSessionV2 构造时从池里取, 免去每会话
// CPU 现场算. GPU 不可用 / DLL 缺失 → 全部静默回退 CPU 现算.
//
// 侧信道注: GPU keygen 非常数时间 — 但标量来自宿主 OS CSPRNG,
//           一次性会话密钥, 公钥计算时序不泄漏有意义信息.
// ============================================================

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using E2EChatClient.Native;

namespace E2EChatClient.CryptoV2
{
    public static class GpuKeyPool
    {
        private static readonly ConcurrentQueue<(byte[] pub, byte[] priv)> _pool = new();
        private static int _filling;   // 0=闲 1=正在填 (Interlocked)

        public static bool IsGpuBacked => CryptoLibBridge.IsDllAvailable() && CryptoLibBridge.IsGpuAvailable();

        /// <summary>启动时后台填池 (32 把). 不阻塞 UI.</summary>
        public static void TryFillAsync()
        {
            if (!IsGpuBacked) return;
            if (Interlocked.CompareExchange(ref _filling, 1, 0) != 0) return;
            _ = Task.Run(() =>
            {
                try
                {
                    string[]? pairs = CryptoLibBridge.GpuBatchKeypairs(32);
                    if (pairs == null) return;
                    foreach (var p in pairs)
                    {
                        int bar = p.IndexOf('|');
                        if (bar <= 0) continue;
                        try
                        {
                            byte[] pub  = Convert.FromBase64String(p[..bar]);
                            byte[] priv = Convert.FromBase64String(p[(bar + 1)..]);
                            if (pub.Length == 32 && priv.Length == 32)
                                _pool.Enqueue((pub, priv));
                        }
                        catch (FormatException) { /* 坏条目跳过 */ }
                    }
                }
                catch { /* GPU 出错不影响主链 */ }
                finally { _filling = 0; }
            });
        }

        /// <summary>从池取一把; 池空返回 null (调用方 CPU 现算).</summary>
        public static (byte[]? pub, byte[]? priv) TryTake()
        {
            if (_pool.TryDequeue(out var k)) return k;
            return (null, null);
        }

        public static int PoolCount => _pool.Count;
    }
}
