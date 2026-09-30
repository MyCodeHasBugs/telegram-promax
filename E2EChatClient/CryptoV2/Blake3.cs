// BLAKE3 thin wrapper: delegate to BLAKE3 official NuGet package
// (the previous hand-written C# port was deterministic but produced wrong hash values;
// this is byte-for-byte equivalent with PyPI blake3 / Rust official.)
//
// API intact so callers like ChatSessionV2 / MainWindow Fingerprint still work.
//   >>> rename note <<<  Class renamed from `Blake3` to `Blake3Hash` to avoid collision
//   with the BLAKE3 NuGet 2.2.x which uses namespace `Blake3`. Callers are updated to
//   use `Blake3Hash.HashHex / .Hash` etc.

using System;
using System.Text;
using NuBlake3 = global::Blake3;

namespace E2EChatClient.CryptoV2
{
    public static class Blake3Hash
    {
        public const int BlockLen    = 64;
        public const int ChunkLen    = 1024;
        public const int OutLen      = 32;
        public const int KeyLen      = 32;

        static byte[] HashRaw(ReadOnlySpan<byte> input) {
            var h = NuBlake3.Hasher.New();
            h.Update(input);
            var hash = h.Finalize();
            return hash.AsSpan().ToArray();
        }

        public static byte[] Hash(byte[] input) {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return HashRaw(input);
        }

        public static byte[] HashKeyed(byte[] key, byte[] input) {
            if (key == null || key.Length != KeyLen) throw new ArgumentException("key 32B");
            var h = NuBlake3.Hasher.NewKeyed(key);
            h.Update(input);
            var hash = h.Finalize();
            return hash.AsSpan().ToArray();
        }

        public static byte[] HashExtended(byte[] input, int outLen) {
            // BUG-7 修复: outLen > 32 时旧代码用零填充, 不是真正的 BLAKE3 XOF 扩展输出.
            //   BLAKE3 NuGet 2.2.x 的 Finalize() 只返回 32B; 要 >32B 需用 XOF seek 模式.
            //   当前项目内无 >32B 调用方, 为安全起见直接拒绝, 防误用产出弱密钥.
            if (outLen <= 0) return Array.Empty<byte>();
            if (outLen > 32)
                throw new ArgumentOutOfRangeException(nameof(outLen),
                    "HashExtended 当前仅支持 ≤ 32B (BLAKE3 标准 digest). " +
                    "> 32B 需用 XOF 模式, 请改用 BLAKE3 NuGet 的 Hasher.Finalize(Span<byte>) API.");
            var h = NuBlake3.Hasher.New();
            h.Update(input);
            var hash = h.Finalize();
            byte[] src = hash.AsSpan().ToArray();
            return src[..outLen];
        }

        public static string HashHex(byte[] input) {
            byte[] d = Hash(input);
            var sb = new StringBuilder(d.Length * 2);
            const string H = "0123456789abcdef";
            foreach (var b in d) {
                sb.Append(H[(b >> 4) & 0xf]);
                sb.Append(H[b & 0xf]);
            }
            return sb.ToString();
        }
    }
}
