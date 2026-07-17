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
            var h = NuBlake3.Hasher.New();
            h.Update(input);
            var hash = h.Finalize();
            byte[] src = hash.AsSpan().ToArray();
            if (outLen <= 0) return Array.Empty<byte>();
            if (outLen <= src.Length) return src[..outLen];
            byte[] big = new byte[outLen];
            Buffer.BlockCopy(src, 0, big, 0, Math.Min(src.Length, big.Length));
            return big;
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
