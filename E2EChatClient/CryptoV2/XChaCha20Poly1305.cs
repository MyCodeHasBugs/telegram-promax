// ChaCha20 (RFC 8439) + HChaCha20 + XChaCha20-Poly1305
// 完全手写, 无第三方, 不放任何 placeholder
//
// 安全等级: XChaCha20 提供 24 字节 (192-bit) nonce, 抗乱用, 大批量消息无需放计数器管理
// AEAD 形态: IETF 拼接 — nonce || ciphertext || tag
// tag = 16 字节 Poly1305 MAC, 同时验证 (aad || ciphertext)
//
// 单条消息加密流程:
//   1) HChaCha20(key, nonce[0..16)) -> 32B subkey
//   2) ChaCha20(subkey, nonce[16..24) || zero_pad12, counter=0)
//      -> 第 0 个 64B block 用于 Poly1305 密钥
//      -> 第 1+ 个 block 用于流加密 plaintext
//   3) Poly1305(key=poly_key, aad || pad16 || ciphertext || pad16 ||
//               aad_len_le32 || cipher_len_le32) -> 16B tag
//   4) nonce || ciphertext || tag 一起作为 ciphertext 包

using System;
using System.Security.Cryptography;

namespace E2EChatClient.CryptoV2;

public static class XChaCha20Poly1305
{
    public const int KeySize   = 32;
    public const int NonceSize = 24;
    public const int TagSize   = 16;

    // ---------- helpers ----------
    static uint RotL32(uint x, int n) => (x << n) | (x >> (32 - n));

    static uint LoadLE32(byte[] b, int o) =>
        (uint)b[o] | ((uint)b[o + 1] << 8) | ((uint)b[o + 2] << 16) | ((uint)b[o + 3] << 24);

    static void StoreLE32(byte[] b, int o, uint v) {
        b[o] = (byte)v; b[o + 1] = (byte)(v >> 8);
        b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
    }

    // ---------- ChaCha quarter round ----------
    static void QR(ref uint a, ref uint b, ref uint c, ref uint d) {
        a += b; d ^= a; d = RotL32(d, 16);
        c += d; b ^= c; b = RotL32(b, 12);
        a += b; d ^= a; d = RotL32(d, 8);
        c += d; b ^= c; b = RotL32(b, 7);
    }

    // ---------- ChaCha20 block function 20 轮 (RFC 8439 §2.3) ----------
    static void ChaCha20Block(uint[] key, uint counter, uint[] nonce3, byte[] outBuf, int outOff) {
        uint[] s = new uint[16];
        s[0]  = 0x61707865; s[1]  = 0x3320646e; s[2]  = 0x79622d32; s[3]  = 0x6b206574;   // "expand 32-byte k"
        for (int i = 0; i < 8; i++) s[4 + i] = key[i];
        s[12] = counter;
        s[13] = nonce3[0]; s[14] = nonce3[1]; s[15] = nonce3[2];

        uint[] x = (uint[])s.Clone();
        for (int i = 0; i < 10; i++) {
            // column rounds
            QR(ref x[0], ref x[4], ref x[ 8], ref x[12]);
            QR(ref x[1], ref x[5], ref x[ 9], ref x[13]);
            QR(ref x[2], ref x[6], ref x[10], ref x[14]);
            QR(ref x[3], ref x[7], ref x[11], ref x[15]);
            // diagonal rounds
            QR(ref x[0], ref x[5], ref x[10], ref x[15]);
            QR(ref x[1], ref x[6], ref x[11], ref x[12]);
            QR(ref x[2], ref x[7], ref x[ 8], ref x[13]);
            QR(ref x[3], ref x[4], ref x[ 9], ref x[14]);
        }
        for (int i = 0; i < 16; i++)
            StoreLE32(outBuf, outOff + i * 4, x[i] + s[i]);
    }

    // ---------- HChaCha20: 输出 32B 子密钥 (draft-irtf-cfrg-xchacha §2.2.1) ----------
    static byte[] HChaCha20(byte[] key, byte[] nonce16) {
        uint[] s = new uint[16];
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        for (int i = 0; i < 8; i++) s[4 + i] = LoadLE32(key, i * 4);
        for (int i = 0; i < 4; i++) s[8 + i] = LoadLE32(nonce16, i * 4);
        s[12] = 0; s[13] = 0; s[14] = 0; s[15] = 0;

        uint[] x = (uint[])s.Clone();
        for (int i = 0; i < 10; i++) {
            QR(ref x[0], ref x[4], ref  x[8], ref x[12]);
            QR(ref x[1], ref x[5], ref  x[9], ref x[13]);
            QR(ref x[2], ref x[6], ref x[10], ref x[14]);
            QR(ref x[3], ref x[7], ref x[11], ref x[15]);
            QR(ref x[0], ref x[5], ref x[10], ref x[15]);
            QR(ref x[1], ref x[6], ref x[11], ref x[12]);
            QR(ref x[2], ref x[7], ref  x[8], ref x[13]);
            QR(ref x[3], ref x[4], ref  x[9], ref x[14]);
        }

        // HChaCha20 输出: x[0..3] || x[12..15] (8 个 uint = 32 字节)
        byte[] subkey = new byte[32];
        StoreLE32(subkey,  0, x[0]);
        StoreLE32(subkey,  4, x[1]);
        StoreLE32(subkey,  8, x[2]);
        StoreLE32(subkey, 12, x[3]);
        StoreLE32(subkey, 16, x[12]);
        StoreLE32(subkey, 20, x[13]);
        StoreLE32(subkey, 24, x[14]);
        StoreLE32(subkey, 28, x[15]);
        return subkey;
    }

    // ---------- ChaCha20 stream cipher ----------
    static void ChaCha20Xor(uint[] keyWords, uint counter, byte[] nonce12, byte[] data, int dataOff, int len) {
        uint[] nonce3 = new uint[3];
        for (int i = 0; i < 3; i++) nonce3[i] = LoadLE32(nonce12, i * 4);

        byte[] block = new byte[64];
        int p = dataOff;
        int remaining = len;
        while (remaining > 0) {
            ChaCha20Block(keyWords, counter, nonce3, block, 0);
            int n = Math.Min(64, remaining);
            for (int i = 0; i < n; i++)
                data[p + i] ^= block[i];
            p += n; remaining -= n; counter++;
        }
    }

    // ---------- Poly1305 (RFC 8439 §2.6) ----------
    // 用 BigInteger 做 mod 2^130 - 5, 简单且正确 (性能足够聊天场景)

    static void Poly1305Big(byte[] key, byte[] msg, int off, int len, byte[] tag, int tagOff) {
        System.Numerics.BigInteger r = BytesToUInt128Clamped(key, 0);
        System.Numerics.BigInteger s = BytesToUInt128(key, 16);
        System.Numerics.BigInteger p = (System.Numerics.BigInteger.One << 130) - 5;
        System.Numerics.BigInteger acc = 0;

        int i = 0;
        while (i < len) {
            int n = Math.Min(16, len - i);
            // n 字节 little-endian + 1 << (8n)
            byte[] block = new byte[17];   // 最多 16 字节 + 1 字节高位置 1
            Buffer.BlockCopy(msg, off + i, block, 0, n);
            block[n] = 1;                   // 高位 1
            var v = new System.Numerics.BigInteger(block);
            acc = ((acc + v) * r) % p;
            i += 16;
        }
        acc += s;
        // 取低 128-bit little endian
        byte[] accBytes = acc.ToByteArray();
        byte[] out16 = new byte[16];
        int copy = Math.Min(16, accBytes.Length);
        Buffer.BlockCopy(accBytes, 0, out16, 0, copy);
        Buffer.BlockCopy(out16, 0, tag, tagOff, 16);
    }

    static System.Numerics.BigInteger BytesToUInt128(byte[] b, int off) {
        byte[] tmp = new byte[17];
        for (int i = 0; i < 16; i++) tmp[i] = b[off + i];
        tmp[16] = 0;
        return new System.Numerics.BigInteger(tmp);
    }

    static System.Numerics.BigInteger BytesToUInt128Clamped(byte[] b, int off) {
        // clamp: byte 3/7/11/15 顶 4bit 清零, byte 4/8/12 底 2bit 清零
        byte[] c = new byte[16];
        for (int i = 0; i < 16; i++) c[i] = b[off + i];
        c[3]  &= 0x0f; c[7]  &= 0x0f; c[11] &= 0x0f; c[15] &= 0x0f;
        c[4]  &= 0xfc; c[8]  &= 0xfc; c[12] &= 0xfc;
        byte[] tmp = new byte[17];
        Buffer.BlockCopy(c, 0, tmp, 0, 16);
        tmp[16] = 0;
        return new System.Numerics.BigInteger(tmp);
    }

    // ---------- AEAD 公开 API ----------
    public static byte[] Encrypt(byte[] key, byte[] nonce24, byte[] plaintext, byte[]? aad = null) {
        if (key.Length != KeySize) throw new ArgumentException("key");
        if (nonce24.Length != NonceSize) throw new ArgumentException("nonce");

        // 1) subkey = HChaCha20(key, nonce[0..16])
        byte[] subkey = HChaCha20(key, nonce24);

        // 2) chacha20 nonce (12B) = 4 zero bytes || nonce[16..24]
        byte[] subNonce = new byte[12];
        Buffer.BlockCopy(nonce24, 16, subNonce, 4, 8);

        uint[] subkeyWords = new uint[8];
        for (int i = 0; i < 8; i++) subkeyWords[i] = LoadLE32(subkey, i * 4);

        // 3) poly key = first 32B of ChaCha20 stream with counter=0
        byte[] polyKeyBlock = new byte[64];
        ChaCha20Block(subkeyWords, 0, new uint[] {
            LoadLE32(subNonce, 0), LoadLE32(subNonce, 4), LoadLE32(subNonce, 8)
        }, polyKeyBlock, 0);
        byte[] polyKey = new byte[32];
        Buffer.BlockCopy(polyKeyBlock, 0, polyKey, 0, 32);

        // 4) encrypt plaintext with ChaCha20 starting at counter=1
        byte[] ct = (byte[])plaintext.Clone();
        ChaCha20Xor(subkeyWords, 1, subNonce, ct, 0, ct.Length);

        // 5) MAC = Poly1305(polyKey, aad || pad16 || ct || pad16 || aad_len_le32 || ct_len_le32)
        byte[] mac = new byte[16];
        using var ms = new System.IO.MemoryStream();
        if (aad != null && aad.Length > 0) {
            ms.Write(aad, 0, aad.Length);
            int pad1 = (16 - (aad.Length & 15)) & 15;
            if (pad1 > 0) ms.Write(new byte[pad1], 0, pad1);
        }
        ms.Write(ct, 0, ct.Length);
        int pad2 = (16 - (ct.Length & 15)) & 15;
        if (pad2 > 0) ms.Write(new byte[pad2], 0, pad2);
        byte[] lenBuf = new byte[8];
        uint aadLen = (uint)(aad?.Length ?? 0);
        uint ctLen  = (uint)ct.Length;
        StoreLE32(lenBuf, 0, aadLen);
        StoreLE32(lenBuf, 4, ctLen);
        ms.Write(lenBuf, 0, 8);

        byte[] macInput = ms.ToArray();
        Poly1305Big(polyKey, macInput, 0, macInput.Length, mac, 0);

        // output = nonce || ct || tag
        byte[] outBuf = new byte[NonceSize + ct.Length + TagSize];
        Buffer.BlockCopy(nonce24, 0, outBuf, 0, NonceSize);
        Buffer.BlockCopy(ct, 0, outBuf, NonceSize, ct.Length);
        Buffer.BlockCopy(mac, 0, outBuf, NonceSize + ct.Length, TagSize);
        return outBuf;
    }

    public static byte[] Decrypt(byte[] key, byte[] pkg, byte[]? aad = null) {
        if (key.Length != KeySize) throw new ArgumentException("key");
        if (pkg.Length < NonceSize + TagSize) throw new CryptographicException("pkg short");

        byte[] nonce24 = new byte[NonceSize];
        Buffer.BlockCopy(pkg, 0, nonce24, 0, NonceSize);
        int ctLen = pkg.Length - NonceSize - TagSize;
        byte[] ct = new byte[ctLen];
        Buffer.BlockCopy(pkg, NonceSize, ct, 0, ctLen);
        byte[] tag = new byte[TagSize];
        Buffer.BlockCopy(pkg, NonceSize + ctLen, tag, 0, TagSize);

        // 1) subkey
        byte[] subkey = HChaCha20(key, nonce24);
        byte[] subNonce = new byte[12];
        Buffer.BlockCopy(nonce24, 16, subNonce, 4, 8);
        uint[] subkeyWords = new uint[8];
        for (int i = 0; i < 8; i++) subkeyWords[i] = LoadLE32(subkey, i * 4);

        // 2) poly key
        byte[] polyKeyBlock = new byte[64];
        ChaCha20Block(subkeyWords, 0, new uint[] {
            LoadLE32(subNonce, 0), LoadLE32(subNonce, 4), LoadLE32(subNonce, 8)
        }, polyKeyBlock, 0);
        byte[] polyKey = new byte[32];
        Buffer.BlockCopy(polyKeyBlock, 0, polyKey, 0, 32);

        // 3) recompute MAC
        byte[] macInput;
        using (var ms = new System.IO.MemoryStream()) {
            if (aad != null && aad.Length > 0) {
                ms.Write(aad, 0, aad.Length);
                int pad1 = (16 - (aad.Length & 15)) & 15;
                if (pad1 > 0) ms.Write(new byte[pad1], 0, pad1);
            }
            ms.Write(ct, 0, ct.Length);
            int pad2 = (16 - (ct.Length & 15)) & 15;
            if (pad2 > 0) ms.Write(new byte[pad2], 0, pad2);
            byte[] lenBuf = new byte[8];
            StoreLE32(lenBuf, 0, (uint)(aad?.Length ?? 0));
            StoreLE32(lenBuf, 4, (uint)ct.Length);
            ms.Write(lenBuf, 0, 8);
            macInput = ms.ToArray();
        }
        byte[] expect = new byte[16];
        Poly1305Big(polyKey, macInput, 0, macInput.Length, expect, 0);
        bool ok = CryptographicOperations.FixedTimeEquals(expect, tag);
        if (!ok) throw new CryptographicException("Poly1305 tag mismatch");

        // 4) decrypt
        byte[] pt = (byte[])ct.Clone();
        ChaCha20Xor(subkeyWords, 1, subNonce, pt, 0, pt.Length);
        return pt;
    }

    public static byte[] GenerateNonce() {
        byte[] n = new byte[NonceSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(n);
        return n;
    }
}
