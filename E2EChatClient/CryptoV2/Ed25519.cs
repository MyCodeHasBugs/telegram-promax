// Ed25519 — NSec.Cryptography (libsodium 后端)

using System;
using NSec.Cryptography;

namespace E2EChatClient.CryptoV2;

public sealed class Ed25519Keypair : IDisposable
{
    public byte[]? PublicKey;     // 32B
    private byte[]? _privateKey;  // 32B seed
    // 缓存已 Import 的 NSec Key 对象, 避免每次 Sign 都 Import + 不 Dispose 导致
    // 私钥明文在堆上滞留到 GC. Sign 调用频繁 (每条消息一次), 复用 Key 对象.
    private Key? _importedKey;

    public static Ed25519Keypair Create()
    {
        var algo = SignatureAlgorithm.Ed25519;
        // NSec 默认禁止导出私钥; 必须显式允许明文导出才能取出 raw private key
        var kp = new Key(algo, new KeyCreationParameters {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        });
        byte[] pub  = kp.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        byte[] priv = kp.Export(KeyBlobFormat.RawPrivateKey);
        // kp 自带 Dispose (NSec Key 实现 IDisposable), 但 Export 后即可释放
        kp.Dispose();
        return new Ed25519Keypair { PublicKey = pub, _privateKey = priv };
    }

    /// <summary>
    /// 用导入的 NSec Key 对象做缓存, 避免每次 Sign 都 import 一次临时 Key 不释放
    /// 导致 raw private key 在堆里漂着到 GC. 第一次调用惰性 import, 后续复用.
    /// </summary>
    private Key GetImportedKey()
    {
        if (_importedKey != null) return _importedKey;
        if (_privateKey == null) throw new InvalidOperationException("no priv");

        var algo = SignatureAlgorithm.Ed25519;
        _importedKey = Key.Import(algo, _privateKey,
                                   KeyBlobFormat.RawPrivateKey,
                                   new KeyCreationParameters());
        return _importedKey;
    }

    public byte[] Sign(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        var algo = SignatureAlgorithm.Ed25519;
        var kp   = GetImportedKey();
        return algo.Sign(kp, data);
    }

    public static bool Verify(byte[] publicKey, byte[] data, byte[] signature) {
        if (publicKey == null || publicKey.Length != 32)
            throw new ArgumentException("publicKey must be 32 bytes", nameof(publicKey));
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (signature == null || signature.Length != 64)
            throw new ArgumentException("signature must be 64 bytes", nameof(signature));
        var algo = SignatureAlgorithm.Ed25519;
        // 显式限定到 NSec.Cryptography.PublicKey, 避免与本类实例字段 PublicKey 冲突 (CS0120)
        var pubKey = NSec.Cryptography.PublicKey.Import(algo, publicKey,
                                       KeyBlobFormat.RawPublicKey);
        return algo.Verify(pubKey, data, signature);
    }

    public void Dispose() {
        // 先 Dispose 已 import 的 Key (NSec 内部 zeroize 私钥 in-memory)
        _importedKey?.Dispose();
        _importedKey = null;

        if (_privateKey != null) {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_privateKey);
            _privateKey = null;
        }
        if (PublicKey != null) {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(PublicKey);
            PublicKey = null;
        }
    }
}
