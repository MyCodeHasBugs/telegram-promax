// ML-KEM-1024 (NIST FIPS 203, 原 CRYSTALS-Kyber-1024) 薄封装.
// ============================================================
// 抗量子关键点: X25519/ECC 会被 Shor 算法在量子机上破解,
// "先存后解密" (harvest-now, decrypt-later) 攻击在长寿命量子机出现
// 即可反解今天录到的全部密文. ML-KEM 是 NIST 标准化的格基 KEM,
// 目前公认抗 Grover/Shor 类量子攻击.
//
// 握手混合模式: seed = HKDF(X25519_shared || ML-KEM_ss) —
// 任一算法不破, 整体立即安全 (即使 X25519 日后被量子破, 密文仍安全).
//
// 协议: epub 字典序较小的一方为 encapsulator, 对端为 decapsulator.
// 私钥永不落盘, Dispose 时 zeroize.
// ============================================================

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Security;

namespace E2EChatClient.CryptoV2
{
    public sealed class MlKemKeyPair : IDisposable
    {
        public byte[] PublicKey  { get; }
        public byte[] PrivateKey { get; }

        internal MlKemKeyPair(byte[] pub, byte[] priv) { PublicKey = pub; PrivateKey = priv; }

        public void Dispose()
        {
            if (PrivateKey != null)
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(PrivateKey);
        }
    }

    public static class MlKemHybrid
    {
        // ML-KEM-1024 (参数集 3, NIST 安全等级 5): pub=1568B, ct=1568B, ss=32B
        public const int PUBLIC_KEY_BYTES    = 1568;
        public const int CIPHERTEXT_BYTES    = 1568;
        public const int SHARED_SECRET_BYTES = 32;

        private static readonly MLKemParameters Params = MLKemParameters.ml_kem_1024;

        /// <summary> 生成 ML-KEM-1024 密钥对 (CSPRNG 强随机). </summary>
        public static MlKemKeyPair GenerateKeyPair()
        {
            var gen = new MLKemKeyPairGenerator();
            gen.Init(new MLKemKeyGenerationParameters(new SecureRandom(), Params));
            var pair = gen.GenerateKeyPair();
            var pub  = (MLKemPublicKeyParameters)pair.Public;
            var priv = (MLKemPrivateKeyParameters)pair.Private;
            return new MlKemKeyPair(pub.GetEncoded(), priv.GetEncoded());
        }

        /// <summary> 对 peer 公钥封装 -> (ciphertext 1568B, sharedSecret 32B). </summary>
        public static (byte[] CipherText, byte[] SharedSecret) Encapsulate(byte[] peerPubBytes)
        {
            if (peerPubBytes == null || peerPubBytes.Length != PUBLIC_KEY_BYTES)
                throw new ArgumentException("kpub 必须是 ML-KEM-1024 公钥 (1568B)");

            var pub = MLKemPublicKeyParameters.FromEncoding(Params, peerPubBytes);
            var enc = new MLKemEncapsulator(Params);
            enc.Init(pub);

            byte[] ct = new byte[enc.EncapsulationLength];
            byte[] ss = new byte[enc.SecretLength];
            enc.Encapsulate(ct, 0, ct.Length, ss, 0, ss.Length);
            return (ct, ss);
        }

        /// <summary> 解封 peer 发回的 ciphertext -> sharedSecret 32B. </summary>
        public static byte[] Decapsulate(byte[] privBytes, byte[] cipherText)
        {
            if (privBytes == null) throw new ArgumentException("priv 为空");
            if (cipherText == null || cipherText.Length != CIPHERTEXT_BYTES)
                throw new ArgumentException("kem_ct 必须是 ML-KEM-1024 密文 (1568B)");

            var priv = MLKemPrivateKeyParameters.FromEncoding(Params, privBytes);
            var dec = new MLKemDecapsulator(Params);
            dec.Init(priv);

            byte[] ss = new byte[dec.SecretLength];
            dec.Decapsulate(cipherText, 0, cipherText.Length, ss, 0, ss.Length);
            return ss;
        }
    }
}
