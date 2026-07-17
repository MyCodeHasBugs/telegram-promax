// IdentityStore — Ed25519 长期身份密钥持久化
// --------------------------------------------------------------
// 问题背景: F5 踢人禁令以 id_pub 为键, 房主认领也靠 owner_id_pub 匹配.
//   若每次连接都 new Ed25519Keypair, id_pub 每会话变 → 禁入秒破 + 房主重连丢身份.
// 治本: 身份私钥落盘一次 (%LOCALAPPDATA%/E2EChatClient/identity.key),
//   之后每次启动加载复用, 保证 id_pub 跨重连稳定.
//
// 安全:
//   * 文件权限: Windows EFS 加密 (File.Encrypt) + Hidden + ReadOnly
//   * 私钥仅在内存中保留副本, 落盘后立即 zeroize 临时 buffer
//   * 文件格式: 32B raw Ed25519 seed (无 magic/header, 减少信息泄漏)
//   * 损坏/长度非 32B → 视为无效, 生成新身份覆写

using System;
using System.IO;
using System.Security.Cryptography;

namespace E2EChatClient.CryptoV2;

public static class IdentityStore
{
    private static readonly string IdentityDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "E2EChatClient");
    private static readonly string IdentityPath = Path.Combine(IdentityDir, "identity.key");

    /// <summary>
    /// 加载持久化身份密钥; 文件不存在或损坏则生成新身份并落盘.
    /// 返回的 Ed25519Keypair 由调用方拥有生命周期 (用完 Dispose).
    /// </summary>
    public static Ed25519Keypair LoadOrCreate()
    {
        // 尝试加载
        try
        {
            if (File.Exists(IdentityPath))
            {
                byte[] raw = File.ReadAllBytes(IdentityPath);
                if (raw.Length == 32)
                {
                    var kp = Ed25519Keypair.FromPrivateKey(raw);
                    CryptographicOperations.ZeroMemory(raw);
                    return kp;
                }
                // 长度不对 → 损坏, 落到生成新身份
                CryptographicOperations.ZeroMemory(raw);
            }
        }
        catch
        {
            // 读取失败 (权限/IO) → 退化为每次生成新身份 (不持久化, 但不崩溃)
            return Ed25519Keypair.Create();
        }

        // 生成新身份并落盘
        var keypair = Ed25519Keypair.Create();
        TrySave(keypair);
        return keypair;
    }

    /// <summary>
    /// 将 32B 私钥写入文件, 设 EFS 加密 + Hidden + ReadOnly.
    /// 失败不抛异常 (持久化是 best-effort, 不影响功能).
    /// </summary>
    private static void TrySave(Ed25519Keypair keypair)
    {
        byte[] priv = keypair.ExportPrivateKey();
        try
        {
            Directory.CreateDirectory(IdentityDir);
            File.WriteAllBytes(IdentityPath, priv);
            // Windows EFS 加密 (仅当前用户可解密) + 隐藏 + 只读
            try { File.Encrypt(IdentityPath); } catch { /* EFS 不可用时静默 */ }
            File.SetAttributes(IdentityPath,
                FileAttributes.Hidden | FileAttributes.ReadOnly);
        }
        catch
        {
            // 落盘失败: 身份仍可用 (仅本次会话), 下次启动会再试
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }
}
