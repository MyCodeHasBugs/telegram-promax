using System;
using System.Runtime.InteropServices;
using System.Text;

namespace E2EChatClient.Native
{
    /// <summary>
    /// CryptoLib.dll P/Invoke 隔离层
    /// =============================
    /// V2 只用 DLL 来做:
    ///   1. IsDllAvailable / IsGpuAvailable — MainWindow 启动显示状态
    ///   2. GpuBatchKeypairs — 预留 CUDA 批量密钥对接口 (未实现即返回 null, 不影响主链)
    ///
    /// 之前的 hybrid_encrypt / hybrid_decrypt / generate_keypair DLL entry 在 V2
    /// 不再使用 (审计指出 DLL 占位实现是 "ERROR:not_implemented", 误接会静默破坏加密),
    /// 已全部从此 bridge 删除. V2 走 NSec.Cryptography (libsodium) 纯 C# ECDH/XChaCha.
    /// </summary>
    public static class CryptoLibBridge
    {
        const string DLL = "CryptoLib.dll";

        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
        private static extern void free_string(IntPtr p);

        // === GPU 预留接口 (待 CUDA DLL 编译后启用) ===
        //   void gpu_batch_keygen(int count,
        //                          char* outPairs,
        //                          int outBufLen);

        [DllImport(DLL, CallingConvention = CallingConvention.Cdecl, EntryPoint = "gpu_batch_keygen")]
        private static extern int gpu_batch_keygen_native(int count, IntPtr outBuf, int outBufLen);

        public static bool IsDllAvailable()
        {
            try
            {
                string path = System.IO.Path.Combine(AppContext.BaseDirectory, DLL);
                return System.IO.File.Exists(path);
            }
            catch { return false; }
        }

        /// <summary>
        /// 检测 GPU 是否可用 (调用 gpu_batch_keygen with count=0)
        /// </summary>
        public static bool IsGpuAvailable()
        {
            try
            {
                IntPtr buf = Marshal.AllocHGlobal(0);
                try
                {
                    int r = gpu_batch_keygen_native(0, buf, 0);
                    return r >= 0;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            catch { return false; }
        }

        /// <summary>
        /// GPU 批量密钥对 — 预留接口, CUDA kernel 编译好后直接生效.
        /// </summary>
        public static string[]? GpuBatchKeypairs(int count)
        {
            if (count <= 0) return Array.Empty<string>();

            const int MAX_PAIR_BYTES = 200;
            int bufLen = count * MAX_PAIR_BYTES;
            IntPtr buf = Marshal.AllocHGlobal(bufLen);
            try
            {
                int written = gpu_batch_keygen_native(count, buf, bufLen);
                if (written < 0) return null;

                byte[] arr = new byte[written];
                Marshal.Copy(buf, arr, 0, written);

                string full = Encoding.UTF8.GetString(arr, 0, written);
                return full.Split('\0', StringSplitOptions.RemoveEmptyEntries);
            }
            catch { return null; }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static string? PtrToStringAndFree(IntPtr p)
        {
            if (p == IntPtr.Zero) return null;
            int i = 0;
            while (Marshal.ReadByte(p, i) != 0) i++;
            byte[] buf = new byte[i];
            Marshal.Copy(p, buf, 0, i);
            free_string(p);
            return Encoding.UTF8.GetString(buf);
        }
    }
}
