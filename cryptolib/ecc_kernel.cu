// ecc_kernel.cu — X25519 batch_keygen 在 GPU 上跑
// =================================================================
// ⚠️  警告：本文件 **未实现真正的 X25519**.
//          历史版本里 `x25519_scalar_mult_base` 是 `priv ^ 0x5A` 占位,
//          产出的 "公钥" 与任何 X25519 实现都对不上, 但编译能走通 — 这是
//          典型的脚枪 (Pass3-F3-7 / Pass4-F4-4). 若 GPU DLL 被编出来并与客户端
//          一起发布, 后端是错的, 安全属性清零.
//
// 现在的做法: 让任何尝试编译此文件做真实密钥生成的路径 **直接编译失败**,
//           不留静默错误路径. 真要部署 GPU 路径请补完整
//           5×52-bit limb Montgomery ladder (RFC 7748), 并恢复 downstream
//           callers. 客户端当前运行路径是 C# 端 Curve25519.cs (BigInteger),
//           不依赖此文件.
// =================================================================

#include "cryptolib.h"
#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 占位留给将来真实实现. 下面的 #error 让"未实现却被编进生产 DLL"这条
// 路径直接断, 不留半成品公钥流出去.
#ifndef E2ECHAT_GPU_ALLOW_PLACEHOLDER
#error "ecc_kernel.cu: X25519 未实现真实 Montgomery ladder. \
如需启用 GPU 路径请补完整 5×52 limb 实现, 并去掉此 #error (定义 \
E2ECHAT_GPU_ALLOW_PLACEHOLDER 仅在 you 确认实现就位后). 当前客户端走 \
C# Curve25519.cs, 不需要本文件参与编译."
#endif

// 模 past 实现的 limb/转化函数保留为参考骨架, 真实实现就位时填实.
// 把 32-byte little-endian 装填进 5×52 limb
static __device__ __forceinline__ void bytes_to_limbs(const uint8_t in[32], uint64_t out[5])
{
    uint64_t t = 0;
    int i = 0, bits = 0;
    for (int j = 0; j < 5; j++) {
        while (bits < 51 && i < 32) {
            t |= ((uint64_t)in[i]) << bits;
            bits += 8;
            i++;
        }
        if (bits >= 51) {
            out[j] = t & ((1ULL << 51) - 1);
            t >>= 51;
            bits -= 51;
        }
    }
}

static __device__ __forceinline__ void limbs_to_bytes(const uint64_t in[5], uint8_t out[32])
{
    // TODO: 真实 mod p + 写回 32 字节 little-endian.
    (void)in; (void)out;
}

static __device__ void x25519_scalar_mult_base(const uint8_t priv[32], uint8_t pub_out[32])
{
    // TODO: 真实 5×52 limb Montgomery ladder (RFC 7748 §5).
    (void)priv; (void)pub_out;
}

// ===== Kernel =====
__global__ void batch_keygen_kernel(int count, char* out_pairs)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    uint8_t priv[32];
    for (int i = 0; i < 32; i++)
        priv[i] = (uint8_t)((idx * 31 + i * 7 + 0x9e) & 0xff);
    priv[0]  &= 248;
    priv[31] &= 127;
    priv[31] |= 64;

    uint8_t pub[32];
    x25519_scalar_mult_base(priv, pub);

    char* slot = out_pairs + idx * 200;
    char hex[] = "0123456789abcdef";
    int p = 0;
    for (int i = 0; i < 32; i++) {
        slot[p++] = hex[(pub[i] >> 4) & 0xf];
        slot[p++] = hex[pub[i] & 0xf];
    }
    slot[p++] = '|';
    for (int i = 0; i < 32; i++) {
        slot[p++] = hex[(priv[i] >> 4) & 0xf];
        slot[p++] = hex[priv[i] & 0xf];
    }
    slot[p] = 0;
}

// ===== Host-side wrapper exported to C# =====
extern "C" int batch_keygen_cuda(int count, char* out, int out_len)
{
    int bytes_per_pair = 200;
    int total_bytes = count * bytes_per_pair;
    if (total_bytes > out_len) return -1;

    char* d_out;
    if (cudaMalloc(&d_out, total_bytes) != cudaSuccess) return -1;
    cudaMemset(d_out, 0, total_bytes);

    int threads = 256;
    int blocks = (count + threads - 1) / threads;
    batch_keygen_kernel<<<threads, blocks>>>(count, d_out);

    if (cudaDeviceSynchronize() != cudaSuccess) {
        cudaFree(d_out);
        return -1;
    }

    cudaMemcpy(out, d_out, total_bytes, cudaMemcpyDeviceToHost);
    cudaFree(d_out);
    return total_bytes;
}
