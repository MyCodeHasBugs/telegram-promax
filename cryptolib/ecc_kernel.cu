// ecc_kernel.cu — X25519 批量密钥生成 (CUDA GPU 加速)
// =====================================================================
// 实现 batch_keygen_cuda(count, out, out_len):
//   * 每线程: 32B 随机标量 (宿主侧 OS CSPRNG 提供, 宿主已 clamp) ->
//     Montgomery ladder × base point 9 -> 32B 公钥
//   * 输出格式与 cryptolib.h 约定一致: "pub_b64|priv_b64\0" 逐条拼接
//   * count=0 时跑 RFC 7748 标准向量自测 (CPU 参考实现 + GPU 各一遍),
//     返回 0 = 通过, -1 = 失败. C# 端 IsGpuAvailable() 用它探测.
//
// 域运算: 2^255-19, 10-limb radix 2^25.5 (ref10/donna 风格),
//         全程 u32×u32→u64 乘法 — 兼容所有 CUDA 架构 (不依赖 __int128).
//
// 侧信道说明: 密钥均为一次性会话密钥, 标量来自宿主 OS CSPRNG,
//             公钥计算的时序不泄漏有意义信息 — 不强制 constant-time.
//
// 编译 (生产 DLL, 含 CUDA + OpenSSL):
//   nvcc -shared -o CryptoLib.dll -DUSE_CUDA -DHAVE_OPENSSL ^
//        -Xcompiler "/EHsc /MD" cryptolib.cpp ecc_kernel.cu -lcrypto
// 编译 (无 CUDA, 纯 CPU DLL):
//   cl /LD /EHsc /MD /DHAVE_OPENSSL cryptolib.cpp
// =====================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __CUDACC__
#define HD  __host__ __device__
#define FI  __forceinline__
#include <cuda_runtime.h>
#include <random>
#else
#define HD
#define FI  inline
#endif

// =====================================================================
//  域运算: 2^255-19, 10-limb (radix 2^25.5)
//  limb 位宽: [26,25,26,25,26,25,26,25,26,25] (共 255 bit)
// =====================================================================
typedef uint32_t fe[10];

#define MASK25 0x1FFFFFFu
#define MASK26 0x3FFFFFFu

HD FI void fe_zero(fe h) {
#pragma unroll
    for (int i = 0; i < 10; i++) h[i] = 0;
}

HD FI void fe_one(fe h) {
    fe_zero(h); h[0] = 1;
}

HD FI void fe_copy(fe dst, const fe src) {
#pragma unroll
    for (int i = 0; i < 10; i++) dst[i] = src[i];
}

HD FI void fe_cswap(int swap, fe a, fe b) {
    uint32_t m = (uint32_t)(-(int32_t)swap);
#pragma unroll
    for (int i = 0; i < 10; i++) {
        uint32_t t = m & (a[i] ^ b[i]);
        a[i] ^= t; b[i] ^= t;
    }
}

// out = a + b (不做 carry; 输入 limb < 2^26 → 输出 < 2^27, 值域安全)
HD FI void fe_add(fe out, const fe a, const fe b) {
#pragma unroll
    for (int i = 0; i < 10; i++) out[i] = a[i] + b[i];
}

// out = a - b + 2p (保证非负), 完整 carry 归约
HD FI void fe_sub(fe out, const fe a, const fe b) {
    out[0] = a[0] + 0x7FFFFDAu - b[0];
    out[1] = a[1] + 0x7FFFFFEu - b[1];
    out[2] = a[2] + 0x7FFFFFEu - b[2];
    out[3] = a[3] + 0x7FFFFFEu - b[3];
    out[4] = a[4] + 0x7FFFFFEu - b[4];
    out[5] = a[5] + 0x3FFFFFEu - b[5];
    out[6] = a[6] + 0x3FFFFFEu - b[6];
    out[7] = a[7] + 0x3FFFFFEu - b[7];
    out[8] = a[8] + 0x3FFFFFEu - b[8];
    out[9] = a[9] + 0x3FFFFFEu - b[9];

    uint64_t c;
    c = out[0] >> 26; out[0] &= MASK26; out[1] += (uint32_t)c;
    c = out[1] >> 25; out[1] &= MASK25; out[2] += (uint32_t)c;
    c = out[2] >> 26; out[2] &= MASK26; out[3] += (uint32_t)c;
    c = out[3] >> 25; out[3] &= MASK25; out[4] += (uint32_t)c;
    c = out[4] >> 26; out[4] &= MASK26; out[5] += (uint32_t)c;
    c = out[5] >> 25; out[5] &= MASK25; out[6] += (uint32_t)c;
    c = out[6] >> 26; out[6] &= MASK26; out[7] += (uint32_t)c;
    c = out[7] >> 25; out[7] &= MASK25; out[8] += (uint32_t)c;
    c = out[8] >> 26; out[8] &= MASK26; out[9] += (uint32_t)c;
    c = out[9] >> 25; out[9] &= MASK25;
    out[0] += (uint32_t)(c * 19u);
    out[1] += out[0] >> 26; out[0] &= MASK26;
}

// 乘法: 10×10 schoolbook + 19 交叉归约 + carry 链
// 输入 limb < 2^27 时中间量 ≤ 2^61.7, 安全落在 u64 内
HD FI void fe_mul(fe out, const fe a, const fe b) {
    uint64_t a0=a[0],a1=a[1],a2=a[2],a3=a[3],a4=a[4];
    uint64_t a5=a[5],a6=a[6],a7=a[7],a8=a[8],a9=a[9];
    uint64_t b0=b[0],b1=b[1],b2=b[2],b3=b[3],b4=b[4];
    uint64_t b5=b[5],b6=b[6],b7=b[7],b8=b[8],b9=b[9];

    uint64_t r0 = a0*b0 + 19u*(a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1);
    uint64_t r1 = a0*b1 + a1*b0 + 19u*(a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2);
    uint64_t r2 = a0*b2 + a1*b1 + a2*b0 + 19u*(a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3);
    uint64_t r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + 19u*(a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4);
    uint64_t r4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 + 19u*(a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5);
    uint64_t r5 = a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0 + 19u*(a6*b9 + a7*b8 + a8*b7 + a9*b6);
    uint64_t r6 = a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0 + 19u*(a7*b9 + a8*b8 + a9*b7);
    uint64_t r7 = a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0 + 19u*(a8*b9 + a9*b8);
    uint64_t r8 = a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0 + 19u*(a9*b9);
    uint64_t r9 = a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;

    uint64_t c;
    c = r0 >> 26; r0 &= MASK26; r1 += c;
    c = r1 >> 25; r1 &= MASK25; r2 += c;
    c = r2 >> 26; r2 &= MASK26; r3 += c;
    c = r3 >> 25; r3 &= MASK25; r4 += c;
    c = r4 >> 26; r4 &= MASK26; r5 += c;
    c = r5 >> 25; r5 &= MASK25; r6 += c;
    c = r6 >> 26; r6 &= MASK26; r7 += c;
    c = r7 >> 25; r7 &= MASK25; r8 += c;
    c = r8 >> 26; r8 &= MASK26; r9 += c;
    c = r9 >> 25; r9 &= MASK25;
    c = c * 19u;
    r0 += c;
    c = r0 >> 26; r0 &= MASK26; r1 += c;
    c = r1 >> 25; r1 &= MASK25; r2 += c;

    out[0]=(uint32_t)r0;  out[1]=(uint32_t)r1;  out[2]=(uint32_t)r2;
    out[3]=(uint32_t)r3;  out[4]=(uint32_t)r4;  out[5]=(uint32_t)r5;
    out[6]=(uint32_t)r6;  out[7]=(uint32_t)r7;  out[8]=(uint32_t)r8;
    out[9]=(uint32_t)r9;
}

HD FI void fe_sq(fe out, const fe a) {
    fe_mul(out, a, a);
}

HD FI void fe_mul121666(fe out, const fe a) {
    uint64_t r[10];
#pragma unroll
    for (int i = 0; i < 10; i++) r[i] = (uint64_t)a[i] * 121666u;

    uint64_t c;
    c = r[0] >> 26; r[0] &= MASK26; r[1] += c;
    c = r[1] >> 25; r[1] &= MASK25; r[2] += c;
    c = r[2] >> 26; r[2] &= MASK26; r[3] += c;
    c = r[3] >> 25; r[3] &= MASK25; r[4] += c;
    c = r[4] >> 26; r[4] &= MASK26; r[5] += c;
    c = r[5] >> 25; r[5] &= MASK25; r[6] += c;
    c = r[6] >> 26; r[6] &= MASK26; r[7] += c;
    c = r[7] >> 25; r[7] &= MASK25; r[8] += c;
    c = r[8] >> 26; r[8] &= MASK26; r[9] += c;
    c = r[9] >> 25; r[9] &= MASK25;
    r[0] += c * 19u;
    c = r[0] >> 26; r[0] &= MASK26; r[1] += c;

    out[0]=(uint32_t)r[0];  out[1]=(uint32_t)r[1];  out[2]=(uint32_t)r[2];
    out[3]=(uint32_t)r[3];  out[4]=(uint32_t)r[4];  out[5]=(uint32_t)r[5];
    out[6]=(uint32_t)r[6];  out[7]=(uint32_t)r[7];  out[8]=(uint32_t)r[8];
    out[9]=(uint32_t)r[9];
}

// ---- 32B LE <-> 10 limbs ----
// limb 累计位偏移: h0:0-25 h1:26-50 h2:51-76 h3:77-101 h4:102-127
//                  h5:128-152 h6:153-178 h7:179-203 h8:204-229 h9:230-254
HD FI void fe_frombytes(fe h, const uint8_t* s) {
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    for (int i = 0; i < 8; i++) {
        t0 |= ((uint64_t)s[i])      << (8 * i);
        t1 |= ((uint64_t)s[8 + i])  << (8 * i);
        t2 |= ((uint64_t)s[16 + i]) << (8 * i);
        t3 |= ((uint64_t)s[24 + i]) << (8 * i);
    }
    t3 &= 0x7FFFFFFFFFFFFFFFull;   // 清 bit255

    h[0] = (uint32_t)( t0                  & MASK26);
    h[1] = (uint32_t)((t0 >> 26)           & MASK25);
    h[2] = (uint32_t)(((t0 >> 51) | (t1 << 13)) & MASK26);
    h[3] = (uint32_t)( (t1 >> 13)          & MASK25);
    h[4] = (uint32_t)( (t1 >> 38)          & MASK26);
    h[5] = (uint32_t)( t2                  & MASK25);
    h[6] = (uint32_t)((t2 >> 25)           & MASK26);
    h[7] = (uint32_t)(((t2 >> 51) | (t3 << 13)) & MASK25);
    h[8] = (uint32_t)( (t3 >> 12)          & MASK26);
    h[9] = (uint32_t)( (t3 >> 38)          & MASK25);
}

// 10 limbs -> 32B LE (完整归约 2^255-19)
HD FI void fe_tobytes(uint8_t* s, const fe h) {
    uint64_t q[10];
#pragma unroll
    for (int i = 0; i < 10; i++) q[i] = (uint64_t)h[i];

    // 完整 carry 归约 (含 2^255 位折回 +19)
    uint64_t c;
    c = q[0] >> 26; q[0] &= MASK26; q[1] += c;
    c = q[1] >> 25; q[1] &= MASK25; q[2] += c;
    c = q[2] >> 26; q[2] &= MASK26; q[3] += c;
    c = q[3] >> 25; q[3] &= MASK25; q[4] += c;
    c = q[4] >> 26; q[4] &= MASK26; q[5] += c;
    c = q[5] >> 25; q[5] &= MASK25; q[6] += c;
    c = q[6] >> 26; q[6] &= MASK26; q[7] += c;
    c = q[7] >> 25; q[7] &= MASK25; q[8] += c;
    c = q[8] >> 26; q[8] &= MASK26; q[9] += c;
    c = q[9] >> 25; q[9] &= MASK25;
    q[0] += c * 19u;
    c = q[0] >> 26; q[0] &= MASK26; q[1] += c;

    // 打包: w0..w3 (little-endian 32B)
    uint64_t w0 = q[0] | (q[1] << 26) | (q[2] << 51);
    uint64_t w1 = (q[2] >> 13) | (q[3] << 13) | (q[4] << 38);
    uint64_t w2 = q[5] | (q[6] << 25) | (q[7] << 51);
    uint64_t w3 = (q[7] >> 13) | (q[8] << 12) | (q[9] << 38);

    uint8_t tmp[32];
    for (int i = 0; i < 8; i++) {
        tmp[i]      = (uint8_t)(w0 >> (8 * i));
        tmp[8 + i]  = (uint8_t)(w1 >> (8 * i));
        tmp[16 + i] = (uint8_t)(w2 >> (8 * i));
        tmp[24 + i] = (uint8_t)(w3 >> (8 * i));
    }

    // 条件减 p (若 tmp >= p): p = 2^255-19
    static const uint8_t P[32] = {
        0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
    };
    int32_t borrow = 0;
    uint8_t diff[32];
    for (int i = 0; i < 32; i++) {
        int32_t d = (int32_t)tmp[i] - (int32_t)P[i] - borrow;
        borrow = (d < 0) ? 1 : 0;
        diff[i] = (uint8_t)(d & 0xff);
    }
    const uint8_t* sel = (borrow == 0) ? diff : tmp;   // borrow==0 → tmp >= p → 用 tmp-p
    for (int i = 0; i < 32; i++) s[i] = sel[i];
}

// out = z^(p-2) (square-and-multiply, MSB-first)
HD void fe_invert(fe out, const fe z) {
    // exp = p-2 = 2^255-21 → LE bytes: 0xED, 0xFF×30, 0x7F
    static const uint8_t EXPP2[32] = {
        0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
    };
    fe acc, tmp;
    fe_one(acc);
    for (int t = 254; t >= 0; t--) {
        fe_sq(tmp, acc);
        int bit = (EXPP2[t >> 3] >> (t & 7)) & 1;
        if (bit) fe_mul(acc, tmp, z);
        else     fe_copy(acc, tmp);
    }
    fe_copy(out, acc);
}

// =====================================================================
//  X25519 scalar multiplication (Montgomery ladder, RFC 7748)
//  标量必须已 clamp. 每步独立临时变量, 无覆盖复用.
// =====================================================================
HD void x25519_scalarmult(uint8_t* out32, const uint8_t* scalar, const uint8_t* point32) {
    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point32);
    fe_one(x2); fe_zero(z2);
    fe_copy(x3, x1); fe_one(z3);

    int swap = 0;
    for (int t = 254; t >= 0; t--) {
        int kt = (scalar[t >> 3] >> (t & 7)) & 1;
        swap ^= kt;
        fe_cswap(swap, x2, x3);
        fe_cswap(swap, z2, z3);
        swap = kt;

        // ladder step (donna/ref10)
        fe_add(A, x2, z2);
        fe_sq(AA, A);                 // AA = A^2
        fe_sub(B, x2, z2);
        fe_sq(BB, B);                 // BB = B^2
        fe_sub(E, AA, BB);            // E = AA - BB
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);             // DA = D*A
        fe_mul(CB, C, B);             // CB = C*B
        fe_add(t0, DA, CB);
        fe_sq(x3, t0);                // x3 = (DA+CB)^2
        fe_sub(t0, DA, CB);
        fe_sq(t0, t0);                // (DA-CB)^2
        fe_mul(z3, x1, t0);           // z3 = x1*(DA-CB)^2
        fe_mul(x2, AA, BB);           // x2 = AA*BB  (AA 此处最后一次使用)
        fe_mul121666(t0, E);          // t0 = a24*E
        fe_add(t0, AA, t0);           // t0 = AA + a24*E
        fe_mul(z2, E, t0);            // z2 = E*(AA + a24*E)
    }
    fe_cswap(swap, x2, x3);
    fe_cswap(swap, z2, z3);

    // out = x2 * z2^(p-2)
    fe inv, res;
    fe_invert(inv, z2);
    fe_mul(res, x2, inv);
    fe_tobytes(out32, res);
}

// =====================================================================
//  base64 (host) + 自测 + CUDA 入口
// =====================================================================
#ifndef __CUDACC__
#else
static void b64_encode(const unsigned char* in, int inlen, char* out, int* outlen) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0, v;
    for (i = 0; i < inlen;) {
        v = in[i++] << 16;
        if (i < inlen) v |= in[i++] << 8;
        if (i < inlen) v |= in[i++];
        out[j++] = tbl[(v >> 18) & 0x3f];
        out[j++] = tbl[(v >> 12) & 0x3f];
        out[j++] = tbl[(v >>  6) & 0x3f];
        out[j++] = tbl[ v        & 0x3f];
    }
    int pad = (3 - inlen % 3) % 3;
    for (int k = 0; k < pad; k++) out[j - k - 1] = '=';
    out[j] = 0;
    *outlen = j;
}

static void clamp_scalar(uint8_t* s) {
    s[0]  &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

static const uint8_t RFC_SCALAR[32] = {
    0x77,0x76,0xd0,0xa7,0x31,0x8a,0x57,0xd3,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
    0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a
};
static const uint8_t RFC_EXPECTED[32] = {
    0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
    0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a
};

// RFC 7748: scalar a × base 9 → 期待 pub
__global__ void batch_keygen_kernel(int count, const uint8_t* seeds, uint8_t* pubs) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    const uint8_t base9[32] = { 9 };
    x25519_scalarmult(pubs + i * 32, seeds + i * 32, base9);
}

extern "C" int batch_keygen_cuda(int count, char* out, int out_len) {
    // ---- count=0: 自测 (CPU 参考 + GPU 各一遍) ----
    if (count <= 0) {
        uint8_t scalar[32];
        memcpy(scalar, RFC_SCALAR, 32);
        clamp_scalar(scalar);
        uint8_t base9[32] = { 9 };
        uint8_t cpuOut[32];
        x25519_scalarmult(cpuOut, scalar, base9);
        if (memcmp(cpuOut, RFC_EXPECTED, 32) != 0) {
            fprintf(stderr, "[gpu] CPU self-test FAILED\n");
            return -1;
        }

        uint8_t *d_seeds = NULL, *d_pubs = NULL;
        if (cudaMalloc((void**)&d_seeds, 32) != cudaSuccess) return -1;
        if (cudaMalloc((void**)&d_pubs, 32)  != cudaSuccess) { cudaFree(d_seeds); return -1; }
        cudaMemcpy(d_seeds, scalar, 32, cudaMemcpyHostToDevice);
        batch_keygen_kernel<<<1, 1>>>(1, d_seeds, d_pubs);
        if (cudaGetLastError() != cudaSuccess) { cudaFree(d_seeds); cudaFree(d_pubs); return -1; }
        uint8_t gpuOut[32];
        cudaMemcpy(gpuOut, d_pubs, 32, cudaMemcpyDeviceToHost);
        cudaDeviceSynchronize();
        cudaFree(d_seeds); cudaFree(d_pubs);
        if (memcmp(gpuOut, RFC_EXPECTED, 32) != 0) {
            fprintf(stderr, "[gpu] GPU self-test FAILED\n");
            return -1;
        }
        fprintf(stderr, "[gpu] self-test OK (RFC 7748 vector, CPU+GPU)\n");
        return 0;
    }

    // ---- count>0: 批量生成 ----
    uint8_t* seeds = (uint8_t*)malloc((size_t)count * 32);
    uint8_t* pubs  = (uint8_t*)malloc((size_t)count * 32);
    if (!seeds || !pubs) { free(seeds); free(pubs); return -1; }

    // 标量来源: OS CSPRNG (std::random_device → Windows 上即 BCryptGenRandom)
    {
        static std::random_device rd;
        for (long i = 0; i < (long)count * 32; i++) seeds[i] = (uint8_t)rd();
    }
    // 宿主侧 clamp (kernel 内 clamp 幂等)
    for (int i = 0; i < count; i++) clamp_scalar(seeds + (size_t)i * 32);

    uint8_t *d_seeds = NULL, *d_pubs = NULL;
    size_t bytes = (size_t)count * 32;
    if (cudaMalloc((void**)&d_seeds, bytes) != cudaSuccess) { free(seeds); free(pubs); return -1; }
    if (cudaMalloc((void**)&d_pubs,  bytes) != cudaSuccess) {
        cudaFree(d_seeds); free(seeds); free(pubs); return -1;
    }
    cudaMemcpy(d_seeds, seeds, bytes, cudaMemcpyHostToDevice);

    int threads = 128;
    int blocks  = (count + threads - 1) / threads;
    batch_keygen_kernel<<<blocks, threads>>>(count, d_seeds, d_pubs);
    if (cudaGetLastError() != cudaSuccess) {
        cudaFree(d_seeds); cudaFree(d_pubs); free(seeds); free(pubs); return -1;
    }
    cudaMemcpy(pubs, d_pubs, bytes, cudaMemcpyDeviceToHost);
    cudaDeviceSynchronize();
    cudaFree(d_seeds); cudaFree(d_pubs);

    // 写出 "pub_b64|priv_b64\0" 逐条拼接 (priv = clamped scalar)
    int written = 0;
    for (int i = 0; i < count; i++) {
        char pub64[64], priv64[64];
        int n1 = 0, n2 = 0;
        b64_encode(pubs  + (size_t)i * 32, 32, pub64,  &n1);
        b64_encode(seeds + (size_t)i * 32, 32, priv64, &n2);
        int need = n1 + 1 + n2 + 1;
        if (written + need > out_len) break;
        memcpy(out + written, pub64, n1);  written += n1;
        out[written++] = '|';
        memcpy(out + written, priv64, n2); written += n2;
        out[written++] = '\0';
    }
    free(seeds); free(pubs);
    return written;
}
#endif  // __CUDACC__
