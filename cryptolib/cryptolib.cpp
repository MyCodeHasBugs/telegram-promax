// CryptoLib - CPU fallback 实现
// ===================================
// ⚠️  Pass4-F4-4: V2 客户端主链路 (ChatSessionV2) **完全不用** 本 DLL,
//     只走 NSec.Cryptography (libsodium) + C# Curve25519.cs / XChaCha20Poly1305.cs.
//     CryptoLibBridge.cs 的 P/Invoke 仅探测性 (UI 显示 GPU 状态), 不会用本 DLL 的
//     generate_keypair / hybrid_encrypt / hybrid_decrypt 产安全敏感输出.
//
//     因此 hybrid_encrypt / hybrid_decrypt 历史上是 stub 返回 "ERROR:not_implemented",
//     但仍是被导出的符号——若调用方误接会静默拿到一个 "看似返回值" 的错误串,
//     可能被当成密文继续走. 本文件现把这些 stub 改为 abort() 硬失败, 不留静默错误路径.
//
// 设计原则 (保留):
//   1. 保持 oldest Python ctypes 版完全一致 (generate_keypair / hybrid_encrypt / hybrid_decrypt / free_string)
//   2. 当 CUDA 在编译期可用时，gpu_batch_keygen → 调 ecc_kernel.cu 上的 batch_keygen_cuda()
//      否则 gpu_batch_keygen 返回 -1，让 C# 端走 CPU 后备 (Curve25519.cs)
//
// 真要换实现可只改这里, 不动 C# 端 — C# 走 IsDllAvailable()/GpuBatchKeypairs() 里的兜底路径
//
// 真正部署时建议把 X25519/AES 都换成您信任的实现 (libsodium/mbedtls)
// ===================================

#include "cryptolib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---- 是否启用 GPU 编译路径 ----
#if defined(USE_CUDA) && defined(__CUDACC__)
#define HAVE_CUDA 1
extern int batch_keygen_cuda(int count, char* out, int out_len);
#else
#define HAVE_CUDA 0
#endif

// ----------------------------------------------------------------
// 基础工具: 写一个格式化的字符串, 用 malloc 分配 (调用方用 free_string)
// ----------------------------------------------------------------
static char* strdup_to_libstr(const char* s)
{
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

void free_string(char* p)
{
    if (p) free(p), p = NULL;
}

// ===== OpenSSL-backed (历史 V1 路径) =====
// Pass4-F4-4: hybrid_encrypt/decrypt 从 not_implemented stub 改为 abort() 硬失败.
//   之前虽返回 ERROR:not_implemented, 但仍是 malloc 出去的合法字符串指针,
//   误接调用方可能当成"密文"继续走下游 (尤其 C#/Python ctypes 边界). 改 abort
//   后任何误调用直接 crash 进程, 静默错误路径被消除.
#if defined(HAVE_OPENSSL)

#include <openssl/evp.h>
#include <openssl/rand.h>

static void base64_encode(const unsigned char* in, int inlen, char* out, int* outlen)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j, v;
    for (i = 0, j = 0; i < inlen;) {
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

static int base64_decode(const char* in, int inlen, unsigned char* out)
{
    static const int tbl[256] = { ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,
        ['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
        ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
        ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
        ['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,
        ['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63 };
    int j = 0, v = 0, bits = 0;
    for (int i = 0; i < inlen; i++) {
        if (in[i] == '=') break;
        int c = tbl[(unsigned char)in[i]];
        if (c == 0 && in[i] != 'A') continue;
        v = (v << 6) | c;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (v >> bits) & 0xff;
        }
    }
    return j;
}

char* generate_keypair()
{
    unsigned char priv[32], pub[32];
    RAND_bytes(priv, 32);
    priv[0]  &= 248; priv[31] &= 127; priv[31] |= 64;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    size_t outlen = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub, &outlen);
    EVP_PKEY_free(pkey);

    char pub64[64], priv64[64];
    int n1, n2;
    base64_encode(pub, 32, pub64, &n1);
    base64_encode(priv, 32, priv64, &n2);

    char* result = (char*)malloc(128);
    snprintf(result, 128, "%s|%s", pub64, priv64);
    return result;
}

char* hybrid_encrypt(const char* /*recv_pub_b64*/,
                     const char* /*sender_priv_b64*/,
                     const char* /*plain_b64*/)
{
    // F4-4: V2 不用 hybrid_*; 历史上是 not_implemented stub, 但仍返回合法指针,
    //       误接会静默得到错误串. 改 abort() 硬失败, 杜绝静默误用.
    fprintf(stderr, "FATAL: hybrid_encrypt is not implemented; V2 uses NSec.Cryptography. "
                    "Aborting to prevent silent misuse.\n");
    abort();
}

char* hybrid_decrypt(const char* /*recv_priv_b64*/,
                     const char* /*sender_pub_b64*/,
                     const char* /*cipher_pkg_b64*/)
{
    fprintf(stderr, "FATAL: hybrid_decrypt is not implemented; V2 uses NSec.Cryptography. "
                    "Aborting to prevent silent misuse.\n");
    abort();
}

#else   // ===== 无 OpenSSL: 整个 DLL 不应被编进生产路径 =====

// Pass4-F4-4: 没有 OpenSSL 还把本文件编进 DLL = 半成品 (generate_keypair 都跑不起来,
//   C# 端 IsDllAvailable() 会误判 DLL "可用"). 直接让编译期硬失败, 杜绝半成品 DLL 发布.
#error "cryptolib.cpp: OpenSSL 路径未启用. V2 客户端不依赖本 DLL (走 NSec.Cryptography), \
若执意要编 DLL, 请启用 HAVE_OPENSSL 并补完整实现; 否则不要把本文件编进任何发布制品."

char* generate_keypair()
{ return strdup_to_libstr("ERROR:no_openssl_build"); }

char* hybrid_encrypt(const char*, const char*, const char*)
{ return strdup_to_libstr("ERROR:no_openssl_build"); }

char* hybrid_decrypt(const char*, const char*, const char*)
{ return strdup_to_libstr("ERROR:no_openssl_build"); }

#endif  // HAVE_OPENSSL

// ----------------------------------------------------------------
// GPU 批量 — 没编译 CUDA 则返回 -1 (C# 端走 CPU 回退)
// ----------------------------------------------------------------
int gpu_batch_keygen(int count, char* out, int out_len)
{
#if HAVE_CUDA
    return batch_keygen_cuda(count, out, out_len);
#else
    (void)count; (void)out; (void)out_len;
    return -1;
#endif
}
