// CryptoLib - 公共接口
// 与 Python ctypes 版完全兼容的导出符号; 另外,加了 gpu_batch_keygen (OPTIONAL)
#pragma once

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 经典版（与最早的 ctypes 调用对齐）
EXPORT char* generate_keypair();   // 返回 "pub_b64|priv_b64" 用 malloc, 调用者用 free_string 释放
EXPORT char* hybrid_encrypt(const char* recv_pub_b64,
                            const char* sender_priv_b64,
                            const char* plain_b64);
EXPORT char* hybrid_decrypt(const char* recv_priv_b64,
                           const char* sender_pub_b64,
                           const char* cipher_pkg_b64);
EXPORT void  free_string(char* p);

// GPU 批量 — GPU 不可用时返回 -1
//   count  批量大小, 例: 32
//   out     一次性写出, 每条 "pub_b64|priv_b64\0" 拼接
//   out_len 缓冲区大小
//   返回: 实际写入字节,或 -1 (GPU 不可用 / 其它错误)
EXPORT int gpu_batch_keygen(int count, char* out, int out_len);

#ifdef __cplusplus
}
#endif
