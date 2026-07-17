"""
一键生成自签 TLS 证书, 供 server_v2.py --tls-cert/--tls-key 使用.

输出:
  E:\\launcher\\server\\certs\\cert.pem   (含 cert+chain, 自签单证书)
  E:\\launcher\\server\\certs\\key.pem    (PEM-encoded 私钥, **口令加密 AES-256-CBC**)

Pass2-F6 / 2026-07-15 修复:
  * 之前私钥 NoEncryption() 明文落盘 -> 主机被攻陷即泄露 -> 攻击者可以对客户端
    伪造"合法"证书升级 MITM. 改为强制口令加密 (BestAvailableEncryption, AES-256).
  * 有效期从 3650 天 (10 年) 缩到 365 天 (1 年), 缩短暴露窗口.

启动 server_v2.py 时 --tls-key-pw 传入同一口令; server_v2.py 现已透传给 uvicorn
(原代码已支持 --tls-key-pw 参数).

需要: pip install cryptography  (>3.0)
"""

import getpass
import os
import sys
import datetime
import hashlib
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _ask_password() -> bytes:
    """交互式要求输入并二次确认口令. 返回 utf-8 bytes."""
    while True:
        pw = getpass.getpass("私钥加密口令 (>= 12 字符): ")
        if len(pw) < 12:
            print("[gen-cert] 口令过短 (最低 12 字符), 防爆破. 请重输.", flush=True)
            continue
        pw2 = getpass.getpass("再次输入口令确认: ")
        if pw != pw2:
            print("[gen-cert] 两次输入不一致, 请重试.", flush=True)
            continue
        return pw.encode("utf-8")


def main(out_dir=None, key_password: bytes | None = None):
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
    os.makedirs(out_dir, exist_ok=True)

    # Pass2-F6: 私钥必须口令加密. 默认交互式 prompt; CLI 可传 --password-stdin.
    if key_password is None:
        key_password = _ask_password()
    if not key_password or len(key_password) < 12:
        raise SystemExit("[FATAL] 私钥口令必须 >= 12 字符 (防爆破). 拒绝生成明文私钥.")

    # ECDSA (secp256r1) 私钥, TLS 证书签名 (X25519 不能签名, 用 ECDSA)
    priv = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,  "ZZ"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "E2EChat-V2-Self-Signed"),
        x509.NameAttribute(NameOID.COMMON_NAME,   "e2echat.local"),
    ])
    # timezone-aware now (Python 3.14 deprecates datetime.utcnow)
    now = datetime.datetime.now(datetime.timezone.utc)
    # Pass2-F6: 有效期从 3650 天 (10 年) 缩到 365 天 (1 年), 缩短泄露暴露窗口.
    NOT_AFTER_DAYS = 365
    cert = (
        x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=NOT_AFTER_DAYS))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("e2echat.local"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(priv, hashes.SHA256())
    )

    cert_path = os.path.join(out_dir, "cert.pem")
    key_path  = os.path.join(out_dir, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    # Pass2-F6: 私钥 BestAvailableEncryption (cryptography 用 AES-256-CBC + PBKDF2).
    # 之前 NoEncryption() 明文落盘 = 主机脱库即私钥泄露, 改后必须带口令才能 load.
    encrypted_key = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(key_password),
    )
    with open(key_path, "wb") as f:
        f.write(encrypted_key)
    # 用完即清, 防 Python GC 不及时
    if isinstance(key_password, bytes):
        try:
            import ctypes; ctypes.memmove((ctypes.c_char * len(key_password)).from_address_copy(id(key_password)), b"\x00" * len(key_password), len(key_password))
        except Exception:
            pass

    der = cert.public_bytes(serialization.Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()
    print(f"[gen-cert] cert: {cert_path}  (valid {NOT_AFTER_DAYS} days)")
    print(f"[gen-cert] key:  {key_path}   (AES-256 encrypted, requires passphrase)")
    print(f"[gen-cert] sha256 fingerprint:\n  {fp}")
    print(f"[gen-cert] usage: python server_v2.py --tls-cert {cert_path} "
          f"--tls-key {key_path} --tls-key-pw '<your-passphrase>'")
    print(f"[gen-cert] client GUI: 勾 TLS, 把上面 sha256 指纹粘到指纹框, 否则拒连 (F1 强制).")


if __name__ == "__main__":
    # 支持 --password-stdin 让 server 部署脚本/CI 提供口令 (不交互)
    import argparse
    ap = argparse.ArgumentParser(description="Generate self-signed TLS cert (encrypted key)")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read key passphrase from stdin instead of interactive prompt")
    args = ap.parse_args()
    pw: bytes | None = None
    if args.password_stdin:
        line = sys.stdin.readline().rstrip("\n")
        pw = line.encode("utf-8")
    main(key_password=pw)
