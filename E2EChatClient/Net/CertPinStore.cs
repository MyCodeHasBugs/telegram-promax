// TOFU (Trust On First Use) 证书指纹钉定:
//   首次连接某 host:port 时记录 SHA-256(DER) 指纹并提示,
//   后续连接指纹不匹配立即拒绝 (防中间人替换证书).
//
// 持久化于 %LOCALAPPDATA%\E2EChatClient\tofu_pins.json
// 手动指纹框填了值 = 走严格 pins 模式, 跳过 TOFU.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace E2EChatClient.Net
{
    public static class CertPinStore
    {
        private static readonly string Dir  = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "E2EChatClient");
        private static readonly string Path_ = Path.Combine(Dir, "tofu_pins.json");

        private static Dictionary<string, string> Load()
        {
            try {
                if (File.Exists(Path_)) {
                    string json = File.ReadAllText(Path_);
                    var d = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (d != null) return d;
                }
            } catch { /* 损坏的文件按空表处理 */ }
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        private static void Save(Dictionary<string, string> d)
        {
            try {
                Directory.CreateDirectory(Dir);
                File.WriteAllText(Path_,
                    JsonSerializer.Serialize(d, new JsonSerializerOptions { WriteIndented = true }));
            } catch { /* 占用等情况仅跳过落盘, 不影响在线判定 */ }
        }

        /// <summary> 找已钉指纹; return null = 无记录. </summary>
        public static string? Get(string host, int port)
        {
            return Load().TryGetValue($"{host}:{port}", out var fp) ? fp : null;
        }

        public static void Pin(string host, int port, string fingerprint)
        {
            var d = Load();
            d[$"{host}:{port}"] = fingerprint;
            Save(d);
        }
    }
}
