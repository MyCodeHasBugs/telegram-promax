using System;
using System.Threading;
using System.Windows;

namespace E2EChatClient
{
    public partial class App : Application
    {
        // 单实例 Mutex — 防止用户 (或攻击者通过命令行) 启动多个客户端
        // 多开会消耗多个 sid 槽位 + 多份 RHS 内存, 可被滥用做 DoS 放大.
        // Mutex 跨进程, 命名带 user-SID (per-user, 防远程会话互踩).
        private static Mutex? _singleInstance;

        protected override void OnStartup(StartupEventArgs e)
        {
            // 用 user-local 命名, 避免跨用户干扰; 前缀 Local\ 让 Citrix/多会话不互锁
            string mutexName = @"Local\E2EChatClient-SingleInstance-7F3A2E1D";
            _singleInstance = new Mutex(initiallyOwned: true, name: mutexName, out bool createdNew);

            if (!createdNew)
            {
                // 已有实例在跑, 提示并退出
                MessageBox.Show(
                    "E2EChat 已在运行, 不可多开.\n如需多账号, 请在客户端 UI 切换昵称/房间.",
                    "单实例锁定",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                this.Shutdown(0);
                return;
            }

            // 防 GC 提前回收 (字面持有到进程结束)
            AppDomain.CurrentDomain.ProcessExit += (_, __) =>
            {
                try { _singleInstance?.ReleaseMutex(); } catch { }
                try { _singleInstance?.Dispose(); }      catch { }
            };

            base.OnStartup(e);
        }
    }
}
