// AnimatedGlassFallback — 纯 WPF 动画液态玻璃兜底背景
// =====================================================================
// GL (GLWpfControl) 不可用时启用: 3 个径向渐变"液滴"在深色底上缓慢漂移,
// DoubleAnimation 自动往返. 纯 WPF 渲染 (DX 合成, RDP 上也可用).
// 配色与 GL 版一致: 深蓝 → 靛紫 → 青微亮.
// =====================================================================

using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace E2EChatClient.UI
{
    public class AnimatedGlassFallback : Canvas
    {
        public AnimatedGlassFallback()
        {
            Background = new LinearGradientBrush(
                Color.FromRgb(0x0B, 0x0F, 0x1A),
                Color.FromRgb(0x14, 0x1B, 0x30),
                new Point(0, 0), new Point(1, 1));

            AddBlob(0x551B2A4A, 520, 1.0, 0.15, 0.10, 6.0);   // 靛紫 大
            AddBlob(0x453A2A6A, 420, 1.4, 0.50, 0.55, 9.0);   // 紫红 中
            AddBlob(0x388AB4A8, 300, 1.9, 0.30, 0.80, 13.0);  // 青 小
            AddBlob(0x301B2A4A, 460, 1.2, 0.75, 0.25, 8.0);
        }

        private void AddBlob(uint argb, double size, double speedSec, double x0, double y0, double phase)
        {
            var brush = new RadialGradientBrush(
                Color.FromArgb((byte)(argb >> 24), (byte)(argb >> 16), (byte)(argb >> 8), (byte)argb),
                Color.FromArgb(0, 0, 0, 0));
            var ellipse = new Ellipse
            {
                Width = size,
                Height = size,
                Fill = brush,
                IsHitTestVisible = false,
            };
            SetLeft(ellipse, x0 * 800);
            SetTop(ellipse, y0 * 500);
            Children.Add(ellipse);

            var animX = new DoubleAnimation
            {
                From = x0 * 800 - 120,
                To   = x0 * 800 + 120,
                Duration = new Duration(TimeSpan.FromSeconds(speedSec * 10)),
                AutoReverse = true,
                EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
                BeginTime = TimeSpan.FromSeconds(phase * 0.3),
            };
            var animY = new DoubleAnimation
            {
                From = y0 * 500 - 80,
                To   = y0 * 500 + 80,
                Duration = new Duration(TimeSpan.FromSeconds(speedSec * 13)),
                AutoReverse = true,
                EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut },
                BeginTime = TimeSpan.FromSeconds(phase * 0.5),
            };
            // 随窗口大小自适应: 用渲染时实际尺寸重播 (简化: 固定 800x500 逻辑坐标, Stretch 由 Canvas 处理)
            ellipse.BeginAnimation(Canvas.LeftProperty, animX);
            ellipse.BeginAnimation(Canvas.TopProperty, animY);
        }
    }
}
