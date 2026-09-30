// LiquidGlassBackground — OpenGL 动态液态玻璃背景 (GLWpfControl 宿主)
// =====================================================================
// 全屏 fragment shader: 流动 metaballs (液体玻璃质感) + 暗色调渐变
//   * 深蓝 → 靛紫 → 青色高光, 匹配聊天 UI 的玻璃卡配色
//   * 胶片颗粒 + 暗角, 抑制色带
//   * GL 3.30 core, 任何 2010 后的 GPU 都能跑
//
// 用法: MainWindow.xaml 根 Grid 最底层插 <ui:LiquidGlassBackground/> (RowSpan 全部),
//       IsHitTestVisible=False; UI 卡片都是半透明, 动态玻璃从底下透出来.
// GL 初始化失败 → 自动 Collapse, 不影响聊天主功能.
// =====================================================================

using System;
using OpenTK;
using OpenTK.Graphics;
using OpenTK.Graphics.OpenGL4;
using OpenTK.Wpf;

namespace E2EChatClient.UI
{
    public class LiquidGlassBackground : GLWpfControl
    {
        private int _program;
        private int _vao;
        private int _uniTime;
        private int _uniRes;
        private bool _ready;

        /// <summary>GL 初始化失败时触发 (MainWindow 据此切换 CPU 动画兜底背景).</summary>
        public event Action? Failed;

        private static void Log(string msg)
        {
            try {
                System.IO.File.AppendAllText(
                    System.IO.Path.Combine(System.IO.Path.GetTempPath(), "e2echat_gl.log"),
                    DateTime.Now.ToString("HH:mm:ss ") + msg + "\r\n");
            } catch { }
        }

        private const string VertSrc = @"#version 330 core
layout(location=0) in vec2 aPos;
out vec2 vUv;
void main() {
    vUv = aPos * 0.5 + 0.5;
    gl_Position = vec4(aPos, 0.0, 1.0);
}";

        private const string FragSrc = @"#version 330 core
in vec2 vUv;
out vec4 fragColor;
uniform float uTime;
uniform vec2  uRes;

float hash(vec2 p) {
    p = fract(p * vec2(234.34, 435.345));
    p += dot(p, p + 34.23);
    return fract(p.x * p.y);
}

float noise(vec2 p) {
    vec2 i = floor(p); vec2 f = fract(p);
    f = f * f * (3.0 - 2.0 * f);
    float a = hash(i);
    float b = hash(i + vec2(1.0, 0.0));
    float c = hash(i + vec2(0.0, 1.0));
    float d = hash(i + vec2(1.0, 1.0));
    return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
}

void main() {
    vec2 uv = vUv;
    float t = uTime;

    // flowing metaballs (liquid glass blobs)
    float field = 0.0;
    for (int i = 0; i < 6; i++) {
        float fi = float(i);
        vec2 pos = vec2(
            0.5 + 0.38 * sin(t * (0.21 + fi * 0.043) + fi * 1.93),
            0.5 + 0.34 * cos(t * (0.17 + fi * 0.057) + fi * 2.71)
        );
        vec2 d = uv - pos;
        d.x *= uRes.x / max(uRes.y, 1.0);   // fix aspect ratio
        field += 0.021 / max(dot(d, d), 0.0004);
    }

    // color ramp: deep navy -> indigo -> violet -> soft cyan
    vec3 deep   = vec3(0.043, 0.059, 0.102);
    vec3 indigo = vec3(0.106, 0.165, 0.290);
    vec3 violet = vec3(0.227, 0.165, 0.416);
    vec3 cyan   = vec3(0.541, 0.706, 0.660);

    float m1 = smoothstep(0.0,  0.55, field);
    float m2 = smoothstep(0.45, 0.95, field);
    float m3 = smoothstep(0.85, 1.30, field);
    vec3 col = mix(deep, indigo, m1);
    col = mix(col, violet, m2 * 0.8);
    col = mix(col, cyan,   m3 * 0.5);

    // liquid perturbation noise (glass flow feel)
    float w = noise(uv * 6.0 + vec2(t * 0.12, -t * 0.09));
    col += (w - 0.5) * 0.045;

    // vignette
    vec2 vc = uv - 0.5;
    col *= 1.0 - dot(vc, vc) * 0.9;

    // film grain (anti-banding)
    col += (hash(uv * uRes + t) - 0.5) * 0.012;

    fragColor = vec4(col, 1.0);
}";

        public LiquidGlassBackground()
        {
            Render += OnRender;
            Loaded += (_, _) => Start();
        }

        private void Start()
        {
            try
            {
                var settings = new GLWpfControlSettings
                {
                    MajorVersion = 3,
                    MinorVersion = 3,
                    RenderContinuously = true,
                    TransparentBackground = false,   // 不透明背景: 我们是整层底图, 不带 alpha 合成
                };
                Start(settings);
                Log("GLWpfControl started (GL 3.3)");
                // 1.0.0 的 Render 可能不自动跑: Ready 后手动触发一帧
                Ready += () => Log("GL context ready");
                Dispatcher.BeginInvoke(new Action(() => InvalidateVisual()),
                    System.Windows.Threading.DispatcherPriority.Loaded);
            }
            catch (Exception ex)
            {
                Log("Start failed: " + ex.Message);
                Visibility = System.Windows.Visibility.Collapsed;   // 无 GL → 优雅退出
                Failed?.Invoke();
            }
        }

        private void OnRender(TimeSpan delta)
        {
            try
            {
                if (!_ready)
                {
                    if (!InitGl())
                    {
                        Log("InitGl failed — 控件隐藏, 走兜底背景");
                        Visibility = System.Windows.Visibility.Collapsed;
                        Failed?.Invoke();
                        return;
                    }
                    _ready = true;
                    Log("GL 初始化完成, 开始渲染");
                }
                GL.UseProgram(_program);
                GL.Uniform1(_uniTime, (float)(DateTime.Now - System.Diagnostics.Process.GetCurrentProcess().StartTime).TotalSeconds);
                GL.Uniform2(_uniRes, (float)ActualWidth, (float)ActualHeight);
                GL.BindVertexArray(_vao);
                GL.DrawArrays(PrimitiveType.TriangleStrip, 0, 4);
            }
            catch (Exception ex)
            {
                // 渲染线程异常不让它静默死掉
                Log("OnRender 异常: " + ex.Message);
                Visibility = System.Windows.Visibility.Collapsed;
                Failed?.Invoke();
            }
        }

        private bool InitGl()
        {
            try
            {
                _program = GL.CreateProgram();
                CompileAttach(ShaderType.VertexShader, VertSrc);
                CompileAttach(ShaderType.FragmentShader, FragSrc);
                GL.LinkProgram(_program);
                GL.GetProgram(_program, GetProgramParameterName.LinkStatus, out int ok);
                if (ok == 0)
                {
                    string log = GL.GetProgramInfoLog(_program);
                    Log("GL link 失败: " + log);
                    return false;
                }

                _uniTime = GL.GetUniformLocation(_program, "uTime");
                _uniRes  = GL.GetUniformLocation(_program, "uRes");

                // 全屏两三角形
                _vao = GL.GenVertexArray();
                GL.BindVertexArray(_vao);
                int vbo = GL.GenBuffer();
                GL.BindBuffer(BufferTarget.ArrayBuffer, vbo);
                float[] quad = { -1f, -1f,  1f, -1f,  -1f, 1f,  1f, 1f };
                GL.BufferData(BufferTarget.ArrayBuffer, quad.Length * sizeof(float), quad, BufferUsageHint.StaticDraw);
                GL.EnableVertexAttribArray(0);
                GL.VertexAttribPointer(0, 2, VertexAttribPointerType.Float, false, 0, 0);
                GL.BindBuffer(BufferTarget.ArrayBuffer, 0);
                GL.BindVertexArray(0);
                return true;
            }
            catch { return false; }
        }

        private void CompileAttach(ShaderType type, string src)
        {
            int sh = GL.CreateShader(type);
            GL.ShaderSource(sh, src);
            GL.CompileShader(sh);
            GL.GetShader(sh, ShaderParameter.CompileStatus, out int ok);
            if (ok == 0)
            {
                string log = GL.GetShaderInfoLog(sh);
                System.Diagnostics.Debug.WriteLine("GL compile: " + log);
            }
            GL.AttachShader(_program, sh);
        }
    }
}
