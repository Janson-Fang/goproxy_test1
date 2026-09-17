/**
 * 首屏主题初始化。
 *
 * 这段逻辑原来内联在 index.html 的 <script> 里，现在抽成外部文件 —— 因为
 * 内联脚本会强制 CSP 挂上 'unsafe-inline'，而那样 CSP 就基本失效了
 * （XSS 只要注入一个内联 <script> 就能跑）。抽出来之后 script-src 才能
 * 收成 'self'，这是 CSP 真正起作用的前提。
 *
 * 它必须是**普通脚本**而不是 ES module：module 是延迟执行的，
 * 会等到 DOM 解析完才跑，那时首屏已经用默认主题渲染过一帧，浅色用户
 * 就会看到一闪的黑。Vite 会按 build.rollupOptions 的配置原样保留这个文件。
 */
try {
  var t = localStorage.getItem('goproxy.theme')
  if (t !== 'light' && t !== 'dark') {
    t =
      window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light'
        : 'dark'
  }
  document.documentElement.dataset.theme = t
} catch (e) {
  /* 隐私模式下 localStorage 可能不可读，用 index.html 上的默认值即可 */
}
